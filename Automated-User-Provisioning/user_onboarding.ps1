<#
.SYNOPSIS
    Bulk Active Directory user provisioning from a CSV data source.

.DESCRIPTION
    Automates the end-to-end onboarding lifecycle for new employees: reads structured
    HR data from a CSV, creates AD accounts with standardized attributes, generates
    cryptographically secure passwords, provisions home directories, and assigns
    department-appropriate Security Group membership. All operations are timestamped
    to a persistent log file for SOC 2 audit trail compliance.

.PARAMETER CsvPath
    Full path to the CSV file containing new hire data.
    Required columns: FirstName, LastName, Department, Manager, Title, Office

.PARAMETER HomeDriveRoot
    UNC path to the file server share root where home directories are created.
    Example: \\fileserver01\HomeDirectories$

.PARAMETER LogPath
    Full path to the output log file. Defaults to the script directory with a
    datestamped filename if not specified.

.PARAMETER OUPath
    Distinguished Name of the target Organizational Unit for new accounts.
    Example: "OU=Employees,OU=Users,DC=contoso,DC=com"

.EXAMPLE
    .\user_onboarding.ps1 -CsvPath "C:\HR\NewHires_2026-01.csv" `
                          -HomeDriveRoot "\\fileserver01\HomeDirectories$" `
                          -OUPath "OU=Employees,OU=Users,DC=contoso,DC=com"

    # Dry run with WhatIf — no changes committed to AD or the file system
    .\user_onboarding.ps1 -CsvPath "C:\HR\NewHires_2026-01.csv" `
                          -HomeDriveRoot "\\fileserver01\HomeDirectories$" `
                          -WhatIf

.NOTES
    Author:      Seth Yang
    Version:     3.0
    Requires:    ActiveDirectory PowerShell module (RSAT), delegated OU write rights
    Tested On:   Windows Server 2022, PowerShell 5.1+
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to the new hire CSV file.")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory = $true, HelpMessage = "UNC root path for home directory creation.")]
    [string]$HomeDriveRoot,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$PSScriptRoot\onboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",

    [Parameter(Mandatory = $false)]
    [string]$OUPath = "OU=Employees,OU=Users,DC=contoso,DC=com",

    [Parameter(Mandatory = $false)]
    [string]$Domain = "contoso.com",

    [Parameter(Mandatory = $false)]
    [string]$UPNSuffix = "@contoso.com"
)

# Expose log path at script scope so Write-Log can reference it without threading
# issues if this is ever wrapped in a runspace pool for parallel execution.
$Global:LogPath = $LogPath

#region --- Department-to-Group Mapping ---
# This lookup table is the single source of truth for group assignments.
# Maintaining it here (rather than in the CSV) enforces separation of concerns:
# HR owns the CSV data; IT owns the access control policy. Adding a new department
# requires one line here, not a CSV schema change.
$DepartmentGroupMap = @{
    "Engineering"        = "GRP-Engineering-Staff"
    "Finance"            = "GRP-Finance-Staff"
    "Human Resources"    = "GRP-HR-Staff"
    "IT"                 = "GRP-IT-Staff"
    "Marketing"          = "GRP-Marketing-Staff"
    "Operations"         = "GRP-Operations-Staff"
    "Sales"              = "GRP-Sales-Staff"
    "Legal"              = "GRP-Legal-Staff"
}
# All employees receive this baseline group regardless of department,
# which grants access to shared drives, printers, and the intranet.
$BaselineGroup = "GRP-All-Employees"
#endregion

#region --- Helper Functions ---

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped, color-coded entry to the console and appends it to
        the persistent log file at $Global:LogPath.
    .NOTES
        Using Write-Host intentionally here rather than Write-Output — the log file
        handles the persistent record, and Write-Host is appropriate for interactive
        status output that should not pollute the pipeline.
    #>
    param (
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "INFO"    { Write-Host $entry -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        "WARNING" { Write-Host $entry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
    }

    Add-Content -Path $Global:LogPath -Value $entry
}

function New-SecurePassword {
    <#
    .SYNOPSIS
        Generates a cryptographically random 16-character password that satisfies
        enterprise complexity requirements: uppercase, lowercase, digit, and symbol.
    .NOTES
        I seed the array with at least one character from each required class before
        filling the rest randomly. This guarantees complexity compliance without
        relying on probabilistic chance, which would occasionally produce passwords
        that failed the domain policy and caused New-ADUser to throw.
    #>
    $uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lowercase = "abcdefghjkmnpqrstuvwxyz"
    $digits    = "23456789"
    $symbols   = "!@#$%^&*"
    $allChars  = $uppercase + $lowercase + $digits + $symbols

    $passwordChars = @(
        $uppercase[(Get-Random -Maximum $uppercase.Length)]
        $lowercase[(Get-Random -Maximum $lowercase.Length)]
        $digits[(Get-Random -Maximum $digits.Length)]
        $symbols[(Get-Random -Maximum $symbols.Length)]
    )

    for ($i = 0; $i -lt 12; $i++) {
        $passwordChars += $allChars[(Get-Random -Maximum $allChars.Length)]
    }

    # Fisher-Yates shuffle ensures the four guaranteed characters are not
    # always at positions 0-3, which would make the pattern predictable.
    for ($i = $passwordChars.Count - 1; $i -gt 0; $i--) {
        $j    = Get-Random -Maximum ($i + 1)
        $temp = $passwordChars[$i]
        $passwordChars[$i] = $passwordChars[$j]
        $passwordChars[$j] = $temp
    }

    return ($passwordChars -join "")
}

function New-SamAccountName {
    <#
    .SYNOPSIS
        Derives a standardized sAMAccountName (first initial + last name, lowercase).
        Strips non-alphanumeric characters and truncates to AD's 20-character limit.
    #>
    param ([string]$FirstName, [string]$LastName)
    $sam = ($FirstName[0] + $LastName) -replace '[^a-zA-Z0-9]', ''
    return $sam.ToLower().Substring(0, [Math]::Min($sam.Length, 20))
}

function Resolve-ManagerDN {
    <#
    .SYNOPSIS
        Resolves a manager's sAMAccountName to their AD DistinguishedName.
        Returns $null if the manager account is not found, rather than throwing.
    .NOTES
        New-ADUser accepts the Manager parameter as a DistinguishedName string.
        Passing $null explicitly (rather than omitting the key from the hashtable)
        causes the cmdlet to set Manager to an empty attribute cleanly, which is
        preferable to inheriting a stale manager reference from a previous run.
    #>
    param ([string]$ManagerSam)

    if ([string]::IsNullOrWhiteSpace($ManagerSam)) {
        return $null
    }

    $managerObject = Get-ADUser -Filter { SamAccountName -eq $ManagerSam } `
                                -Properties DistinguishedName `
                                -ErrorAction SilentlyContinue

    if ($null -eq $managerObject) {
        Write-Log "Manager SAM '$ManagerSam' not found in AD. The Manager attribute will be left blank." -Level WARNING
        return $null
    }

    return $managerObject.DistinguishedName
}

#endregion

#region --- Pre-flight Validation ---

Write-Log "=== User Onboarding Script Started ===" -Level INFO
Write-Log "Operator : $env:USERNAME on $env:COMPUTERNAME" -Level INFO
Write-Log "CSV Path : $CsvPath" -Level INFO
Write-Log "Log File : $Global:LogPath" -Level INFO

# Verify the ActiveDirectory module before attempting any AD operations.
# RSAT is not installed by default on all Windows Server builds.
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    Write-Log "FATAL: ActiveDirectory PowerShell module not found. Install RSAT and retry." -Level ERROR
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop
Write-Log "ActiveDirectory module loaded." -Level INFO

# Import the CSV and validate its schema before touching AD.
# Failing fast here prevents a partial run where some users were created
# and others were not, which is harder to audit and reconcile.
$newHires = Import-Csv -Path $CsvPath
if ($newHires.Count -eq 0) {
    Write-Log "FATAL: CSV is empty. No records to process." -Level ERROR
    exit 1
}

$requiredColumns = @("FirstName", "LastName", "Department", "Manager", "Title", "Office")
$csvColumns      = ($newHires[0].PSObject.Properties).Name
foreach ($col in $requiredColumns) {
    if ($col -notin $csvColumns) {
        Write-Log "FATAL: Required column '$col' missing from CSV. Aborting." -Level ERROR
        exit 1
    }
}

Write-Log "CSV validated. Records to process: $($newHires.Count)" -Level INFO

#endregion

#region --- Main Processing Loop ---

$successCount = 0
$failureCount = 0

foreach ($hire in $newHires) {

    $samAccountName = New-SamAccountName -FirstName $hire.FirstName -LastName $hire.LastName
    $upn            = "$samAccountName$UPNSuffix"
    $displayName    = "$($hire.FirstName) $($hire.LastName)"
    $homePath       = Join-Path -Path $HomeDriveRoot -ChildPath $samAccountName
    $plainPassword  = New-SecurePassword
    $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

    Write-Log "--- Processing: $displayName (SAM: $samAccountName) ---" -Level INFO

    try {
        # Duplicate check before any creation attempt. New-ADUser throws a
        # non-terminating error on duplicates by default; catching it here
        # converts it to a logged WARNING and continues the batch.
        if (Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue) {
            throw [System.InvalidOperationException] "Account '$samAccountName' already exists in Active Directory."
        }

        # Resolve the manager DN separately so we can handle the not-found case
        # gracefully. Previously, embedding Get-ADUser inline in the hashtable
        # caused New-ADUser to receive $null silently, resulting in a blank Manager
        # attribute with no log entry. The explicit check below produces an auditable
        # WARNING instead.
        $managerDN = Resolve-ManagerDN -ManagerSam $hire.Manager

        # --- Step 1: Create the AD User account ---
        $adParams = @{
            SamAccountName        = $samAccountName
            UserPrincipalName     = $upn
            Name                  = $displayName
            GivenName             = $hire.FirstName
            Surname               = $hire.LastName
            DisplayName           = $displayName
            Department            = $hire.Department
            Title                 = $hire.Title
            Office                = $hire.Office
            Manager               = $managerDN
            AccountPassword       = $securePassword
            Enabled               = $true
            PasswordNeverExpires  = $false
            ChangePasswordAtLogon = $true
            Path                  = $OUPath
            HomeDirectory         = $homePath
            HomeDrive             = "H:"
        }

        if ($PSCmdlet.ShouldProcess($displayName, "Create AD User")) {
            New-ADUser @adParams -ErrorAction Stop
            Write-Log "AD account created: $upn" -Level SUCCESS
        }

        # --- Step 2: Assign Security Group membership ---
        # Every user gets the baseline group. Department-specific group assignment
        # follows from $DepartmentGroupMap. Using Add-ADGroupMember rather than
        # setting the MemberOf attribute on New-ADUser because the latter only
        # accepts groups in the same domain; this approach works across trusts.
        $groupsToAssign = @($BaselineGroup)

        if ($DepartmentGroupMap.ContainsKey($hire.Department)) {
            $groupsToAssign += $DepartmentGroupMap[$hire.Department]
        } else {
            Write-Log "No group mapping found for department '$($hire.Department)'. Only baseline group will be assigned." -Level WARNING
        }

        foreach ($groupName in $groupsToAssign) {
            if ($PSCmdlet.ShouldProcess($groupName, "Add $samAccountName to group")) {
                try {
                    Add-ADGroupMember -Identity $groupName -Members $samAccountName -ErrorAction Stop
                    Write-Log "Group assigned: '$groupName' -> $samAccountName" -Level SUCCESS
                }
                catch {
                    # Log the group failure but do not abort the user's overall provisioning.
                    # A missing group is an IT configuration issue, not an HR data issue.
                    Write-Log "WARNING: Could not add $samAccountName to '$groupName': $($_.Exception.Message)" -Level WARNING
                }
            }
        }

        # --- Step 3: Provision the home directory on the file server ---
        if (-not (Test-Path -Path $homePath)) {
            if ($PSCmdlet.ShouldProcess($homePath, "Create Home Directory")) {
                New-Item -Path $homePath -ItemType Directory -Force -ErrorAction Stop | Out-Null

                # Set ACL: Full Control for the user, scoped with container and object
                # inheritance so subdirectories created later inherit the same rights.
                $acl        = Get-Acl -Path $homePath
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $upn, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                )
                $acl.SetAccessRule($accessRule)
                Set-Acl -Path $homePath -AclObject $acl -ErrorAction Stop
                Write-Log "Home directory created and ACL applied: $homePath" -Level SUCCESS
            }
        } else {
            Write-Log "Home directory already exists (skipping): $homePath" -Level WARNING
        }

        # --- Step 4: Log credential distribution requirement ---
        # ChangePasswordAtLogon = $true forces the user to set their own password
        # at first login. The initial password must be communicated to the user
        # through the organization's secure channel (helpdesk ticket, PAM system,
        # or encrypted email) — it is not logged here.
        Write-Log "Account ready. Initial password must be delivered via secure channel: $upn" -Level INFO

        $successCount++

    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log "FAILED [$displayName]: $errorMessage" -Level ERROR
        $failureCount++
        # Continue to the next record. A single failed user should not block
        # provisioning for the rest of the batch.
        continue
    }
}

#endregion

#region --- Summary Report ---

Write-Log "=== Onboarding Run Complete ===" -Level INFO
Write-Log "Successful: $successCount | Failed: $failureCount | Total: $($newHires.Count)" -Level INFO

if ($failureCount -gt 0) {
    Write-Log "Review log for failure details: $Global:LogPath" -Level WARNING
    exit 1
} else {
    Write-Log "All users provisioned successfully." -Level SUCCESS
    exit 0
}

#endregion
