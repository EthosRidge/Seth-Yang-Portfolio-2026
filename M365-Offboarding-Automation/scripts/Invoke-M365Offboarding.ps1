<#
.SYNOPSIS
    Automates the complete Microsoft 365 employee offboarding sequence.

.DESCRIPTION
    Executes the full M365 offboarding workflow in the correct order, gating
    each step on the outcome of the previous where necessary. Connects to both
    ExchangeOnlineManagement and Microsoft Graph.

    Steps performed:
      1. Block sign-in (disable Azure AD account)
      2. Revoke all active sessions (Microsoft Graph)
      3. Set Out of Office auto-reply
      4. Convert mailbox to Shared Mailbox
      5. Grant manager Full Access to shared mailbox
      6. Remove from all M365 groups and Teams
      7. Remove M365 licenses (only after confirmed shared mailbox conversion)
      8. Export per-step audit report

.PARAMETER UserPrincipalName
    UPN of the departing user. Required for single-user mode.

.PARAMETER ManagerUPN
    UPN of the user's manager. Receives Full Access delegation on the shared mailbox.

.PARAMETER OOOMessage
    Text body for the Out of Office auto-reply. Defaults to a generic message if omitted.

.PARAMETER CsvPath
    Path to a CSV for batch offboarding. Columns: UserPrincipalName, ManagerUPN, OOOMessage.
    When provided, UserPrincipalName and ManagerUPN are ignored.

.PARAMETER ReportPath
    Path to write the CSV audit report. Defaults to TEMP\Offboarding_<date>.csv.

.EXAMPLE
    .\Invoke-M365Offboarding.ps1 -UserPrincipalName "jsmith@contoso.com" -ManagerUPN "manager@contoso.com"
    .\Invoke-M365Offboarding.ps1 -UserPrincipalName "jsmith@contoso.com" -ManagerUPN "manager@contoso.com" -WhatIf
    .\Invoke-M365Offboarding.ps1 -CsvPath "C:\HR\Terminations_2026-03.csv"

.NOTES
    Required modules: ExchangeOnlineManagement, Microsoft.Graph
    Required roles: Exchange Administrator, User Administrator (Azure AD)
    Exit 0 = all steps completed. Exit 1 = one or more steps failed or require follow-up.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Single')]
param (
    [Parameter(Mandatory, ParameterSetName = 'Single')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory, ParameterSetName = 'Single')]
    [string]$ManagerUPN,

    [Parameter(ParameterSetName = 'Single')]
    [string]$OOOMessage = 'This employee is no longer with the organization. Please contact your department manager for assistance.',

    [Parameter(Mandatory, ParameterSetName = 'Batch')]
    [string]$CsvPath,

    [string]$ReportPath = "$env:TEMP\Offboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogPath = "$env:TEMP\Offboarding_$(Get-Date -Format 'yyyyMMdd').log"
$Report  = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $Entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Entry
    Write-Verbose $Entry
}

function Add-ReportRow {
    param([string]$UPN, [string]$Step, [string]$Status, [string]$Detail)
    $Report.Add([PSCustomObject]@{
        UserPrincipalName = $UPN
        Step              = $Step
        Status            = $Status
        Detail            = $Detail
        Timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
    $Symbol = switch ($Status) { 'PASS' { '[PASS]' } 'WARN' { '[WARN]' } default { '[FAIL]' } }
    Write-Host "$Symbol  [$UPN] $Step — $Detail"
    Write-Log "$Symbol [$UPN] $Step — $Detail" -Level $Status
}

# ── Module checks ─────────────────────────────────────────────────────────────
foreach ($Module in @('ExchangeOnlineManagement', 'Microsoft.Graph')) {
    if (-not (Get-Module -ListAvailable -Name $Module)) {
        throw "Required module '$Module' is not installed. Run: Install-Module $Module"
    }
}

# ── Connect ───────────────────────────────────────────────────────────────────
Write-Log 'Connecting to Exchange Online and Microsoft Graph'
if (-not $WhatIfPreference) {
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Connect-MgGraph -Scopes 'User.ReadWrite.All', 'Group.ReadWrite.All', 'Directory.AccessAsUser.All' `
        -NoWelcome -ErrorAction Stop
}

# ── Build work queue ──────────────────────────────────────────────────────────
$Queue = if ($PSCmdlet.ParameterSetName -eq 'Batch') {
    if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
    $Rows = Import-Csv -Path $CsvPath
    foreach ($Col in @('UserPrincipalName', 'ManagerUPN')) {
        if ($Col -notin $Rows[0].PSObject.Properties.Name) {
            throw "CSV missing required column: $Col"
        }
    }
    $Rows
} else {
    [PSCustomObject]@{
        UserPrincipalName = $UserPrincipalName
        ManagerUPN        = $ManagerUPN
        OOOMessage        = $OOOMessage
    }
}

# ── Per-user offboarding function ─────────────────────────────────────────────
function Invoke-SingleUserOffboarding {
    param([PSCustomObject]$User)

    $UPN  = $User.UserPrincipalName
    $Mgr  = $User.ManagerUPN
    $OOO  = if ($User.OOOMessage) { $User.OOOMessage } else { $OOOMessage }
    $HasError = $false

    Write-Host ''
    Write-Host "── Offboarding: $UPN ──────────────────────────────────"

    # ── Step 1: Block sign-in ─────────────────────────────────────────────────
    try {
        if ($PSCmdlet.ShouldProcess($UPN, 'Disable Azure AD account (block sign-in)')) {
            Update-MgUser -UserId $UPN -AccountEnabled:$false
        }
        Add-ReportRow $UPN 'Block Sign-In' 'PASS' 'Account disabled in Azure AD'
    } catch {
        Add-ReportRow $UPN 'Block Sign-In' 'FAIL' "Error: $_"
        $HasError = $true
    }

    # ── Step 2: Revoke active sessions ────────────────────────────────────────
    try {
        $MgUser = Get-MgUser -UserId $UPN -Property UserType, DisplayName -ErrorAction Stop
        if ($MgUser.UserType -eq 'Guest') {
            Add-ReportRow $UPN 'Revoke Sessions' 'WARN' 'Guest account — session revocation must be handled by home tenant admin'
        } else {
            if ($PSCmdlet.ShouldProcess($UPN, 'Revoke all active refresh tokens')) {
                Revoke-MgUserSignInSession -UserId $UPN | Out-Null
            }
            Add-ReportRow $UPN 'Revoke Sessions' 'PASS' 'All refresh tokens invalidated'
        }
    } catch {
        Add-ReportRow $UPN 'Revoke Sessions' 'FAIL' "Error: $_"
        $HasError = $true
    }

    # ── Step 3: Set Out of Office auto-reply ──────────────────────────────────
    try {
        if ($PSCmdlet.ShouldProcess($UPN, 'Set Out of Office auto-reply')) {
            Set-MailboxAutoReplyConfiguration -Identity $UPN `
                -AutoReplyState Enabled `
                -InternalMessage $OOO `
                -ExternalMessage $OOO
        }
        Add-ReportRow $UPN 'Set OOO Reply' 'PASS' 'Auto-reply configured'
    } catch {
        Add-ReportRow $UPN 'Set OOO Reply' 'FAIL' "Error: $_"
        $HasError = $true
    }

    # ── Step 4: Convert to shared mailbox ─────────────────────────────────────
    $MailboxConverted = $false
    try {
        # Check mailbox size before conversion — flag if >49 GB
        $MailboxStats = Get-EXOMailboxStatistics -Identity $UPN -ErrorAction SilentlyContinue
        if ($MailboxStats) {
            $SizeGB = [math]::Round(
                ($MailboxStats.TotalItemSize.Value.ToBytes() / 1GB), 1
            )
            if ($SizeGB -ge 49) {
                Add-ReportRow $UPN 'Convert to Shared' 'WARN' `
                    "Mailbox is ${SizeGB} GB — exceeds 50 GB limit for unlicensed shared mailbox. Enable archive before removing license."
                # Still attempt conversion — archiving is a follow-up action
            }
        }

        if ($PSCmdlet.ShouldProcess($UPN, 'Convert mailbox to Shared Mailbox')) {
            Set-Mailbox -Identity $UPN -Type Shared
        }

        # Gate: confirm conversion before proceeding
        if (-not $WhatIfPreference) {
            $ConfirmMailbox = Get-EXOMailbox -Identity $UPN -ErrorAction SilentlyContinue
            if ($ConfirmMailbox.RecipientTypeDetails -eq 'SharedMailbox') {
                $MailboxConverted = $true
                Add-ReportRow $UPN 'Convert to Shared' 'PASS' 'Mailbox type confirmed SharedMailbox'
            } else {
                Add-ReportRow $UPN 'Convert to Shared' 'FAIL' 'Conversion command ran but mailbox type did not change — license removal will be skipped'
                $HasError = $true
            }
        } else {
            $MailboxConverted = $true
            Add-ReportRow $UPN 'Convert to Shared' 'PASS' 'WhatIf: Would convert mailbox to Shared'
        }
    } catch {
        Add-ReportRow $UPN 'Convert to Shared' 'FAIL' "Error: $_"
        $HasError = $true
    }

    # ── Step 5: Grant manager Full Access ─────────────────────────────────────
    try {
        if ($PSCmdlet.ShouldProcess($UPN, "Grant Full Access to $Mgr")) {
            Add-MailboxPermission -Identity $UPN -User $Mgr `
                -AccessRights FullAccess -InheritanceType All -AutoMapping $true | Out-Null
        }
        Add-ReportRow $UPN 'Delegate to Manager' 'PASS' "Full Access granted to $Mgr"
    } catch {
        Add-ReportRow $UPN 'Delegate to Manager' 'FAIL' "Error: $_"
        $HasError = $true
    }

    # ── Step 6: Remove from M365 groups and Teams ─────────────────────────────
    try {
        $MgUserId     = (Get-MgUser -UserId $UPN -Property Id).Id
        $MemberGroups = Get-MgUserMemberOf -UserId $MgUserId -All
        $RemovedCount = 0

        foreach ($Group in $MemberGroups) {
            try {
                if ($PSCmdlet.ShouldProcess($Group.Id, "Remove $UPN from group")) {
                    Remove-MgGroupMember -GroupId $Group.Id -DirectoryObjectId $MgUserId -ErrorAction Stop
                }
                $RemovedCount++
            } catch {
                Write-Log "Could not remove from group $($Group.Id): $_" -Level 'WARN'
            }
        }
        Add-ReportRow $UPN 'Remove Group Memberships' 'PASS' "Removed from $RemovedCount group(s) and Teams"
    } catch {
        Add-ReportRow $UPN 'Remove Group Memberships' 'FAIL' "Error: $_"
        $HasError = $true
    }

    # ── Step 7: Remove M365 licenses (gated on confirmed shared mailbox) ──────
    if ($MailboxConverted) {
        try {
            $AssignedLicenses = (Get-MgUser -UserId $UPN -Property AssignedLicenses).AssignedLicenses
            if ($AssignedLicenses.Count -eq 0) {
                Add-ReportRow $UPN 'Remove Licenses' 'PASS' 'No licenses assigned — nothing to remove'
            } else {
                $RemoveSKUs = $AssignedLicenses | Select-Object -ExpandProperty SkuId
                if ($PSCmdlet.ShouldProcess($UPN, "Remove $($RemoveSKUs.Count) license(s)")) {
                    Set-MgUserLicense -UserId $UPN `
                        -AddLicenses @() `
                        -RemoveLicenses $RemoveSKUs | Out-Null
                }
                Add-ReportRow $UPN 'Remove Licenses' 'PASS' "Removed $($RemoveSKUs.Count) license(s) — seats available for reassignment"
            }
        } catch {
            Add-ReportRow $UPN 'Remove Licenses' 'FAIL' "Error: $_"
            $HasError = $true
        }
    } else {
        Add-ReportRow $UPN 'Remove Licenses' 'SKIP' 'Skipped — shared mailbox conversion was not confirmed'
    }

    return $HasError
}

# ── Run queue ─────────────────────────────────────────────────────────────────
$OverallError = $false
foreach ($User in $Queue) {
    $OverallError = (Invoke-SingleUserOffboarding -User $User) -or $OverallError
}

# ── Export report ─────────────────────────────────────────────────────────────
try {
    $Report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host ''
    Write-Host "Report exported to: $ReportPath"
    Write-Log "Report exported to $ReportPath"
} catch {
    Write-Warning "Report export failed: $_"
    Write-Log "Report export failed: $_" -Level 'WARN'
}

# ── Disconnect ────────────────────────────────────────────────────────────────
if (-not $WhatIfPreference) {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}

if ($OverallError) {
    Write-Log 'Offboarding completed with one or more errors — review report'
    exit 1
} else {
    Write-Log 'Offboarding completed successfully'
    exit 0
}
