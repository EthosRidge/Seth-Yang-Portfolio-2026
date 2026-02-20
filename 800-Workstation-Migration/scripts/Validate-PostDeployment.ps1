<#
.SYNOPSIS
    Validates that a newly provisioned workstation's custom ecosystem is fully in place.

.DESCRIPTION
    Runs after the workstation setup checklist completes. Checks every layer of the
    deployment: Hybrid Azure AD join, Intune MDM enrollment, required application
    presence, BitLocker encryption, Defender real-time protection, and on-prem domain trust.

    Designed to be pushed via NinjaOne RMM (Devices > Run Script) against newly enrolled
    devices during staging review, or run locally by IT staff. Surfaces gaps before the
    device is handed off to a user.

.PARAMETER RequiredApps
    Array of application display names to check in Add/Remove Programs. Defaults to
    a baseline set. Override with your org's required app list.

.PARAMETER ExportCSV
    Path to write a CSV export of results. Useful when running across a provisioning wave.

.EXAMPLE
    .\Validate-PostDeployment.ps1
    .\Validate-PostDeployment.ps1 -ExportCSV "C:\Temp\Wave2_ValidationResults.csv"
    .\Validate-PostDeployment.ps1 -RequiredApps @("CrowdStrike Falcon","Microsoft 365 Apps","Cisco AnyConnect")

.NOTES
    Run as: SYSTEM (when pushed via NinjaOne Run Script) or as the local admin during staging.
    Exit 0 = all checks passed. Exit 1 = one or more checks failed.
    Results also written to registry for optional Intune Compliance Policy query.
#>

[CmdletBinding()]
param (
    [string[]]$RequiredApps = @(
        'CrowdStrike Falcon',
        'Microsoft 365 Apps for enterprise',
        'Cisco AnyConnect Secure Mobility Client'
    ),
    [string]$ExportCSV
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogPath    = "$env:TEMP\PostDeploy_Validation_$(Get-Date -Format 'yyyyMMdd').log"
$DeviceName = $env:COMPUTERNAME
$Results    = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $Entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Entry
    Write-Verbose $Entry
}

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail)
    $Results.Add([PSCustomObject]@{
        Device  = $DeviceName
        Check   = $Check
        Status  = $Status
        Detail  = $Detail
        RunTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
    $Symbol = if ($Status -eq 'PASS') { '[PASS]' } else { '[FAIL]' }
    Write-Host "$Symbol  $Check — $Detail"
    Write-Log "$Symbol $Check — $Detail" -Level $Status
}

# ── 1. Azure AD Join ──────────────────────────────────────────────────────────
try {
    # dsregcmd /status is the authoritative source for join state
    $DsReg = & dsregcmd /status 2>&1 | Out-String
    $AadJoined = $DsReg -match 'AzureAdJoined\s*:\s*YES'
    if ($AadJoined) {
        Add-Result 'Azure AD Join' 'PASS' 'Device is Azure AD joined'
    } else {
        Add-Result 'Azure AD Join' 'FAIL' 'Device is NOT Azure AD joined — Autopilot enrollment may be incomplete'
    }
} catch {
    Add-Result 'Azure AD Join' 'FAIL' "Error running dsregcmd: $_"
}

# ── 2. Domain Join (Hybrid) ───────────────────────────────────────────────────
try {
    $DomainJoined = $DsReg -match 'DomainJoined\s*:\s*YES'
    if ($DomainJoined) {
        # Extract domain name for the log
        $DomainName = if ($DsReg -match 'DomainName\s*:\s*(\S+)') { $Matches[1] } else { 'unknown' }
        Add-Result 'Domain Join' 'PASS' "Device is domain joined ($DomainName) — Hybrid Azure AD Join confirmed"
    } else {
        Add-Result 'Domain Join' 'FAIL' 'Device is NOT domain joined — AD computer object may not have synced yet, check Azure AD Connect delta sync'
    }
} catch {
    Add-Result 'Domain Join' 'FAIL' "Error checking domain join state: $_"
}

# ── 3. Intune MDM Enrollment ──────────────────────────────────────────────────
try {
    $EnrollmentRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    $ActiveEnrollment = Get-ChildItem -Path $EnrollmentRoot -ErrorAction Stop |
        Get-ItemProperty -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderID -eq 'MS DM Server' -and $_.EnrollmentState -eq 1 }

    if ($ActiveEnrollment) {
        $UPN = $ActiveEnrollment.UPN
        Add-Result 'Intune Enrollment' 'PASS' "Active MDM enrollment confirmed (UPN: $UPN)"
    } else {
        Add-Result 'Intune Enrollment' 'FAIL' 'No active Intune MDM enrollment found — check Intune enrollment status in portal'
    }
} catch {
    Add-Result 'Intune Enrollment' 'FAIL' "Error querying enrollment registry: $_"
}

# ── 4. Required Applications ──────────────────────────────────────────────────
try {
    # Check both 32-bit and 64-bit uninstall registry paths
    $UninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $InstalledApps = foreach ($Path in $UninstallPaths) {
        if (Test-Path $Path) {
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object -ExpandProperty DisplayName
        }
    }
    $InstalledApps = $InstalledApps | Sort-Object -Unique

    $MissingApps = $RequiredApps | Where-Object {
        $AppName = $_
        -not ($InstalledApps | Where-Object { $_ -like "*$AppName*" })
    }

    if ($MissingApps.Count -eq 0) {
        Add-Result 'Required Apps' 'PASS' "All $($RequiredApps.Count) required application(s) detected"
    } else {
        Add-Result 'Required Apps' 'FAIL' "Missing: $($MissingApps -join ', ') — check Intune app deployment status and Win32 app detection rules"
    }
} catch {
    Add-Result 'Required Apps' 'FAIL' "Error querying installed applications: $_"
}

# ── 5. BitLocker Encryption ───────────────────────────────────────────────────
try {
    $SystemDrive     = $env:SystemDrive
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $SystemDrive -ErrorAction Stop
    $CompliantStates = @('FullyEncrypted', 'EncryptionInProgress')

    if ($BitLockerVolume.VolumeStatus -in $CompliantStates) {
        Add-Result 'BitLocker' 'PASS' "Drive ${SystemDrive} $($BitLockerVolume.VolumeStatus)"
    } else {
        Add-Result 'BitLocker' 'FAIL' "Drive ${SystemDrive} status is $($BitLockerVolume.VolumeStatus) — BitLocker enforcement policy may not have applied yet"
    }
} catch {
    Add-Result 'BitLocker' 'FAIL' "Error querying BitLocker status: $_"
}

# ── 6. Defender Real-Time Protection ─────────────────────────────────────────
try {
    $MpStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($MpStatus.RealTimeProtectionEnabled) {
        Add-Result 'Defender RTP' 'PASS' 'Real-time protection enabled'
    } else {
        Add-Result 'Defender RTP' 'FAIL' 'Real-time protection is disabled — check for conflicting AV or Defender policy'
    }
} catch {
    Add-Result 'Defender RTP' 'FAIL' "Error querying Defender status: $_"
}

# ── 7. Domain Trust (Secure Channel) ─────────────────────────────────────────
try {
    $SecureChannel = Test-ComputerSecureChannel -ErrorAction Stop
    if ($SecureChannel) {
        Add-Result 'Domain Trust' 'PASS' "Secure channel to $env:USERDNSDOMAIN is healthy"
    } else {
        Add-Result 'Domain Trust' 'FAIL' "Secure channel to domain is broken — device may need to be re-joined or synced"
    }
} catch {
    # Test-ComputerSecureChannel throws if the machine is not domain joined — already caught above
    Add-Result 'Domain Trust' 'FAIL' "Could not verify domain secure channel: $_"
}

# ── Write registry key for Intune Compliance Policy query ────────────────────
try {
    $RegPath = 'HKLM:\SOFTWARE\OrgIT\PostDeployValidation'
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    $Failures = ($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    Set-ItemProperty -Path $RegPath -Name 'ValidationResult' -Value ($Failures -eq 0 ? 'PASS' : 'FAIL') -Force
    Set-ItemProperty -Path $RegPath -Name 'LastRun'          -Value (Get-Date -Format 'o') -Force
    Set-ItemProperty -Path $RegPath -Name 'FailureCount'     -Value $Failures -Force
    Write-Log "Registry key written: $RegPath (Failures: $Failures)"
} catch {
    Write-Log "Could not write registry key: $_" -Level 'WARN'
}

# ── Summary ───────────────────────────────────────────────────────────────────
$Failures = $Results | Where-Object { $_.Status -eq 'FAIL' }
$Passes   = $Results | Where-Object { $_.Status -eq 'PASS' }

Write-Host ''
Write-Host '────────────────────────────────────────'
Write-Host "  Results: $($Passes.Count) passed / $($Failures.Count) failed"
Write-Host "  Log: $LogPath"
Write-Host '────────────────────────────────────────'

if ($ExportCSV) {
    try {
        $Results | Export-Csv -Path $ExportCSV -NoTypeInformation -Force
        Write-Host "  CSV exported to: $ExportCSV"
        Write-Log "CSV exported to $ExportCSV"
    } catch {
        Write-Warning "CSV export failed: $_"
        Write-Log "CSV export failed: $_" -Level 'WARN'
    }
}

if ($Failures.Count -gt 0) {
    Write-Log "POST-DEPLOYMENT VALIDATION FAILED ($($Failures.Count) check(s) failed)"
    exit 1
} else {
    Write-Log 'POST-DEPLOYMENT VALIDATION PASSED — device ecosystem is healthy'
    exit 0
}
