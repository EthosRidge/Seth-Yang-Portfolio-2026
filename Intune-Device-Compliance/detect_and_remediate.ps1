<#
.SYNOPSIS
    Microsoft Intune Proactive Remediation: Zero-Trust Endpoint Compliance Agent.

.DESCRIPTION
    Deployed as an Intune Proactive Remediation (Endpoint Analytics > Proactive
    Remediations), this script enforces three security controls on managed endpoints:

    CONTROL 1 — BitLocker Encryption
      Verifies the system drive (C:) is fully encrypted or actively encrypting.

    CONTROL 2 — CrowdStrike Falcon Sensor
      Verifies the CsFalconService is in a Running state.

    CONTROL 3 — Windows Defender for Endpoint (MDE)
      Verifies the Sense service is running AND real-time protection is enabled.
      This detects cases where MDE is installed but its real-time engine has been
      disabled by a user or conflicting software.

    If any control fails detection, the script attempts autonomous remediation.
    Intune reads the exit code to determine compliance state:

    EXIT CODES:
      0 = Compliant (all controls passed, or all failures were remediated)
      1 = Non-Compliant (one or more failures could not be auto-remediated)

.NOTES
    Author:      Seth Yang
    Version:     4.0
    Deployment:  Intune > Endpoint Analytics > Proactive Remediations
    Schedule:    Every 1 hour
    Run As:      SYSTEM (64-bit PowerShell)
#>

#region --- Configuration ---

# Daily log file in TEMP so it persists between user sessions and can be
# retrieved via Intune's log collection without requiring a remote session.
$Global:LogFile = Join-Path -Path $env:TEMP -ChildPath "intune_remediation_$(Get-Date -Format 'yyyyMMdd').log"

# CrowdStrike service name. Verify this matches your organization's deployment —
# some older sensor versions registered under "CSFalconService" (uppercase CS).
$CrowdStrikeServiceName = "CsFalconService"

# MDE sensor service name. This is consistent across all MDE deployments.
$MdeSenseServiceName = "Sense"

# The drive to enforce BitLocker on.
$ProtectedDrive = "C:"

# BitLocker states that are acceptable for compliance. "EncryptionInProgress"
# is included because a device mid-encryption is actively moving toward
# compliance — penalizing it with a remediation trigger would re-run
# Enable-BitLocker on an already-encrypting volume, which throws an error.
$CompliantBitLockerStates = @("FullyEncrypted", "EncryptionInProgress")

#endregion

#region --- Logging ---

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "PASS", "FAIL", "REMEDIATE", "ERROR")]
        [string]$Level = "INFO"
    )
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $Global:LogFile -Value $entry -ErrorAction SilentlyContinue
    Write-Output $entry
}

#endregion

#region --- Detection Functions ---

function Test-BitLockerCompliance {
    <#
    .SYNOPSIS
        Returns $true if C: is in a BitLocker-compliant state, $false otherwise.
    .NOTES
        Compliant states are defined in $CompliantBitLockerStates. "EncryptionInProgress"
        is treated as passing because re-triggering Enable-BitLocker on an in-progress
        encryption operation throws a non-terminating error and creates noise in logs.
        I discovered this during the first production deployment when 12 devices that
        had just been enrolled showed as failing for 45-90 minutes while encryption ran.
    #>
    try {
        $volume = Get-BitLockerVolume -MountPoint $ProtectedDrive -ErrorAction Stop
        $status = $volume.VolumeStatus
        Write-Log "BitLocker status on ${ProtectedDrive}: $status" -Level INFO

        if ($status -in $CompliantBitLockerStates) {
            Write-Log "BitLocker: COMPLIANT ($status)" -Level PASS
            return $true
        } else {
            Write-Log "BitLocker: NON-COMPLIANT (Status: $status)" -Level FAIL
            return $false
        }
    }
    catch {
        Write-Log "BitLocker check error: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-CrowdStrikeCompliance {
    <#
    .SYNOPSIS
        Returns $true if the CrowdStrike Falcon service is Running, $false otherwise.
    #>
    try {
        $service = Get-Service -Name $CrowdStrikeServiceName -ErrorAction Stop
        Write-Log "CrowdStrike service status: $($service.Status)" -Level INFO

        if ($service.Status -eq "Running") {
            Write-Log "CrowdStrike: COMPLIANT" -Level PASS
            return $true
        } else {
            Write-Log "CrowdStrike: NON-COMPLIANT (Status: $($service.Status))" -Level FAIL
            return $false
        }
    }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        Write-Log "CrowdStrike: NON-COMPLIANT — service '$CrowdStrikeServiceName' not found on this endpoint." -Level FAIL
        return $false
    }
    catch {
        Write-Log "CrowdStrike check error: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-DefenderCompliance {
    <#
    .SYNOPSIS
        Returns $true if the MDE Sense service is Running AND real-time
        protection is enabled, $false otherwise.
    .NOTES
        Checking only the Sense service is insufficient. On some endpoints, Sense
        was running but the real-time protection engine had been disabled by a
        conflicting AV product during an upgrade. The endpoint appeared healthy
        in the service list while offering no active protection.
        Both conditions must be true for this control to pass.
    #>
    try {
        # Check 1: Sense service state
        $senseService = Get-Service -Name $MdeSenseServiceName -ErrorAction Stop
        Write-Log "MDE Sense service status: $($senseService.Status)" -Level INFO

        if ($senseService.Status -ne "Running") {
            Write-Log "Defender/MDE: NON-COMPLIANT — Sense service is $($senseService.Status)" -Level FAIL
            return $false
        }

        # Check 2: Real-time protection engine state
        # Get-MpComputerStatus requires the Defender module; it is available
        # on all Windows 10/11 and Server 2019+ endpoints managed by Intune.
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        Write-Log "MDE RealTimeProtectionEnabled: $($defenderStatus.RealTimeProtectionEnabled)" -Level INFO

        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            Write-Log "Defender/MDE: NON-COMPLIANT — RealTimeProtection is disabled" -Level FAIL
            return $false
        }

        Write-Log "Defender/MDE: COMPLIANT (Sense Running, RTP Enabled)" -Level PASS
        return $true
    }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        Write-Log "Defender/MDE: NON-COMPLIANT — Sense service not found. MDE may not be enrolled." -Level FAIL
        return $false
    }
    catch {
        Write-Log "Defender/MDE check error: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

#endregion

#region --- Remediation Functions ---

function Invoke-BitLockerRemediation {
    <#
    .SYNOPSIS
        Enables BitLocker on C: using the TPM key protector with XTS-AES-256 encryption.
        Returns $true if encryption started successfully, $false on failure.
    #>
    Write-Log "REMEDIATION: Attempting to enable BitLocker on $ProtectedDrive..." -Level REMEDIATE

    try {
        $tpm = Get-Tpm -ErrorAction Stop

        # Fail early if TPM is absent or not ready. Enable-BitLocker will throw
        # a generic error in this case; checking first produces a useful log entry.
        if (-not $tpm.TpmPresent) {
            Write-Log "REMEDIATION FAILED: TPM not present. Manual BitLocker configuration required." -Level ERROR
            return $false
        }
        if (-not $tpm.TpmReady) {
            Write-Log "REMEDIATION FAILED: TPM present but not ready (check TPM management console)." -Level ERROR
            return $false
        }

        Enable-BitLocker `
            -MountPoint       $ProtectedDrive `
            -EncryptionMethod XtsAes256 `
            -TpmProtector `
            -SkipHardwareTest `
            -ErrorAction Stop | Out-Null

        Write-Log "REMEDIATION SUCCESS: BitLocker encryption initiated on $ProtectedDrive." -Level REMEDIATE
        return $true
    }
    catch {
        Write-Log "REMEDIATION FAILED (BitLocker): $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Invoke-CrowdStrikeRemediation {
    <#
    .SYNOPSIS
        Attempts to start the CrowdStrike Falcon service.
        Polls for up to 30 seconds before declaring failure.
    #>
    Write-Log "REMEDIATION: Attempting to start CrowdStrike Falcon..." -Level REMEDIATE

    try {
        Start-Service -Name $CrowdStrikeServiceName -ErrorAction Stop

        # Start-Service returns before the service reaches Running state.
        # Polling prevents a false success where the service starts then
        # immediately exits due to a configuration or license issue.
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            $svc = Get-Service -Name $CrowdStrikeServiceName -ErrorAction SilentlyContinue
            if ($svc.Status -eq "Running") {
                Write-Log "REMEDIATION SUCCESS: CrowdStrike Falcon is Running." -Level REMEDIATE
                return $true
            }
        }

        Write-Log "REMEDIATION FAILED: CrowdStrike did not reach Running state within 30 seconds." -Level ERROR
        return $false
    }
    catch {
        Write-Log "REMEDIATION FAILED (CrowdStrike): $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Invoke-DefenderRemediation {
    <#
    .SYNOPSIS
        Attempts to start the MDE Sense service and re-enable real-time protection.
        Forces a signature update via Update-MpSignature to restore full coverage.
    #>
    Write-Log "REMEDIATION: Attempting to restore Windows Defender/MDE compliance..." -Level REMEDIATE

    $remediationOk = $true

    # Step 1: Start the Sense service if it is not running
    try {
        $senseService = Get-Service -Name $MdeSenseServiceName -ErrorAction Stop
        if ($senseService.Status -ne "Running") {
            Start-Service -Name $MdeSenseServiceName -ErrorAction Stop
            Start-Sleep -Seconds 5

            $senseService = Get-Service -Name $MdeSenseServiceName -ErrorAction SilentlyContinue
            if ($senseService.Status -eq "Running") {
                Write-Log "REMEDIATION: Sense service started." -Level REMEDIATE
            } else {
                Write-Log "REMEDIATION FAILED: Sense service did not start." -Level ERROR
                $remediationOk = $false
            }
        }
    }
    catch {
        Write-Log "REMEDIATION FAILED (Sense service): $($_.Exception.Message)" -Level ERROR
        $remediationOk = $false
    }

    # Step 2: Re-enable real-time protection if it is disabled
    # Set-MpPreference modifies the Windows Defender policy. This can be
    # overridden by Group Policy or Intune policy on the next sync cycle,
    # so this remediation is a bridge until the policy applies.
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Log "REMEDIATION: Real-time protection re-enabled." -Level REMEDIATE
    }
    catch {
        Write-Log "REMEDIATION FAILED (RTP): $($_.Exception.Message)" -Level ERROR
        $remediationOk = $false
    }

    # Step 3: Force a signature update so definitions are current after re-enabling
    try {
        Update-MpSignature -ErrorAction Stop
        Write-Log "REMEDIATION: Defender signatures updated." -Level REMEDIATE
    }
    catch {
        # Signature update failure is non-critical — definitions may be
        # recent enough. Log as WARNING, do not mark remediation as failed.
        Write-Log "WARNING: Signature update failed (non-critical): $($_.Exception.Message)" -Level INFO
    }

    return $remediationOk
}

#endregion

#region --- Main Execution ---

Write-Log "==============================" -Level INFO
Write-Log "Compliance Check Started" -Level INFO
Write-Log "Host: $env:COMPUTERNAME | Script version: 4.0" -Level INFO
Write-Log "==============================" -Level INFO

# --- Detection Phase ---
$bitlockerOk   = Test-BitLockerCompliance
$crowdStrikeOk = Test-CrowdStrikeCompliance
$defenderOk    = Test-DefenderCompliance

# If all three controls pass, exit immediately. This is the happy path and
# the majority of hourly runs should follow it on a well-managed fleet.
if ($bitlockerOk -and $crowdStrikeOk -and $defenderOk) {
    Write-Log "RESULT: Device is FULLY COMPLIANT across all 3 controls." -Level PASS
    Write-Log "==============================" -Level INFO
    exit 0
}

# --- Remediation Phase ---
Write-Log "RESULT: Compliance violations detected. Entering remediation phase." -Level FAIL
$allRemediated = $true

if (-not $bitlockerOk) {
    if (-not (Invoke-BitLockerRemediation)) { $allRemediated = $false }
}

if (-not $crowdStrikeOk) {
    if (-not (Invoke-CrowdStrikeRemediation)) { $allRemediated = $false }
}

if (-not $defenderOk) {
    if (-not (Invoke-DefenderRemediation)) { $allRemediated = $false }
}

# --- Final Status ---
if ($allRemediated) {
    Write-Log "RESULT: All violations remediated. Device returning to compliant state." -Level PASS
    Write-Log "==============================" -Level INFO
    exit 0
} else {
    Write-Log "RESULT: Remediation INCOMPLETE. Manual intervention required." -Level ERROR
    Write-Log "Log: $Global:LogFile" -Level ERROR
    Write-Log "==============================" -Level INFO
    exit 1
}

#endregion
