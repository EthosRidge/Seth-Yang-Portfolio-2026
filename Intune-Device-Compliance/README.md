# Intune Proactive Remediation: Endpoint Security Compliance

**Stack:** PowerShell 5.1 | Microsoft Intune | BitLocker | CrowdStrike Falcon | Windows Defender for Endpoint

---

## The Problem

A compliance audit flagged the endpoint fleet -- a meaningful portion of managed Windows devices had at least one security control in a failed state:

- BitLocker suspended after BIOS updates or drive replacements, never re-armed
- CrowdStrike Falcon sensor stopped on a number of devices (software conflicts, bad shutdowns, and in a couple of cases, deliberate user tampering)
- Windows Defender real-time protection disabled on devices migrated from a third-party AV -- the migration script disabled Defender and never turned it back on

The compliance process was a weekly manual CSV review. There was roughly a six-day window between a control failing and someone noticing, and each remediation required a technician to remote in and fix it by hand.

---

## What It Does

Runs on a 1-hour Intune schedule. Checks three controls, remediates failures automatically, exits with a code Intune can read:

- Detection: three independent functions (`Test-BitLockerCompliance`, `Test-CrowdStrikeCompliance`, `Test-DefenderCompliance`) each return a boolean. All passing exits 0 immediately without entering remediation.
- Remediation: each failed control has a paired remediation function. They run independently -- a failed CrowdStrike remediation does not block the Defender attempt.
- Exit codes: `0` = compliant, `1` = non-compliant. Get this wrong and Intune's compliance data is garbage.

| Control | Detection | Remediation |
|---------|-----------|-------------|
| BitLocker | `Get-BitLockerVolume` -- VolumeStatus must be `FullyEncrypted` or `EncryptionInProgress` | `Enable-BitLocker` with TPM protector, XTS-AES-256 |
| CrowdStrike Falcon | `Get-Service CsFalconService` -- must be `Running` | `Start-Service` with 30-second polling loop |
| Windows Defender/MDE | `Get-Service Sense` + `Get-MpComputerStatus.RealTimeProtectionEnabled` | `Start-Service Sense`, `Set-MpPreference`, `Update-MpSignature` |

All operations log to `$env:TEMP\intune_remediation_<date>.log`.

---

## Troubleshooting Notes

**Newly enrolled devices flagged non-compliant mid-encryption**

First production deployment to a batch of new laptops immediately reported 35 non-compliant. IT had enabled BitLocker during enrollment, but the script only accepted `FullyEncrypted` -- it did not account for `EncryptionInProgress`. It then called `Enable-BitLocker` on drives already encrypting, which threw a non-terminating error, got caught by try/catch, and exited with code 1.

Fixed by changing the detection from an equality check to a membership check: `$CompliantBitLockerStates = @("FullyEncrypted", "EncryptionInProgress")`.

**Sense service reported Running but devices had no active protection**

Initial testing only checked `Get-Service Sense`. Several devices passed -- service was running -- but endpoint dashboards showed no coverage. The real-time protection engine had been disabled separately. `Get-MpComputerStatus.RealTimeProtectionEnabled` returned `$false`.

Added the second condition to `Test-DefenderCompliance`: both the service must be running AND the engine must be enabled.

---

## Usage

Intune > Endpoint Analytics > Proactive Remediations:

1. Upload `detect_and_remediate.ps1` as both Detection and Remediation script
2. Run as: **SYSTEM**, 64-bit PowerShell
3. Schedule: **Every 1 hour**
4. Assign to all managed Windows 10/11 devices

```powershell
# Retrieve logs directly on device:
Get-Content "$env:TEMP\intune_remediation_$(Get-Date -Format 'yyyyMMdd').log"
```
