# Enterprise Workstation Refresh & Deployment (800 Devices)

**Stack:** PowerShell 5.1 | NinjaOne RMM | Microsoft Intune | Azure AD | Active Directory | Group Policy

---

## The Problem

800 Windows 10 workstations needed to be replaced. Leadership approved the hardware budget — the decision was made to retire the old machines and bring in new Windows 11 workstations from third-party vendors rather than attempt an in-place upgrade across a mixed fleet.

No vendor provisioning, no imaging setup, no Autopilot — just 800 boxes that needed to be domain-joined, loaded with software, and validated before they hit users' desks. At that scale, doing it by hand machine-by-machine wasn't realistic.

---

## What It Does

The deployment was structured into three phases: decommission old hardware, stage and enroll new hardware, and validate.

### Phase 1 — Decommission & Procurement

Old Windows 10 machines were wiped, asset-tagged, and removed from Active Directory and Intune before being handed off to an ITAD (IT Asset Disposition) vendor. Keeping device records clean before disposal prevented ghost objects from polluting AD and the Intune device inventory.

800 new Windows 11 workstations were sourced from third-party vendors across several models to accommodate department-level requirements and budget tiers.

### Phase 2 — Staged Setup & Enrollment

IT staff processed each workstation through a documented setup checklist. Every step was the same machine to machine, which kept the process consistent and caught configuration drift early rather than at the user's desk.

**Setup sequence per workstation:**

1. Power on, complete initial Windows 11 OOBE
2. Connect to corporate network over wired ethernet — wireless was avoided during setup to eliminate connectivity variables during domain join
3. Join the domain: **Settings > Accounts > Access work or school**, sign in with domain credentials. The machine is placed into the correct Organizational Unit in Active Directory based on department
4. Run `gpupdate /force` to pull Group Policy immediately rather than waiting for the default refresh interval
5. Azure AD Connect picks up the new computer object on its next delta sync, completing Hybrid Azure AD Join and triggering automatic MDM enrollment into Microsoft Intune via the **MDM auto-enrollment Group Policy Object**
6. The NinjaOne RMM agent deploys automatically via a separate Group Policy software installation targeting the workstation OU — once the agent checks in, NinjaOne recognizes the device, applies the correct policy group, and begins software deployment

**NinjaOne software deployment:**

Once the agent checked in, NinjaOne matched the device to its policy group and pushed the full software baseline. No per-device manual installs.

| Application Category | Deployment Method |
|---------------------|------------------|
| Microsoft 365 Apps for enterprise | NinjaOne software policy |
| Endpoint security / EDR agent | NinjaOne software policy |
| VPN client | NinjaOne software policy |
| Department-specific LOB applications | NinjaOne software policy |
| Custom registry configurations | NinjaOne PowerShell script automation |

**Microsoft Intune (post-enrollment via Azure auto-enrollment):**

Once MDM enrollment completed, Intune applied the remaining configuration layer:

- **Configuration Profiles:** BitLocker enforcement, Windows Defender settings, power and sleep policy, security baseline
- **Compliance Policy:** Minimum OS version, BitLocker required, real-time protection enabled, firewall active
- **Administrative Templates:** Additional Windows settings managed through Intune rather than Group Policy

### Phase 3 — Post-Deployment Validation

After each workstation completed the setup sequence, `Validate-PostDeployment.ps1` was pushed via NinjaOne's Run Script feature. The script checks every layer of the deployment — domain join state, Intune enrollment, required app presence, BitLocker, Defender, and on-prem domain trust — and outputs a structured Pass/Fail per check. Results were reviewed in NinjaOne's script output view before the machine left the staging area.

---

## Troubleshooting Notes

**DNS misconfiguration blocking domain join on remote-site machines**

Several workstations staged at branch offices and conference rooms were picking up the ISP's DNS server from the local DHCP scope rather than the internal domain controller. Running `nltest /dsgetdc:contoso.local` returned no DC found — the machine couldn't resolve the domain name, so the join attempt failed before reaching AD. Fixed by manually setting the preferred DNS to the on-prem DC's IP in the adapter settings before attempting the join. After resolving this, a DNS pre-check step (`Resolve-DnsName contoso.local`) was added as the first item on the setup checklist.

**Azure AD Connect sync delay causing MDM auto-enrollment to fail silently**

The MDM auto-enrollment GPO fires on the Group Policy refresh cycle — immediately when `gpupdate /force` is run. But the enrollment request requires that the computer object already exist in Azure AD, which only happens after Azure AD Connect runs its delta sync (default interval: 30 minutes). On early-wave machines, the GPO fired, the enrollment request went out, found no matching object in Azure AD, and failed with no visible error. The device showed in AD but not in Intune.

Fixed by waiting for Azure AD Connect to sync before running `gpupdate /force`. Monitored sync completion with `Get-ADSyncConnectorStatistics` on the sync server and added a manual delta sync trigger (`Start-ADSyncSyncCycle -PolicyType Delta`) between waves to keep the pipeline moving. Added a sync confirmation check to the setup checklist.

**NinjaOne software policy not applying — devices landing in the wrong policy group**

A subset of machines had the NinjaOne agent installed and appeared in the console but weren't receiving software deployments. The root cause was policy group assignment: when the agent first checks in, NinjaOne places the device in a default group if no rule matches it to a specific policy group. The default group in the org had no software policy configured. Devices were sitting visible in the console but idle.

Fixed by updating NinjaOne's device assignment rules to match on the machine's AD OU, which automatically placed newly joined workstations in the correct policy group on agent check-in. Moved the handful of already-affected devices manually. Added a policy group column to the NinjaOne console view so it's immediately visible whether a device is in the right group during staging review.

---

## Usage

**Run validation on a single workstation (locally or via NinjaOne Run Script):**

```powershell
.\Validate-PostDeployment.ps1
```

**Export results to CSV for a staging wave review:**

```powershell
.\Validate-PostDeployment.ps1 -ExportCSV "C:\Temp\Wave3_Validation.csv"
```

**Override the required app list for a specific department:**

```powershell
.\Validate-PostDeployment.ps1 -RequiredApps @("Microsoft 365 Apps for enterprise","Cisco AnyConnect","CrowdStrike Falcon")
```

**Deploy via NinjaOne:**

1. NinjaOne console > Devices > select target device(s) > Run Script
2. Select `Validate-PostDeployment.ps1` from the script library
3. Run as: **SYSTEM**
4. Review output in the Script Results pane — exit code `0` = healthy, exit code `1` = gaps found

**Sample output:**

```
[PASS]  Azure AD Join — Device is Azure AD joined
[PASS]  Domain Join — Device is domain joined (contoso.local) — Hybrid Azure AD Join confirmed
[PASS]  Intune Enrollment — Active MDM enrollment confirmed (UPN: jsmith@contoso.com)
[FAIL]  Required Apps — Missing: CrowdStrike Falcon — check NinjaOne policy group assignment
[PASS]  BitLocker — Drive C: FullyEncrypted
[PASS]  Defender RTP — Real-time protection enabled
[PASS]  Domain Trust — Secure channel to contoso.local is healthy

────────────────────────────────────────
  Results: 6 passed / 1 failed
  Log: C:\Users\TEMP\PostDeploy_Validation_20250415.log
────────────────────────────────────────
```

---

## Outcome

- 800 workstations replaced and in users' hands
- Setup checklist kept each wave consistent — we got faster as we caught edge cases early rather than at the user's desk
- NinjaOne handled software deployment across all 800 machines without touching individual devices
- Validation script caught enrollment and app gaps at the staging area, not after deployment
- All retired machines wiped and sent to ITAD with clean AD and Intune records

**Requirements:** NinjaOne RMM license, Microsoft Intune license (Intune Plan 1), Azure AD P1 for Hybrid Join and MDM auto-enrollment, on-premises Active Directory with Azure AD Connect, Group Policy for NinjaOne agent deployment and MDM auto-enrollment
