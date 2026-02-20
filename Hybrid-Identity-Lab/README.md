# Hybrid Identity Implementation (AD + Entra ID)

**Stack:** Windows Server 2022 | Microsoft Entra ID | Azure AD Connect | Group Policy

---

## The Problem

The organization ran a split-identity model: on-premises AD for legacy infrastructure, separate Entra ID identities for Microsoft 365 and SaaS tools. No connection between them.

In practice: terminating someone in AD left their M365 account active until someone manually disabled it in the Entra ID portal -- a step that got missed or delayed regularly. Remote workers had no domain-joined devices, so GPO didn't reach them. Conditional Access had no visibility into AD group membership, so it couldn't factor in on-premises context.

Built this lab to get hands-on with hybrid identity before touching a production tenant. Documented it in enough detail that another admin could follow the steps without having to reverse-engineer the decisions.

---

## Environment

Three VMs on VMware Workstation:

```
On-Premises (fresnolab.local)         Azure Cloud (fresnolab.onmicrosoft.com)
------------------------------         ---------------------------------------
Windows Server 2022 DC                Microsoft Entra ID Tenant
  DNS:  192.168.1.1                     Conditional Access Policies
  DHCP: 192.168.1.0/24                  MFA Enforcement
  AD DS: fresnolab.local                Privileged Identity Management
  OU Structure:                         Enterprise SSO (M365, SaaS apps)
    OU=Users
      OU=Staff             <-- synced via Azure AD Connect -->
      OU=Admins
      OU=Service Accounts  <-- excluded from sync
    OU=Computers / Laptops / Desktops
    OU=Security Groups / Servers

Azure AD Connect v2.x
  Auth:          Password Hash Synchronization
  Seamless SSO:  Enabled
  Filtered Sync: OU=Users only (Service Accounts excluded)
  Sync Interval: 30 min
  Device Writeback: Enabled
```

Architecture diagram: [architecture_diagram.mermaid](./architecture_diagram.mermaid) -- render at [mermaid.live](https://mermaid.live) or VS Code Mermaid Preview.

---

## Troubleshooting Notes

**GitHub Mermaid renderer showed a blank canvas**

The initial diagram had 22 edges between 18 nodes with nested subgraphs. GitHub's renderer displayed a blank box with no error. The same file rendered correctly in VS Code locally.

Isolated the cause by progressively removing edges until GitHub rendered it, then adding them back one at a time. GitHub enforces an undocumented complexity limit that appeared to be around 18 edges at this node count.

Fixed by collapsing the three device types into a single Devices subgraph and removing the redundant OnPrem/Cloud boundary edge already represented by the sync arrow.

**AAD Connect delta sync silently quarantined 3 objects**

After the initial full sync, 3 of 15 test users were missing from Entra ID. The sync log showed "Success" at the top level. The missing objects only appeared in Synchronization Service Manager when filtering the connector space by "Error" export status.

Two users had a malformed `proxyAddresses` attribute (missing the `@` from a test SMTP config). The third had a UPN suffix not yet verified in the Entra ID custom domains blade. AAD Connect quarantines these silently instead of failing the overall sync cycle.

Fixed by clearing the bad attributes and verifying the domain, then forcing a delta sync:

```powershell
Set-ADUser <samAccountName> -Clear proxyAddresses
Start-ADSyncSyncCycle -PolicyType Delta
```

All three users appeared in Entra ID within 2 minutes.

---

## Build Steps

**DC setup:**
```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools
Install-ADDSForest -DomainName "fresnolab.local" -InstallDns -Force
```

**OU hierarchy:**
```powershell
$root = "DC=fresnolab,DC=local"
$ous = @(
    @{Name="Users"; Path=$root}, @{Name="Staff"; Path="OU=Users,$root"},
    @{Name="Admins"; Path="OU=Users,$root"}, @{Name="Service Accounts"; Path="OU=Users,$root"},
    @{Name="Computers"; Path=$root}, @{Name="Laptops"; Path="OU=Computers,$root"},
    @{Name="Desktops"; Path="OU=Computers,$root"}, @{Name="Security Groups"; Path=$root},
    @{Name="Servers"; Path=$root}
)
$ous | ForEach-Object { New-ADOrganizationalUnit @_ }
```

**Azure AD Connect:** Download v2.x, select Customize, choose Password Hash Sync, enable Seamless SSO, filter sync scope to `OU=Users` only, then run:
```powershell
Start-ADSyncSyncCycle -PolicyType Initial
```

**Verify Hybrid Join:**
```powershell
dsregcmd /status
# AzureAdJoined : YES  |  DomainJoined : YES  |  TenantName : fresnolab.onmicrosoft.com
```
