# Microsoft 365 Employee Offboarding Automation

**Stack:** PowerShell 5.1 | ExchangeOnlineManagement | Microsoft Graph API | Microsoft 365 | Azure AD

---

## The Problem

When an employee left, M365 offboarding was split across three admin portals — Azure AD admin center, Exchange admin center, and Microsoft 365 admin center — with no enforced sequence and no documentation of what had been completed. The process depended entirely on whoever was handling the ticket that day remembering all the steps.

A few things went wrong repeatedly:

- Licenses got removed before the mailbox was converted to shared in several cases — that triggers the 30-day soft-delete window, and during that window you can't convert it. The team had to wait it out.
- Disabling an Azure AD account doesn't revoke active sessions. Tokens stay valid until they expire, so terminated users on personal devices could still have access for hours or days.
- Mailboxes were sitting licensed weeks after departure because nobody looped back to finish the ticket.
- No record of what had actually been done or when. Every offboarding was undocumented.

M365 offboarding is sequence-sensitive. There's a right order and a wrong order, and doing it manually across three portals made it easy to get wrong.

---

## What It Does

`Invoke-M365Offboarding.ps1` runs the full offboarding sequence in a single execution, enforcing the correct order of operations and logging every action to an audit record.

**Sequence (order is enforced — each step gates the next where necessary):**

| Step | Action | Notes |
|------|--------|-------|
| 1 | Block sign-in — disable Azure AD account | Stops new authentication immediately |
| 2 | Revoke all active sessions (Microsoft Graph) | Invalidates all refresh tokens — cuts access on already-authenticated devices |
| 3 | Set Out of Office auto-reply | Configured before mailbox type changes |
| 4 | Convert mailbox → Shared Mailbox | Preserves email history without a license; script confirms conversion before proceeding |
| 5 | Delegate Full Access to manager | Manager access granted while script can still verify the mailbox state |
| 6 | Remove from all M365 groups and Teams | Removes the user from distribution groups, Microsoft 365 groups, and Teams memberships |
| 7 | Remove M365 licenses | Done last — only executed after shared mailbox conversion is confirmed |
| 8 | Export offboarding report | Timestamped CSV + log of every action, success/failure status per step |

**Modules used:**
- `ExchangeOnlineManagement` — mailbox conversion, OOO reply, delegation, group membership
- `Microsoft.Graph` (Scopes: `User.ReadWrite.All`, `Group.ReadWrite.All`, `Directory.AccessAsUser.All`) — account disable, session revocation, Teams removal

Supports `-WhatIf` for a full dry run with no changes committed.

---

## Troubleshooting Notes

**License removed before mailbox conversion — triggered 30-day soft-delete**

An earlier manual process removed the M365 license as the first step to free it up quickly. Once the license is removed from an active mailbox, Exchange Online places it in a 30-day soft-delete state. During that window it cannot be converted to a shared mailbox — the conversion requires the mailbox to be active. The team had to wait out the grace period on several accounts.

The script gates license removal on a confirmed conversion: it calls `Get-EXOMailbox -RecipientTypeDetails SharedMailbox` after the conversion attempt and only proceeds to license removal if that returns the account. If the conversion isn't confirmed, the script logs an error, skips the license step, and exits with a non-zero code so the issue surfaces in the run report.

**Mailbox over 50 GB — license removal silently failed**

Exchange Online enforces a 50 GB size limit on unlicensed shared mailboxes. One departing user had a 52 GB mailbox. The conversion to shared succeeded, but the subsequent license removal returned no error — it simply didn't take effect, and the license stayed assigned with no visible indication in the admin portal.

Fixed by adding a mailbox size check before the license removal step: `(Get-EXOMailbox).ProhibitSendReceiveQuota` is compared against the current `TotalItemSize`. Mailboxes over 49 GB are flagged in the report with a recommendation to enable archive (`Enable-Mailbox -Archive`) before the license can be safely removed. The script completes the remaining steps and notes the manual follow-up required.

**Session revocation returning 403 on contractor guest accounts**

A batch offboarding run that included several contractor accounts hit 403 errors on the Graph API call to revoke refresh tokens (`Revoke-MgUserSignInSession`). Guest accounts are homed in their source tenant — the Graph API call against them from our tenant returns 403 because we don't own their authentication context.

The script now checks `Get-MgUser -UserId $UPN | Select-Object UserType` before the revocation step. If `UserType` is `Guest`, the revocation is skipped with a logged warning and a note in the report that the guest's home tenant admin must handle token revocation on their end. The rest of the offboarding steps (group removal, license removal if applicable) still run.

---

## Usage

**Single user offboarding:**

```powershell
.\Invoke-M365Offboarding.ps1 `
    -UserPrincipalName "jsmith@contoso.com" `
    -ManagerUPN "manager@contoso.com" `
    -OOOMessage "Jane has left the organization. Please contact hr@contoso.com for assistance."
```

**Dry run — no changes committed:**

```powershell
.\Invoke-M365Offboarding.ps1 `
    -UserPrincipalName "jsmith@contoso.com" `
    -ManagerUPN "manager@contoso.com" `
    -WhatIf
```

**Batch offboarding from CSV:**

```powershell
.\Invoke-M365Offboarding.ps1 -CsvPath "C:\HR\Terminations_2026-03.csv"
```

Expected CSV columns: `UserPrincipalName`, `ManagerUPN`, `OOOMessage`

**Export report to specific path:**

```powershell
.\Invoke-M365Offboarding.ps1 `
    -UserPrincipalName "jsmith@contoso.com" `
    -ManagerUPN "manager@contoso.com" `
    -ReportPath "C:\IT\Offboarding\jsmith_$(Get-Date -Format 'yyyyMMdd').csv"
```

**Sample report output:**

```
UserPrincipalName   Step                     Status   Detail
jsmith@contoso.com  Block Sign-In            PASS     Account disabled in Azure AD
jsmith@contoso.com  Revoke Sessions          PASS     All refresh tokens invalidated
jsmith@contoso.com  Set OOO Reply            PASS     Auto-reply configured
jsmith@contoso.com  Convert to Shared        PASS     Mailbox type confirmed SharedMailbox
jsmith@contoso.com  Delegate to Manager      PASS     Full Access granted to manager@contoso.com
jsmith@contoso.com  Remove Group Memberships PASS     Removed from 7 groups, 3 Teams
jsmith@contoso.com  Remove Licenses          WARN     Mailbox 51.2 GB — archive required before license removal
```

**Requirements:** ExchangeOnlineManagement module (`Install-Module ExchangeOnlineManagement`), Microsoft.Graph module (`Install-Module Microsoft.Graph`), Exchange Administrator + User Administrator roles in Azure AD, PowerShell 5.1+

---

## Outcome

- Offboarding went from 45+ minutes spread across three portals to a single script run
- License removal is gated on confirmed mailbox conversion — the soft-delete issue doesn't happen anymore
- Session revocation is now part of the standard process, not something that gets skipped
- Every offboarding generates a timestamped audit log
- Licenses get reclaimed the same day instead of sitting assigned on departed employees for weeks
