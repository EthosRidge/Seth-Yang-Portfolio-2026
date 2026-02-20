# Automated Identity Provisioning at Scale

**Stack:** PowerShell 5.1 | Active Directory | Windows Server 2022

---

## The Problem

The organization was creating AD accounts by hand through the ADUC GUI -- one field at a time, one user at a time. The process ran behind during any busy hiring period, and the manual entry produced a steady stream of mistakes: wrong department, missing manager reference, inconsistent DisplayName capitalization that broke downstream display logic.

Group membership was tracked separately in a shared spreadsheet that nobody kept current. New users regularly spent their first day unable to access the drives or printers they needed because nobody had added them to the right groups.

---

## What It Does

Reads a CSV from HR and runs the full AD onboarding sequence without manual steps:

- Validates CSV schema and AD module availability before touching anything
- Derives a standardized sAMAccountName (first initial + last name, stripped, truncated to 20 chars)
- Generates a 16-character password and creates the account via `New-ADUser`
- Assigns department group via `Add-ADGroupMember` using a `$DepartmentGroupMap` hashtable -- HR owns the CSV data, IT owns the group mapping
- Provisions the home directory on the file server and sets a scoped Full Control ACL
- Logs every operation with a timestamp; supports `-WhatIf` for dry runs

---

## Troubleshooting Notes

**Manager lookup silently passed `$null` to `New-ADUser`**

When a manager SAM did not exist in AD yet, `Get-ADUser` returned `$null` and `New-ADUser` accepted it without error -- the Manager attribute was left blank with no log entry. Fixed by pulling the lookup into `Resolve-ManagerDN` (line 172), which logs a WARNING with the missing SAM before returning `$null`. Behavior is the same, but the audit trail is now usable.

**Passwords intermittently failed domain complexity policy**

The generator was picking from all character classes but not guaranteeing one from each before the random fill. A batch run would occasionally produce an all-lowercase or symbol-free password that `New-ADUser` rejected. Fixed by seeding the array with one character from each required class, then applying Fisher-Yates shuffle so the guaranteed characters are not always at positions 0-3.

---

## Usage

```powershell
.\user_onboarding.ps1 `
    -CsvPath "C:\HR\NewHires_2026-01.csv" `
    -HomeDriveRoot "\\fileserver01\HomeDirectories$" `
    -OUPath "OU=Employees,OU=Users,DC=contoso,DC=com"

# Dry run -- no changes committed
.\user_onboarding.ps1 `
    -CsvPath "C:\HR\NewHires_2026-01.csv" `
    -HomeDriveRoot "\\fileserver01\HomeDirectories$" `
    -WhatIf
```

**Expected CSV columns:** FirstName, LastName, Department, Manager, Title, Office

**Requirements:** Windows Server 2019+, RSAT ActiveDirectory module, delegated OU write rights
