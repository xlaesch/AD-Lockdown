# 11 Backup Services Module

## High-Level Summary
This module creates comprehensive offline recovery artifacts covering both DC-specific (GPOs, DNS, AD, SYSVOL) and universal (Firewall rules, Scheduled tasks, Services) system state. It supports a `-Phase` parameter (`Pre`, `Post`, `Manual`) for automatic pre/post hardening snapshots triggered by `Start-Hardening.ps1`. All backups are written to `C:\Program Files\Windows Mail_Backup` with phase-stamped subdirectories. Use `Restore-State.ps1` for interactive selective restoration.

## Controls

### 1. Backup Directory Provisioning
- What it does: Creates backup root `C:\Program Files\Windows Mail_Backup` with subdirectories: `GPO`, `DNS`, `AD`, `SYSVOL`, `Firewall`, `Tasks`, `Services`.
- Why it exists: Standardizes backup output location and structure for incident recovery.

### 2. GPO Backup (DC-only)
- What it does: Uses `Backup-GPO` to export every domain GPO to a phase-stamped subfolder under `GPO/`.
- Why it exists: Preserves full GPO state before destructive operations (wipe, hardening).
- Note: Each GPO is individually backed up with its GUID, enabling selective `Restore-GPO` later.

### 3. DNS Zone Backup (DC-only)
- What it does: Enumerates primary non-auto-created DNS zones, exports each with `dnscmd /ZoneExport`, and copies resulting `.dns` files to the DNS backup directory.
- Why it exists: Preserves authoritative DNS zone data for restoration.
- Note: Filters out auto-created zones and validates export file existence before counting success.

### 4. Active Directory IFM Backup (DC-only)
- What it does: Creates phase-stamped IFM backup folder and runs `ntdsutil` scripted commands (`activate instance ntds`, `ifm`, `create full`).
- Why it exists: Produces AD database/media backup suitable for directory recovery workflows.
- Note: Uses inline scripted `ntdsutil` input and validates expected `Active Directory` output structure before reporting success.

### 5. SYSVOL Policy Backup (DC-only)
- What it does: Resolves domain DNS root, copies `C:\Windows\SYSVOL\sysvol\<domain>\Policies` to phase-stamped destination under backup root.
- Why it exists: Preserves GPO policy files required for domain policy recovery.

### 6. Firewall Rules Export (All machines)
- What it does: Exports all `NetFirewallRule` objects and `NetFirewallProfile` settings to phase-stamped XML files via `Export-Clixml`.
- Why it exists: Captures firewall state for rollback after hardening changes.

### 7. Scheduled Tasks Export (All machines)
- What it does: Exports all scheduled tasks to a phase-stamped XML file via `Export-Clixml`.
- Why it exists: Preserves task definitions for restoration if tasks are removed during hardening.

### 8. Running Services Export (All machines)
- What it does: Exports service Name, DisplayName, Status, and StartType to a phase-stamped CSV.
- Why it exists: Captures service startup configuration for rollback if services are disabled during hardening.

### 9. Backup Summary and Verification
- What it does: Calculates and logs total backup size, backup root location, and current phase label.
- Why it exists: Provides immediate operator confirmation that artifacts were created and of non-trivial size.
