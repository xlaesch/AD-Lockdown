# 05 Audit Logging Module

## High-Level Summary
This module strengthens host and AD audit visibility by enforcing advanced audit policy, hardening LSASS/credential logging controls, enabling PowerShell telemetry, and expanding event log retention. On DCs, it also applies targeted AD object SACL auditing and performs reporting-only checks for risky GPO permissions.

## Controls

### 1. LSASS Protected Process (RunAsPPL)
- What it does: Sets `RunAsPPL=1` for LSASS.
- Why it exists: Raises protection against memory access and credential theft techniques.

### 2. LSASS Audit Level
- What it does: Sets `AuditLevel=8` for `LSASS.exe` IFEO settings.
- Why it exists: Increases visibility into LSASS access activity.

### 3. WDigest Credential Hardening
- What it does: Sets `UseLogonCredential=0` and `Negotiate=0` in WDigest.
- Why it exists: Prevents plaintext credential caching behavior tied to WDigest.

### 4. Force Advanced Audit Policy
- What it does: Sets `SCENoApplyLegacyAuditPolicy=1`.
- Why it exists: Ensures advanced audit subcategory settings are not overridden by legacy policy mode.

### 5. Comprehensive Audit Subcategory Configuration
- What it does: Applies a large audit baseline across account logon/management, detailed tracking, logon/logoff, object access, policy change, privilege use, and system categories using `auditpol`.
- Why it exists: Improves detection coverage across identity, process, and policy events.
- Note: Uses a centralized rule list and builds `auditpol` command behavior per `Success and Failure`, `Failure`, or `Success`; automatically adds Directory Service categories only when running on a DC.

### 6. Command-Line Process Auditing
- What it does: Enables `ProcessCreationIncludeCmdLine_Enabled`.
- Why it exists: Preserves command-line context in process creation events (for example Event ID 4688).

### 7. PowerShell Script Block Logging
- What it does: Enables script block and script block invocation logging policy keys.
- Why it exists: Increases visibility into script content and execution flow.

### 8. PowerShell Module Logging
- What it does: Enables module logging and configures `ModuleNames\* = *`.
- Why it exists: Captures module-level PowerShell execution details.
- Note: Wildcard module configuration logs all modules rather than selected allowlists.

### 9. Event Log Size Expansion
- What it does: Increases max sizes for Security (~1GB), Application, System, and Windows PowerShell logs.
- Why it exists: Reduces loss of forensic events from log rollover under heavy activity.
- Note: Uses `Get-WinEvent -ListLog` and runtime `SaveChanges()` instead of shelling out to `wevtutil`.

### DC-Only: 10. Advanced AD Object Auditing
- What it does: Adds SACL audit rules on:
  - `RID Manager$` (failure audit for `GenericAll`)
  - `AdminSDHolder` (failure audit for `GenericAll`)
  - `OU=Domain Controllers` (success audit for `WriteDacl`)
- Why it exists: Improves visibility into sensitive AD object and ACL tampering attempts.
- Note: Creates native `System.DirectoryServices.ActiveDirectoryAuditRule` entries using the World SID (`Everyone`) and applies them directly to AD object ACLs.

### DC-Only: 11. GPO Permission Review (Audit-Only)
- What it does: Enumerates all GPO permissions and reports cases where `Authenticated Users` has anything other than `GpoRead`.
- Why it exists: Surfaces potentially dangerous delegation on GPOs without auto-remediation risk.
- Note: Explicitly report-only; logs findings but does not change permissions.
