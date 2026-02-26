# 01 Local Account Policies Module

## High-Level Summary
This module hardens local account behavior on all Windows hosts by disabling weak/default account paths, enforcing baseline local password and lockout policy, and applying key registry controls that reduce credential exposure and local persistence opportunities.

## Controls

### 1. Disable Guest Account
- What it does: Disables the local `Guest` account using `net user Guest /active:no`.
- Why it exists: Removes a common low-friction entry point.
- Note: Uses legacy `net user` for broad compatibility instead of relying on newer-only cmdlets.

### 2. Enforce Local Password and Lockout Policy
- What it does: Sets minimum length, password age/history, lockout threshold/window/duration, and force-logoff behavior via a single `net accounts` command.
- Why it exists: Raises resistance to brute force and weak-password reuse.
- Note: Applies all major local account policy knobs in one atomic command (`/MINPWLEN`, `/UNIQUEPW`, `/lockout*`, `/FORCELOGOFF`).

### 3. Disable Auto Admin Logon
- What it does: Sets `AutoAdminLogon=0` and removes `DefaultPassword` from Winlogon if present.
- Why it exists: Prevents plaintext credential persistence and unattended privileged logon.
- Note: Includes cleanup of stored Winlogon password material, not just policy toggle.

### 4. Restrict Blank Password Network Use
- What it does: Sets `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=1`.
- Why it exists: Blocks remote logons that rely on blank local passwords.

### 5. LSA Notification Package Review and Cleanup
- What it does: Audits `Notification Packages`, flags non-standard entries, and prompts to reset.
- Why it exists: Reduces risk of credential interception by malicious LSA packages.
- Note: Uses an allowlist check (`scecli`, `rassfm`) and interactive remediation; if confirmed, it resets to strict default (`scecli`) for safer baseline.

### 6. Reduce Cached Domain Logons
- What it does: Sets `CachedLogonsCount` to `2`.
- Why it exists: Limits offline credential artifacts and cached domain logon exposure.
- Note: Uses a low-but-nonzero value to balance security and operational resilience.

### 7. Restrict CD-ROM Access Context
- What it does: Sets `AllocateCDRoms=1` so CD-ROM access is tied to the logged-on user.
- Why it exists: Reduces abuse of removable media access from other security contexts.
