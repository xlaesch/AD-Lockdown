# 02 Domain Account Policies Module

## High-Level Summary
This DC-only module hardens core Active Directory account policy, privileged identity posture, and delegation/ACL exposure. It combines enforced controls (password policy, delegation cleanup, KRBTGT/DC secret rotation) with selective interactive and audit-only checks to reduce privilege-escalation and persistence paths without blindly breaking AD operations.

## Controls

### 0. Nuclear GPO Wipe & Rebuild (Prompted)
- What it does: Optionally deletes ALL domain GPOs (including Default Domain Policy and Default Domain Controllers Policy), resets local group policy files, then rebuilds defaults via `dcgpofix /ignoreschema` and `gpupdate /force`.
- Why it exists: Eliminates potentially compromised or red-team-planted GPOs in a single destructive pass before hardening begins.
- Note: This is the "nuclear option" — operator must explicitly confirm. Local GP files are backed up to `results/gp/` before deletion. All domain GPO history is lost; only rebuilt defaults remain. Should only be used when a pre-hardening backup has been captured.

### 1. KRBTGT Double Reset (Golden Ticket Mitigation)
- What it does: Resets `krbtgt` twice with new random 32-character passwords.
- Why it exists: Invalidates both current and previous KRBTGT key material used for forged ticket persistence.
- Note: Explicit two-step reset with both generated credentials written to the encrypted secrets workflow.

### 2. DC Machine Account Password Rotation
- What it does: Runs `Reset-ComputerMachinePassword`.
- Why it exists: Rotates secure-channel trust material for the DC computer account.

### 3. Kerberos Pre-Authentication Enforcement
- What it does: Finds users with `DoesNotRequirePreAuth=$true` and flips it off.
- Why it exists: Reduces AS-REP roasting exposure.

### 4. Disable AD Guest Account
- What it does: Locates and disables domain `Guest`.
- Why it exists: Removes unnecessary anonymous/low-assurance account access.

### 5. noPac Mitigation
- What it does: Sets `ms-DS-MachineAccountQuota=0` at the domain object.
- Why it exists: Prevents unprivileged machine-account creation abuse.

### 6. Domain Password Policy Baseline
- What it does: Enforces domain password and lockout settings (length, complexity, history, age, lockout timing).
- Why it exists: Strengthens resistance to guessing/spraying and weak password reuse.
- Note: Also finds the built-in Administrator by SID (`-500`) and clears `PasswordNeverExpires` if needed.

### 6.1 Pre-Windows 2000 Compatible Access Cleanup
- What it does: Removes all members except Authenticated Users (`S-1-5-11`) and ensures that SID is present.
- Why it exists: Reduces broad legacy enumeration permissions.
- Note: Uses SID-based enforcement to avoid name/localization mismatches.

### 7. Extended Account and Delegation Cleanup
- What it does:
  - Unlocks all AD users.
  - Sets users’ primary group to `Domain Users`.
  - Clears `ManagedBy` across computers/domain/OUs/groups.
  - Removes `TrustedForDelegation` from non-DC computers.
  - Removes computer objects with no `OperatingSystem`.
  - Clears `SIDHistory` from users and groups.
  - Removes `ResetData` under `HKLM:\SAM\...\Users` when present.
- Why it exists: Cleans stale privilege/delegation state and common abuse residue.
- Note: RID-hijack mitigation (`ResetData` removal) is attempted directly in SAM registry and gracefully logs if SYSTEM-level access is insufficient.

### 8. Protected Users Group Hardening
- What it does: Enumerates privileged group members not already protected, then interactively adds selected/all accounts to `Protected Users`.
- Why it exists: Applies stronger Kerberos-only constraints to sensitive identities.
- Note: Numbered operator selection with an explicit warning not to add service accounts requiring NTLM/delegation.

### 10. AdminSDHolder ACL Reset (OS-Gated)
- What it does: Resets AdminSDHolder ACL to hardened SDDL on supported OS builds.
- Why it exists: Re-baselines protected-group permission inheritance root.
- Note: Chooses distinct SDDL for Server 2019 vs 2022 and skips unknown builds to avoid unsafe blanket ACL replacement.

### 11. Force Unlock Re-Authentication
- What it does: Sets `ForceUnlockLogon=1`.
- Why it exists: Requires credentials on console unlock to reduce session hijack risk.

### 12. Enable AD Recycle Bin
- What it does: Enables the AD Recycle Bin optional feature.
- Why it exists: Improves recoverability from accidental/malicious deletions.

### 13. Clear Allowed RODC Password Replication Group
- What it does: Removes members from `Allowed RODC Password Replication Group`.
- Why it exists: Reduces replication of sensitive credentials to RODCs.

### 14. OU ACL Cleanup (Orphaned SIDs and Dangerous Delegations)
- What it does: Iterates OU ACLs, removes orphaned SID ACEs, and strips dangerous rights from broad principals (`Everyone`, `Authenticated Users`, `BUILTIN\Users`, `Domain Users`).
- Why it exists: Removes high-risk delegation footholds.
- Note: Uses SID-to-account translation failure as orphan detection and writes ACLs only when changes are needed.

### 15. DCSync Pruning (Intentionally Skipped)
- What it does: Logs and intentionally skips direct DCSync rights pruning.
- Why it exists: Avoids accidental replication breakage from aggressive permission removals.

### 16. Delegated Access Review (Audit-Only)
- What it does: Audits and logs suspicious risky rights on:
  - `AdminSDHolder`
  - Domain root
  - Protected groups (`adminCount=1`)
- Why it exists: Surfaces stealthy over-delegation without immediate destructive ACL edits.
- Note: Uses internal helper logic to classify risky rights and suppress known-safe admin principals.

### 17. Trigger LAPS Password Resets
- What it does: Clears both legacy and Windows LAPS expiration attributes on computer objects.
- Why it exists: Forces rotation of managed local admin passwords.
- Note: Handles both schemas (`ms-Mcs-AdmPwdExpirationTime` and `msLAPS-PasswordExpirationTime`) in one pass.

### 18. Audit RBCD Backdoors
- What it does: Finds objects with `msDS-AllowedToActOnBehalfOfOtherIdentity`, logs object details, and attempts to parse/log SDDL.
- Why it exists: Detects resource-based constrained delegation abuse paths.
- Note: Converts raw security descriptor bytes to SDDL for investigator-friendly review.

### 19. Interactive Privileged Group Membership Review
- What it does: Enumerates all user members of high-privilege AD groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, Print Operators, DnsAdmins, Group Policy Creator Owners) and presents a numbered interactive prompt per group for the operator to selectively remove accounts.
- Why it exists: Provides operator-driven cleanup of privileged group bloat and unauthorized admin accounts planted by attackers, without blindly stripping all memberships.
- Note: The built-in Administrator account (RID -500) is automatically protected and cannot be selected for removal. Each group is processed independently with its own selection prompt (comma-separated numbers, 'all', or 'n' to skip).
