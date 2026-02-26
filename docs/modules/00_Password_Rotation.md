# 00 Password Rotation Module

## High-Level Summary
This module performs interactive password rotation for domain and local accounts, records generated credentials to a per-run secrets CSV, and encrypts the secrets output (immediately or deferred when orchestrated by `Start-Hardening.ps1`).

## Controls

### 1. Backup Domain Admin Failsafe (DC only)
- What it does: Optionally creates a backup privileged account (default `CCDCAdmin`) or resets it if it already exists.
- Why it exists: Preserves administrative recovery access during incident response or lockout scenarios.
- Note: Re-applies membership in five high-privilege groups (`Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`, `Group Policy Creator Owners`) and handles “already a member” cases idempotently.

### 2. Domain User Password Rotation (DC only)
- What it does: Supports rotating either all eligible domain user passwords or only selected domain accounts.
- Why it exists: Reduces persistence from credential theft and stale passwords.
- Note: Excludes high-risk/built-in accounts (`Administrator`, `krbtgt`, `Guest`, `DefaultAccount`) and privileged group members (`Domain Admins`, `Enterprise Admins`) during bulk rotation, and filters service-style accounts using the `^svc` naming pattern.

### 3. Local User Password Rotation (All machines)
- What it does: Supports rotating either all eligible local user passwords or selected local accounts.
- Why it exists: Limits lateral movement using compromised local credentials.
- Note: Excludes local built-ins (`Guest`, `DefaultAccount`, `WDAGUtilityAccount`) during bulk rotation and uses the same service-account pattern filtering strategy.

### 4. Secrets Capture and Protection
- What it does: Writes all rotated credentials to `secrets/rotated_passwords_<timestamp>.csv` and encrypts the file with operator-supplied password.
- Why it exists: Maintains recoverability of rotated credentials while reducing plaintext exposure.
- Note: Uses global orchestration flags (`$global:SecretsEncryptionDeferred`, `$global:SecretsFilePassword`, `$global:RotatedPasswordFile`) so encryption can be deferred until all selected modules complete.
