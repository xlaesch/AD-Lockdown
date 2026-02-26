# 08 System Hardening Module

## High-Level Summary
This module applies aggressive host-level hardening across policy reset, persistence cleanup, exploit/CVE mitigations, UAC and boot protections, script/command execution restrictions, and multiple registry-based OS security controls. It includes several high-impact interactive options (startup/task cleanup and GPO reset) intended for incident-response style lockdown.

## Controls

### 0. Local Group Policy Reset (Prompted)
- What it does: Optionally backs up and removes local GroupPolicy objects, then forces `gpupdate`.
- Why it exists: Resets potentially tampered local policy state.
- Note: Backs up policy artifacts to `results/gp` before reset. Domain-level GPO wipe (delete all + dcgpofix) has been moved to module 02 (Domain Account Policies) which runs earlier in the hardening sequence.

### 0a. HiveNightmare Mitigation (CVE-2021-36934)
- What it does: Resets ACL inheritance on `%windir%\system32\config\*`.
- Why it exists: Reduces exposure of sensitive SAM/SYSTEM/SECURITY hive data.

### 0b. Winlogon Persistence Protection
- What it does: Removes cached default credentials, restores safe `Shell`/`Userinit`, and removes `UIHost`.
- Why it exists: Removes common Winlogon persistence/credential residue points.

### 0c. DLL Hijacking Protections
- What it does: Removes tracing keys, enforces safe DLL/process search modes, blocks unsafe CWD DLL loading, disables `AppInit_DLLs`.
- Why it exists: Reduces DLL search-order and loader abuse.

### 0d. Disable Windows Script Host
- What it does: Disables WSH in HKLM and HKCU.
- Why it exists: Reduces script-based initial access and persistence.

### 0e. CredSSP Oracle Mitigation (CVE-2018-0886)
- What it does: Sets `AllowEncryptionOracle=0`.
- Why it exists: Enforces secure CredSSP behavior against downgrade abuse.

### 0f. Disable Legacy AT Scheduler Command
- What it does: Sets `EnableAt=0`.
- Why it exists: Removes legacy scheduled execution surface.

### 0g. Office DDE Protections
- What it does: Disables automatic link updates in Office options paths.
- Why it exists: Reduces DDE-based document execution abuse.

### 0h. Disable Windows Error Reporting
- What it does: Disables WER and additional-data submission.
- Why it exists: Reduces telemetry/data leakage and some crash-abuse workflows.

### 0i. BitLocker Policy Hardening
- What it does: Enforces TPM + PIN style BitLocker policy values.
- Why it exists: Strengthens disk-at-rest protection posture.

### 0j. SmartScreen Enforcement
- What it does: Enables SmartScreen policy and block-level behavior.
- Why it exists: Adds reputation and download execution safeguards.

### 1. UAC Hardening
- What it does: Applies strict UAC policy set (LUA, secure desktop prompts, installer detection, signature validation, restricted token filtering).
- Why it exists: Reduces silent privilege escalation and unsafe admin token use.

### 2. DEP AlwaysOn
- What it does: Sets boot DEP to `AlwaysOn` and related policy keys.
- Why it exists: Hardens memory execution protections.

### 3. Disable AutoRun/AutoPlay
- What it does: Disables autorun/autoplay across HKLM/HKCU policy paths.
- Why it exists: Reduces removable media execution abuse.

### 4. Remove Accessibility Backdoor Paths
- What it does: Removes IFEO debugger hijacks for Ease-of-Access binaries, then takes ownership and deletes selected binaries.
- Why it exists: Disrupts sticky-keys/utilman style pre-logon backdoors.
- Note: Performs both IFEO cleanup and binary removal (`sethc`, `Utilman`, `osk`, `Narrator`, `Magnify`).

### 5. Startup Persistence Cleanup (Prompted)
- What it does: Optionally removes startup-folder entries, `autoexec.bat`, GP startup/logon scripts, and Run/RunOnce registry entries.
- Why it exists: Clears common autorun persistence locations.

### 6. Scheduled Task Audit/Removal (Prompted)
- What it does: Optionally removes non-Microsoft scheduled tasks, or lists them for review only.
- Why it exists: Targets scheduled-task persistence while preserving core Microsoft tasks by default.

### 7. Disable Cortana and Cloud Search
- What it does: Disables Cortana/web/cloud search policy settings.
- Why it exists: Reduces cloud-integrated search exposure and data leakage.

### 8. Lock Screen Hardening
- What it does: Disables lock-screen camera/slideshow and input personalization features.
- Why it exists: Reduces lock-screen interaction and data exposure surface.

### 9. Show Extensions and Hidden/System Files
- What it does: Forces Explorer to show file extensions and hidden/system files.
- Why it exists: Improves operator visibility for suspicious files.

### 10. System Integrity Checks
- What it does: Runs `sfc /scannow`, ensures TrustedInstaller auto-start, then runs `DISM /RestoreHealth`.
- Why it exists: Repairs tampered/corrupt system components.

### 11. Disable CMD System-Wide
- What it does: Sets `DisableCMD=1` and sets Command Processor `AutoRun=exit` for HKLM/HKCU.
- Why it exists: Restricts command-shell abuse.
- Note: Uses both policy disable and autorun exit fallback.

### 12. Kernel and Boot Security
- What it does: Disables test-signing and enforces integrity checks via `bcdedit`.
- Why it exists: Reduces unsigned/test driver abuse.

### 12a. Crash Dump and Recovery Hardening
- What it does: Disables crash dumps and enables auto-reboot.
- Why it exists: Reduces memory dump credential exposure.

### 12b. Disable AlwaysInstallElevated
- What it does: Sets `AlwaysInstallElevated=0` for HKLM and HKCU.
- Why it exists: Blocks MSI privilege-escalation misuse.

### 12c. Require Password on Wake
- What it does: Sets power policy to require console lock on resume.
- Why it exists: Protects unattended resumed sessions.

### 12d. Screen Saver Grace Period
- What it does: Sets `ScreenSaverGracePeriod=0`.
- Why it exists: Removes grace window after lock trigger.

### 12e. Reassociate Dangerous Script/File Types
- What it does: Rebinds high-risk file types (for example `batfile`, `jsfile`, `vbsfile`, `htafile`) to Notepad.
- Why it exists: Reduces accidental/direct execution of scriptable payload types.

### 12f. Disable 8.3 Filename Creation
- What it does: Sets `NtfsDisable8dot3NameCreation=1`.
- Why it exists: Reduces legacy short-name abuse opportunities.

### 12g. Remove “Run As Different User” Context Entry
- What it does: Applies suppression policy for runasuser shell entries on key file classes.
- Why it exists: Reduces alternate-credential launch abuse from Explorer.

### 12h. Explorer Hardening
- What it does: Enables heap corruption termination, hardens shell protocol behavior, enables protection mode for system objects.
- Why it exists: Improves shell/process robustness and object protection.

### 12i. Clear Remote Registry Allowed Paths
- What it does: Clears `winreg` allowed exact/allowed path lists.
- Why it exists: Reduces remote registry access scope.

### 12j. Disable RunOnce Processing
- What it does: Sets `DisableLocalMachineRunOnce=1` across HKLM/HKCU (including Wow6432Node paths).
- Why it exists: Reduces one-shot run-key persistence execution.

### 12k. Reset Service Control Manager SDDL
- What it does: Resets SCM security descriptor to a hardened default.
- Why it exists: Re-baselines SCM access control to reduce service-control abuse.

### 12l. Enable SEHOP
- What it does: Sets `DisableExceptionChainValidation=0`.
- Why it exists: Enables structured exception overwrite protection.

### 12m. Early Launch Antimalware Policy
- What it does: Sets `DriverLoadPolicy=3`.
- Why it exists: Ensures ELAM boot-time driver vetting behavior.

### 12n. Block PsExec via IFEO
- What it does: Sets IFEO debugger for `PSEXESVC.exe` to `svchost.exe`.
- Why it exists: Disrupts standard PsExec service execution path.
- Note: Uses IFEO redirect rather than service/firewall-only blocking.

### 12o. Disable Offline Files
- What it does: Disables `CSC` service startup.
- Why it exists: Reduces cached-offline data and sync abuse surface.

### 12p. Disable UPnP
- What it does: Sets UPnP mode policy to disabled state.
- Why it exists: Reduces automatic network service discovery/exposure.

### 12q. Disable DCOM
- What it does: Sets `EnableDCOM="N"`.
- Why it exists: Reduces COM/RPC remote activation surface.

### 12r. Ease-of-Access Registry Hardening
- What it does: Hardens StickyKeys/ToggleKeys/Keyboard Response flags and related logon UI settings.
- Why it exists: Reduces abuse of ease-of-access and logon UI behaviors.

### 13. Spectre/Meltdown/MDS Mitigations
- What it does: Sets memory-management mitigation keys and VM mitigation baseline version.
- Why it exists: Enables CPU-side speculative execution mitigation policies.

### 13 (final). PowerShell Constrained Language Mode
- What it does: Sets machine environment variable `__PSLockdownPolicy=4`.
- Why it exists: Restricts PowerShell language capabilities in new sessions.
- Note: Uses environment-level enforcement instead of per-session script logic.
