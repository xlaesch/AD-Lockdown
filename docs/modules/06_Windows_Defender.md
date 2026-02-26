# 06 Windows Defender Module

## High-Level Summary
This module re-enables and hardens Microsoft Defender end-to-end: real-time/behavior protections, cloud and exploit protections, ASR rules, exclusion hygiene, and signature updates. It combines policy-level registry enforcement with Defender cmdlet settings to resist local tampering and weak default configurations.

## Controls

### 1. Ensure Defender Is Enabled and Active
- What it does: Clears policy keys that disable Defender/real-time monitoring, forces non-passive mode, starts `WinDefend`, and enables Defender sandboxing.
- Why it exists: Restores active antimalware protection if it was disabled or downgraded.
- Note: Uses `setx /M MP_FORCE_USE_SANDBOX 1` to persist sandbox mode at the machine environment level.

### 2. Exclusion Review and Cleanup (Prompted)
- What it does: Enumerates path/process/extension exclusions (and IP exclusions if present), then optionally removes all exclusions.
- Why it exists: Eliminates attacker-added blind spots in Defender coverage.
- Note: Interactive review before destructive removal, with support for all four exclusion types.

### 3. Defender Preference Baseline
- What it does: Applies `Set-MpPreference` with broad protection settings (real-time, behavior, script/IOAV/network scanning, PUA enabled, threat actions, scan/update behavior).
- Why it exists: Enforces a high-protection runtime baseline.

### 4. Heuristics and Scan Policy Hardening
- What it does: Enables heuristics, enforces signature checks before scans, and enforces attachment AV scanning policy.
- Why it exists: Improves detection quality and prevents scan execution with stale signatures.

### 4a. Additional Defender Registry Hardening
- What it does: Sets visibility and engine-related policy keys (exclusions visibility, cloud block level, legacy PUP protection key).
- Why it exists: Strengthens Defender engine posture and admin visibility.

### 4b. Exploit Guard Network Protection
- What it does: Enables Defender Exploit Guard network protection policy.
- Why it exists: Blocks outbound connections to known malicious infrastructure based on Defender intelligence.

### 5. Tamper Protection
- What it does: Sets Defender `TamperProtection` feature value.
- Why it exists: Raises resistance to local attempts to disable or weaken Defender controls.

### 6. Competition Telemetry/Sample Submission Mode
- What it does: Disables MAPS reporting/sample submission-related policies and related reporting keys.
- Why it exists: Reduces outbound telemetry/data sharing in competition environments.
- Note: Explicitly includes `DisableBlockAtFirstSeen=1`, trading some cloud-first blocking behavior for privacy/competition constraints.

### 7. Attack Surface Reduction (ASR) Rules
- What it does: Enables a curated set of ASR rules (Office child process/injection controls, script/obfuscation controls, LSASS credential theft block, WMI/PSExec process creation block, ransomware protection, etc.) and removes ASR-only exclusions.
- Why it exists: Reduces common post-exploitation and initial execution techniques.
- Note: Per-rule enable logging with graceful warning-level failure handling so one unsupported rule does not abort the full ASR rollout.

### 8. Signature Update Trigger
- What it does: Triggers Defender signature update via `Update-MpSignature`.
- Why it exists: Ensures detections are based on current intelligence after policy hardening.
