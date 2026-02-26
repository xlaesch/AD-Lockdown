# 12 Windows Updates Module

## High-Level Summary
This module restores and hardens Windows Update behavior by re-enabling update services, removing common policy-based blockers, disabling update deferrals, enabling recommended updates, and optionally triggering an immediate scan without forced reboot.

## Controls

### 1. Enable Windows Update Service
- What it does: Sets `wuauserv` startup type to `Automatic` and starts the service.
- Why it exists: Ensures update infrastructure is running.

### 2. Remove Windows Update Blockers
- What it does: Clears policy/registry settings that disable update access and configures automatic install behavior (`AUOptions=4`).
- Why it exists: Reverses local/policy tampering that prevents patching.
- Note: Cleans multiple HKLM/HKCU blocker paths, not just standard WindowsUpdate policy keys.

### 3. Clear Update Deferral Policies
- What it does: Sets `DeferFeatureUpdates=0` and `DeferQualityUpdates=0`.
- Why it exists: Prevents prolonged postponement of security updates.

### 4. Include Recommended Updates
- What it does: Enables `IncludeRecommendedUpdates`.
- Why it exists: Expands update coverage beyond strictly critical channels.

### 5. Optional Immediate Update Scan
- What it does: Prompts operator to trigger scan now; uses `UsoClient StartScan` when available, otherwise falls back to `wuauclt /detectnow /updatenow`.
- Why it exists: Allows immediate patch discovery while retaining operator timing control.
- Note: Dual scan-trigger path for compatibility across Windows versions.
