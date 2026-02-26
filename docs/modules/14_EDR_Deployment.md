# 14 EDR Deployment Module

## High-Level Summary
This module deploys and verifies local endpoint detection coverage using Sysmon for telemetry and BLUESPAWN for active monitoring. It is designed to use pre-staged binaries in the local `tools` folder and safely skip components that are missing or already running.

## Controls

### 1. Sysmon Install or Configuration Update
- What it does: Finds `Sysmon64.exe` (preferred) or `Sysmon.exe` in `tools`, installs if absent, or updates configuration if already installed.
- Why it exists: Ensures kernel-level endpoint telemetry is active for post-hardening monitoring and investigation.
- Note: Uses `sysmonconfig.xml` when present; otherwise installs with default configuration.

### 2. Sysmon Service Health Verification
- What it does: Verifies Sysmon service state after install/update and attempts to start it if present but not running.
- Why it exists: Confirms telemetry is actually operational, not just installed.
- Note: Checks service naming for both `Sysmon64` and `Sysmon`.

### 3. BLUESPAWN Monitor Launch
- What it does: Starts `BLUESPAWN-client-x64.exe` in `--monitor` mode with daily log output under `logs`.
- Why it exists: Adds continuous userland threat monitoring and detection activity.
- Note: If BLUESPAWN is already running, launch is skipped to avoid duplicate processes.

### 4. Deployment Status Summary
- What it does: Logs final active/warning state for Sysmon and BLUESPAWN at the end of the module.
- Why it exists: Gives operators a quick operational check without manually validating services/processes.
- Note: Summary includes process IDs and expected log location when available.
