# 13 Post Analysis Module

## High-Level Summary
This module runs post-hardening assessment tooling on Domain Controllers to identify remaining AD, ADCS, and privilege-path risk. It is evidence-focused: it gathers findings and reports for operator follow-up rather than directly enforcing hardening settings.

## Controls

### 1. Domain Controller Scope Gate
- What it does: Exits immediately when the host is not a Domain Controller.
- Why it exists: Keeps AD-specific analysis tooling from running on non-DC systems.
- Note: Full module hard-stop at the top, so all later controls are skipped on non-DC machines.

### 2. Locksmith ADCS Scan (Mode 4)
- What it does: Runs `Invoke-Locksmith.ps1 -Mode 4` when available.
- Why it exists: Detects AD CS misconfigurations and abuse paths.
- Note: Honors the global `$SkipLocksmith` flag (set by earlier CA decisions) and checks two possible Locksmith paths before skipping.

### 3. Certify Vulnerable Template Check
- What it does: Executes `certify.exe find /vulnerable` and logs the output.
- Why it exists: Identifies vulnerable certificate templates that can enable privilege escalation.
- Note: Stores full tool output in module logs and explicitly warns the operator to review findings.

### 4. PingCastle Healthcheck
- What it does: Runs `PingCastle.exe --healthcheck` (with local server target when available) and stores reports under `reports/PingCastle`.
- Why it exists: Produces a broad AD security posture report after hardening.
- Note: If PingCastle drops reports outside the target folder, the module searches fallback directories and moves discovered report files into the expected report directory.

### 5. SharpHound (BloodHound) Collection
- What it does: Runs `SharpHound.exe -c All` and writes a zipped collection to `reports/BloodHound`.
- Why it exists: Captures graph data to analyze privilege relationships and potential attack paths.
- Note: Uses `Start-Process` in hidden mode with wait/exit-code handling for controlled execution and logging.


