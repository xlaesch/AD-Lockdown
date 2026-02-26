# 04 Service Hardening Module

## High-Level Summary
This module reduces service-based attack surface by disabling high-risk legacy services/features, hardening remote management behavior, and applying DC-specific protections around AD data paths and LDAP/DSRM behavior. It uses interactive prompts where disabling a service can break operations.

## Controls

### 1. Print Spooler Control (PrintNightmare)
- What it does: On DCs, force-disables `Spooler`; on non-DCs, prompts whether to disable it.
- Why it exists: Reduces remote code execution and privilege escalation exposure from print spooler attack paths.
- Note: If non-DC operator keeps spooler enabled, the script still applies driver-install restriction (`AddPrinterDrivers=1`) as a fallback hardening layer.

### 1a. Print Spooler CVE Mitigations
- What it does: Applies registry controls for PrintNightmare and related print stack vulnerabilities (RPC privacy, Point and Print restrictions, HTTP print controls).
- Why it exists: Reduces known print subsystem exploitation paths.

### 1b. PetitPotam Mitigation
- What it does: Sets `DisableEncryptedEfsRpc=1` under LanmanServer parameters.
- Why it exists: Reduces NTLM relay/coercion abuse via EFSRPC trigger paths.

### 2. Disable Remote Registry
- What it does: Stops and disables `RemoteRegistry`.
- Why it exists: Removes remote registry tampering surface.

### 3. WinRM / PowerShell Remoting Mode (Prompted)
- What it does: Lets operator fully disable WinRM/PSRemoting or keep it enabled in hardened mode.
- Why it exists: Balances remote-management needs against remoting abuse risk.
- Note:
  - Disable path also removes WSMan listeners and sets `LocalAccountTokenFilterPolicy=0`.
  - Enabled path forces `AllowUnencryptedTraffic=0` for both WinRM service and client policy.

### 4. Disable Telnet
- What it does: Disables Telnet client and server features via DISM.
- Why it exists: Removes plaintext remote shell capability.

### 5. Disable TFTP
- What it does: Disables TFTP feature via DISM.
- Why it exists: Removes unauthenticated/weak file transfer surface.

### 6. Remove PowerShell v2 Engine
- What it does: Disables PowerShell v2 optional features.
- Why it exists: Prevents downgrade to older PowerShell engine frequently used to bypass modern logging/security controls.

### 7. Disable Non-Essential Services
- What it does: Stops/disables selected services (Xbox services, maps broker, geolocation, ICS, WMP sharing, telemetry).
- Why it exists: Reduces unnecessary background service exposure and lateral movement opportunities.

### 8. Optional OpenSSH Removal
- What it does: Detects OpenSSH server/client capabilities and prompts for removal.
- Why it exists: Eliminates additional remote access channels if not required.
- Note: Handles server and client capability packages independently instead of blanket removal.

### DC-Only: 9. DSRM Logon Behavior
- What it does: Sets `DsrmAdminLogonBehavior=1`.
- Why it exists: Restricts DSRM admin logon behavior to safer operational conditions.

### DC-Only: 10. NTDS File Permission Hardening
- What it does: Locates NTDS database/log paths from registry and applies ACL changes.
- Why it exists: Protects AD database/log files from unauthorized read/write.
- Note: Breaks inheritance and explicitly grants full control to `Builtin Administrators` and `SYSTEM` on NTDS database/log folders.

### DC-Only: 11. LDAP Connection Idle Limit
- What it does: Updates `Default Query Policy` `lDAPAdminLimits` to set `MaxConnIdleTime=180`.
- Why it exists: Limits long-lived idle LDAP connections and associated resource/security risk.

### DC-Only: 12. Delete VSS Shadow Copies
- What it does: Runs `vssadmin delete shadows /all /quiet`.
- Why it exists: Reduces offline extraction opportunities for sensitive AD data (for example `NTDS.dit`) from shadow copies.

### Final (All Machines): Ensure RDP Service Availability
- What it does: Sets `fDenyTSConnections=0`, ensures `TermService` startup is `Automatic`, and starts it if needed.
- Why it exists: Preserves remote administrative access/incident response capability after other hardening steps.
- Note: This module intentionally combines aggressive service lockdown with a final availability safeguard for RDP.
