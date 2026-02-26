# 07 Firewall Hardening Module

## High-Level Summary
This module establishes a default-deny firewall posture, enforces profile/logging baselines, scopes rules to operator-defined trusted networks, applies core outbound and DC service rules, blocks outbound LOLBin traffic, and optionally generates dynamic rules from bundled Nmap discovery.

## Controls

### 1. Ensure Firewall Service Is Running
- What it does: Starts `mpssvc` (Windows Firewall service).
- Why it exists: Ensures firewall policy can be enforced.

### 2. Enable All Firewall Profiles
- What it does: Enables Domain/Private/Public profiles via `Set-NetFirewallProfile` and policy registry keys.
- Why it exists: Prevents profile-level firewall bypass.
- Note: Enforces both runtime profile state and policy keys to resist local disablement.

### 3. Default Inbound/Outbound Policy
- What it does: Forces inbound default to `Block`; prompts whether outbound default should be `Block` or `Allow`.
- Why it exists: Establishes least-privilege network behavior with explicit operator control over strictness.

### 4. Firewall Logging Baseline
- What it does: Enables allowed/blocked logging on all profiles, sets 16MB max log size, and standard firewall log path.
- Why it exists: Improves network event visibility for detection and triage.

### 5. Disable Multicast/Broadcast Response
- What it does: Disables multicast/broadcast response through `netsh advfirewall`.
- Why it exists: Reduces noisy discovery surface.

### 6. Trusted Network Scoping
- What it does: Prompts for trusted subnets (or Any), confirms input, and applies that scope to later inbound rules.
- Why it exists: Limits inbound exposure to intended network ranges.
- Note: Interactive confirmation loop prevents accidental subnet mis-entry.

### 7. Common Allow Rules (Baseline Outbound)
- What it does: Adds outbound allows for DNS (TCP/UDP 53), HTTP/HTTPS (80/443), Kerberos (TCP/UDP 88), LDAP (TCP 389), and NTP (UDP 123).
- Why it exists: Preserves core system/domain functionality under stricter firewall defaults.

### DC-Only Core AD Service Rules
- What it does: Adds explicit inbound DC rules for DNS, Kerberos, LDAP, RPC mapper, and W32Time (plus RPC outbound mapper).
- Why it exists: Maintains essential DC authentication/directory service paths.

### DC-Only Optional Rule Sets (Prompted)
- What it does:
  - Optionally enables built-in AD DS firewall rule group.
  - Optionally enables SMB/NetBIOS inbound (`445/139/138`).
  - Optionally enables Global Catalog + ADWS inbound (`3268/3269/9389`).
- Why it exists: Avoids opening non-scored/non-required DC ports by default.
- Note: Includes inline impact notes before each decision point.

### 8. Role-Specific Rules (Prompted)
- What it does: Operator-selectable inbound rules for IIS, DNS server, SMTP, FTP, WinRM, SMB server, plus optional Ping, RDP, and SMB outbound.
- Why it exists: Keeps non-essential service exposure opt-in and role-driven.
- Note: Uses a compact numeric menu with explicit skip option and impact guidance.

### 9. Outbound LOLBin Blocking
- What it does: Adds outbound block rules for a broad legacy LOLBin list across `System32`/`SysWOW64`, plus additional paths (Office `AppVLP.exe`, `wmic`, `rpcping`, `PSEXESVC`, PowerShell, `cmd`, `MSBuild`).
- Why it exists: Reduces abuse of trusted binaries for command-and-control/exfiltration.
- Note: Mirrors and modernizes a legacy LOLBin block set, using a path-driven target array and idempotent helper-based rule creation.

### 10. Dynamic Rule Discovery via Nmap (Optional)
- What it does: Optionally launches bundled Nmap scan and later processes XML results into firewall rules.
- Why it exists: Adds environment-specific allow rules based on discovered services instead of static assumptions.
- Note: Controller-aware flow; if scan was started by `Start-Hardening.ps1`, this module reuses global scan state instead of re-running.
