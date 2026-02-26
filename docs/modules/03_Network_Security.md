# 03 Network Security Module

## High-Level Summary
This module hardens host and domain network attack surface across SMB, name resolution, NTLM/LSA, RPC, TLS/SChannel, and DNS. It applies broad baseline controls on all machines, adds deeper LDAP/DNS/Netlogon protections on DCs, and uses targeted interactive prompts where compatibility breakage is likely.

## Controls

### 1. Disable SMBv1
- What it does: Disables SMBv1 server/client paths via SMB cmdlets or registry, DISM feature disable, and service/driver startup changes.
- Why it exists: Removes legacy SMBv1 remote-exploit and relay exposure.
- Note: Uses multiple enforcement paths (cmdlet + DISM + service config) for resiliency.

### 2. SMB Hardening Baseline
- What it does: Enables SMBv2, disables compression, enables signing, restricts null sessions, disables admin auto-shares, disables plaintext/insecure guest auth, hides server browse visibility, and enables SMBv1 access auditing.
- Why it exists: Reduces SMB relay, null session abuse, downgrade, and data exposure risk.

### 2a. Optional SMB Signing Enforcement
- What it does: Prompts to require SMB signing (`RequireSecuritySignature`).
- Why it exists: Stronger MITM/relay resistance.
- Note: Explicit compatibility prompt for legacy clients/devices.

### 2b. Optional SMB Encryption
- What it does: Prompts to enable SMB encryption (`EncryptData`) with compatibility fallback (`RejectUnencryptedAccess=false`).
- Why it exists: Encrypts SMB traffic in transit while minimizing immediate legacy breakage.
- Note: Security/compatibility hybrid posture instead of strict reject mode.

### 2c. DC Optional Hardened UNC Paths
- What it does: Optionally sets hardened UNC requirements for `\\*\NETLOGON` and `\\*\SYSVOL`.
- Why it exists: Protects core AD path access from downgrade/MITM conditions.

### 3. Disable LLMNR
- What it does: Sets DNSClient multicast resolution off.
- Why it exists: Reduces name-poisoning credential capture opportunities.

### 4. Disable NetBIOS over TCP/IP
- What it does: Disables NetBIOS per-interface, sets P-node behavior, and disables name-release abuse path.
- Why it exists: Shrinks legacy name-service attack surface.

### 5. Disable mDNS
- What it does: Disables mDNS at DNS cache parameters.
- Why it exists: Reduces multicast name spoofing exposure.

### 6. IPv6 Handling (Prompted)
- What it does: Lets operator choose full IPv6 disable, tunnel-only disable (ISATAP/Teredo/6to4), or no change.
- Why it exists: Balances hardening with scoring/operational IPv6 dependencies.
- Note: Tunnel-only mode preserves native IPv6 while removing common transition-protocol risk.

### 7. NTLM Hardening
- What it does: Enforces NTLMv2 baseline, disables LM hash storage, enables machine ID use, and blocks null-session fallback.
- Why it exists: Reduces credential downgrade and weak-auth abuse.

### 7a. Strict NTLM Minimum Security (Optional)
- What it does: Optional enforcement of 128-bit NTLM minimum client/server security.
- Why it exists: Hardens legacy-compatible NTLM posture when environment supports it.

### 8. LSA Hardening
- What it does: Restricts anonymous access, applies remote SAM SDDL restriction, disables submit control, and sets token leak delay behavior.
- Why it exists: Reduces credential and identity policy abuse paths.
- Note: Uses explicit `RestrictRemoteSAM` SDDL string and includes DC-only `DisableDomainCreds`.

### 9. DNS Client Hardening
- What it does: Disables Smart Name Resolution and parallel A/AAAA behavior; flushes resolver cache.
- Why it exists: Reduces spoof/race-based name resolution abuse.

### 9a. WPAD Mitigation
- What it does: Disables WPAD/auto-detect in machine and user proxy settings.
- Why it exists: Blocks common proxy auto-discovery hijack path.

### 9b. RPC Hardening
- What it does: Restricts remote RPC clients, requires authenticated endpoint resolution, and disables select remote RPC endpoints (schedule/SCM related).
- Why it exists: Reduces remote RPC abuse surface.

### 9c. DNS-over-HTTPS
- What it does: Enables automatic DoH behavior in DNS cache service.
- Why it exists: Improves DNS transport privacy/integrity where supported.

### 9d. TCP/IP Stack Hardening
- What it does: Disables source routing, redirects, router discovery, IGMP, dead gateway detection; enables SYN protections and disables dial-up password saving.
- Why it exists: Reduces network-level spoofing and stack abuse vectors.

### 9e. BITS Limiting
- What it does: Applies BITS policy values to constrain transfer behavior.
- Why it exists: Reduces abuse of BITS as stealth transfer channel.

### 9f. Credential Delegation / Remote Credential Guard
- What it does: Enables protected credential delegation settings and Restricted Admin-related controls.
- Why it exists: Limits credential exposure in remote administration workflows.

### 9g. SChannel/TLS Hardening
- What it does: Enables AES ciphers and SHA256+ hashes, disables legacy ciphers/protocols (SSL, TLS 1.0/1.1), enforces TLS 1.2, and sets a curated cipher suite order.
- Why it exists: Removes weak cryptography and downgrade-prone TLS settings.
- Note: Full registry-level SChannel profile rather than minimal toggles.

### 10. Disable TCP Timestamps
- What it does: Disables TCP timestamps via `netsh`.
- Why it exists: Reduces passive fingerprinting and uptime leakage.

### DC-Only: 10. LDAP & Kerberos Hardening
- What it does: Enforces LDAP client/server signing, sets Kerberos encryption types and TGT renewal limit, optionally enforces LDAP channel binding, and disables anonymous LDAP via `dsHeuristics`.
- Why it exists: Hardens DC auth protocols against relay/downgrade/anonymous access.
- Note: Direct `dsHeuristics` character manipulation for anonymous LDAP control.

### DC-Only: 11. DNS Server Security
- What it does: Applies SIGRed-related packet controls, enables global query block list, attempts RRL, enforces socket pool and cache locking.
- Why it exists: Reduces DNS abuse, cache poisoning, and reflection risk.

### DC-Only: 11.1 Advanced DNS Hardening
- What it does: Optional recursion disable, diagnostics tuning, cache TTL controls, secure zone update/transfer policies, scavenging interval, and additional `dnscmd` hardening flags; warns on `ServerLevelPluginDll`.
- Why it exists: Enforces safer authoritative DNS posture and highlights plugin-based persistence risk.
- Note: Zone hardening targets primary non-auto-created zones only to avoid over-touching system zones.

### DC-Only: 12. Zerologon / Netlogon Hardening
- What it does: Enables full secure channel protection, removes vulnerable allowlist if present, and enforces sign/seal/strong key requirements.
- Why it exists: Mitigates secure-channel downgrade and Zerologon-class weaknesses.

### DC-Only: 12a. noPac Mitigation
- What it does: Sets `ms-DS-MachineAccountQuota` to `0` at domain level.
- Why it exists: Reduces machine-account spoofing/escalation paths.

### DC-Only: 13. Time Synchronization
- What it does: Sets timezone to UTC and forces time resync.
- Why it exists: Maintains Kerberos time integrity.

### All Machines: Interactive SMB Share Management
- What it does: Offers share enumeration/removal workflow or full SMB server disable; supports per-share removal with extra confirmation for critical shares (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`).
- Why it exists: Lets operators quickly cut unnecessary share exposure while preserving critical infrastructure intentionally.
- Note: Safety gate specifically for critical system/AD shares before deletion.
