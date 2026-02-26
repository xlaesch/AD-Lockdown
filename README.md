# Win-Hardening

<!-- Badges -->
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Last Commit](https://img.shields.io/github/last-commit/xlaesch/Win-Hardening)
![Issues](https://img.shields.io/github/issues/xlaesch/Win-Hardening)
![Repo Size](https://img.shields.io/github/repo-size/xlaesch/Win-Hardening)

> A comprehensive Windows hardening automation framework built for the Collegiate Cyber Defense Competition (CCDC). Covers the full stack — OS, network, services, firewall, EDR — with additional Active Directory modules that activate automatically on Domain Controllers.

---

## Overview

Win-Hardening is a PowerShell-based orchestration system that rapidly hardens any Windows machine. It auto-detects whether it's running on a Domain Controller or a standalone workstation/server and applies the appropriate hardening controls — from password policies, firewall rules, and service lockdown on every machine, to GPO management, Kerberos hardening, and ADCS configuration on DCs. The majority of modules apply to all Windows machines; AD-specific logic is layered on top only when a DC is detected.

## Quick Start

```powershell
# Run as Administrator
.\Start-Hardening.ps1          # Interactive module selection
.\Start-Hardening.ps1 -All     # Run all modules automatically
.\Start-Hardening.ps1 -IncludeModule "Network","Firewall"  # Run specific modules
```

## How It Works

### `Start-Hardening.ps1` — The Orchestrator

This is the single entry point that drives everything. When launched it:

1. **Detects the machine role** — Domain Controller vs. member/workstation (via WMI)
2. **Elevates privileges** — Ensures Administrator, optionally escalates to SYSTEM via PsExec
3. **Starts a background Nmap scan** — Service discovery to inform dynamic firewall rules
4. **Presents a module menu** — Pick which hardening modules to run (or use `-All`)
5. **Takes a pre-hardening backup** — Snapshot of GPOs, DNS, firewall, services, etc.
6. **Executes selected modules sequentially** — Each module logs progress and prompts for high-impact changes
7. **Takes a post-hardening backup** — Second snapshot for diffing
8. **Encrypts secrets** — Rotated passwords are AES-encrypted to `/secrets/`
9. **Processes Nmap results** — Converts scan output into targeted firewall rules
10. **Outputs a summary log** — Full session written to `/logs/`

### Modules

Each module is a self-contained script in `src/modules/`. Modules that have DC-specific logic will automatically branch based on the detected machine role.

| # | Module | Scope | What It Does |
|---|--------|-------|-------------|
| 00 | **Password Rotation** | All | Rotates local & domain passwords, creates backup Domain Admin, exports encrypted CSV |
| 01 | **Local Account Policies** | All | Disables Guest, sets password/lockout policy, kills null sessions & credential delegation |
| 02 | **Domain Account Policies** | DC | Nukes & rebuilds GPOs, enforces domain password policy, restricts delegation & Kerberos |
| 03 | **Network Security** | All | Disables SMBv1/LLMNR/NetBIOS/NTLMv1, hardens LDAP/Kerberos, mitigates Zerologon |
| 04 | **Service Hardening** | All | Disables Print Spooler (PrintNightmare), unnecessary services, hardens DSRM/NTDS on DCs |
| 05 | **Audit Logging** | All | Enables LSASS protection, WDigest hardening, advanced audit policies, AD object auditing |
| 06 | **Windows Defender** | All | Enables real-time protection, sandboxing, cloud protection, clears suspicious exclusions |
| 07 | **Firewall Hardening** | All | Enables firewall, block-by-default inbound, DC service rules, dynamic Nmap-based rules |
| 08 | **System Hardening** | All | Mitigates HiveNightmare, closes Sticky Keys backdoor, enforces UAC/DEP/CFG |
| 09 | **RDP Security** | All | Enforces NLA, TLS encryption, session limits (keeps RDP enabled for CCDC access) |
| 10 | **Cert Authority** | DC | Configures/hardens ADCS, removes weak templates, restricts delegation |
| 11 | **Backup Services** | All | Creates restorable snapshots of GPOs, DNS zones, AD (IFM), SYSVOL, firewall rules |
| 12 | **Windows Updates** | All | Enables Windows Update, removes blockers, configures auto-install |
| 13 | **Post-Analysis** | DC | Runs Locksmith, Certify, PingCastle, and SharpHound to verify hardening effectiveness |
| 14 | **EDR Deployment** | All | Deploys Sysmon (kernel monitoring) and BLUESPAWN (threat detection) |

### Helper Functions

Reusable utilities in `src/functions/`:

| Function | Purpose |
|----------|---------|
| `Write-Log` | Color-coded console + file logging |
| `Set-RegistryValue` | Safe registry writes with error handling |
| `New-RandomPassword` | Generates complex 16+ character passwords |
| `Read-ConfirmedPassword` | Interactive password input with confirmation |
| `Protect-SecretsFile` | AES-encrypts sensitive output files |
| `Unprotect-SecretsFile` | Decrypts `.enc` files from `/secrets/` |
| `Start-NmapBackgroundScan` | Launches background service discovery |
| `Invoke-NmapRuleCreator` | Converts Nmap XML into firewall rules |

### Bundled Tools

Extracted from `tools.zip` at runtime:

- **Nmap** — Network scanning and service discovery
- **Sysmon** — Kernel-level system activity monitoring
- **BLUESPAWN** — Active threat hunting and EDR
- **SharpHound** — BloodHound data collection (attack path analysis)
- **PingCastle** — AD security assessment
- **Certify / Locksmith** — ADCS vulnerability scanning
- **PsExec** — SYSTEM privilege escalation
- **Sysinternals suite** — ADExplorer, Autoruns, Process Explorer, TCPView, etc.

## Recovery

```powershell
.\Restore-State.ps1    # Interactive restoration from pre/post hardening backups
.\Decrypt-Secrets.ps1  # Decrypt rotated password files
```

## Project Structure

```
Win-Hardening/
├── Start-Hardening.ps1        # Orchestrator (entry point)
├── Restore-State.ps1          # Backup restoration utility
├── Decrypt-Secrets.ps1        # Secrets decryption utility
├── tools.zip                  # Bundled security tools
├── src/
│   ├── modules/               # 15 hardening modules (00-14)
│   └── functions/             # 8 reusable helper functions
├── docs/modules/              # Per-module documentation
├── logs/                      # Session logs (gitignored)
├── secrets/                   # Encrypted credentials (gitignored)
├── reports/                   # Post-analysis output (gitignored)
└── tools/                     # Extracted binaries (gitignored)
```

