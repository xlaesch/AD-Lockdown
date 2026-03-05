# Win-Hardening

<!-- Badges -->
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Last Commit](https://img.shields.io/github/last-commit/xlaesch/Win-Hardening)
![Issues](https://img.shields.io/github/issues/xlaesch/Win-Hardening)
![Repo Size](https://img.shields.io/github/repo-size/xlaesch/Win-Hardening)

> A Windows hardening automation framework built for the Collegiate Cyber Defense Competition (CCDC). Covers the full stack — OS, network, services, firewall, EDR — with additional Active Directory modules that activate automatically on Domain Controllers.

![CLI Screenshot](docs/cli.png)

---

## Quick Start

```powershell
# Run as Administrator
.\Start-Hardening.ps1          # Interactive module selection
.\Start-Hardening.ps1 -All     # Run all modules automatically
.\Start-Hardening.ps1 -IncludeModule "Network","Firewall"  # Run specific modules
```

## Recovery

```powershell
.\Restore-State.ps1    # Interactive restoration from pre/post hardening backups
.\Decrypt-Secrets.ps1  # Decrypt rotated password files
```
