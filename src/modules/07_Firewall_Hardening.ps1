# 07_Firewall_Hardening.ps1
# Handles Windows Firewall configuration, profiles, logging, rules,
# and -- on Domain Controllers -- AD service inbound rules.

param(
    [string]$LogFile,
    [bool]$IsDomainController = $global:IsDomainController
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command Set-RegistryValue -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Set-RegistryValue.ps1"
}

Write-Log -Message "Starting Firewall Hardening..." -Level "INFO" -LogFile $LogFile

# ═════════════════════════════════════════════════════════════════════════════
# ALL MACHINES
# ═════════════════════════════════════════════════════════════════════════════

# --- 1. Ensure Firewall Service is Running ---
Write-Log -Message "Ensuring Windows Firewall service is running..." -Level "INFO" -LogFile $LogFile
try {
    net start mpssvc 2>&1 | Out-Null
    Write-Log -Message "Windows Firewall service running." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to start firewall service: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Enable All Firewall Profiles ---
Write-Log -Message "Enabling all firewall profiles..." -Level "INFO" -LogFile $LogFile
try {
    Set-NetFirewallProfile -Profile Domain -Enabled True
    Set-NetFirewallProfile -Profile Private -Enabled True
    Set-NetFirewallProfile -Profile Public -Enabled True

    # Also enforce via registry (in case GPO or malware disabled via policy)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "EnableFirewall" -Value 1 -Type DWord

    Write-Log -Message "All firewall profiles enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable firewall profiles: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Default Inbound/Outbound Policy ---
Write-Log -Message "Configuring default firewall policy..." -Level "INFO" -LogFile $LogFile
try {
    # Block inbound by default on all profiles
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

    Write-Host ""
    Write-Host "IMPACT: Blocking outbound by default requires explicit ALLOW rules for all outgoing traffic." -ForegroundColor Yellow
    Write-Host "  This is very secure but can break scored services if allow rules are not correctly configured." -ForegroundColor Yellow
    $blockOutbound = Read-Host "Block outbound traffic by default? [y/n]"
    if ($blockOutbound -eq 'y') {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
        Write-Log -Message "Default policy: Block Inbound + Block Outbound." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
        Write-Log -Message "Default policy: Block Inbound + Allow Outbound." -Level "SUCCESS" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to configure firewall policy: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Firewall Logging ---
Write-Log -Message "Enabling firewall logging..." -Level "INFO" -LogFile $LogFile
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -LogBlocked True `
        -LogAllowed True `
        -LogMaxSizeKilobytes 16384 `
        -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Write-Log -Message "Firewall logging enabled on all profiles (16MB max)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable firewall logging: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Disable Multicast/Broadcast Response ---
Write-Log -Message "Disabling multicast/broadcast response..." -Level "INFO" -LogFile $LogFile
try {
    netsh advfirewall firewall set multicastbroadcastresponse mode=disable profile=all 2>&1 | Out-Null
    Write-Log -Message "Multicast/broadcast response disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable multicast response: $_" -Level "WARNING" -LogFile $LogFile
}

# --- 6. Trusted Network Configuration ---
function Get-TrustedNetworkSelection {
    param([string]$LogFile)

    while ($true) {
        $raw = Read-Host "Enter allowed subnets (comma-separated, e.g. 10.0.0.0/8,192.168.1.0/24) or press Enter for Any"

        if ([string]::IsNullOrWhiteSpace($raw)) {
            Write-Log -Message "No subnets provided. Using Any." -Level "INFO" -LogFile $LogFile
            return @{ Addresses = $null; Label = "Any" }
        }

        $rawTrim = $raw.Trim()
        if ($rawTrim -match '^(?i)any$') {
            Write-Log -Message "User selected Any for trusted network." -Level "INFO" -LogFile $LogFile
            return @{ Addresses = $null; Label = "Any" }
        }

        $entries = $rawTrim -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if (-not $entries -or $entries.Count -eq 0) {
            Write-Host "No valid subnets entered. Please try again."
            continue
        }

        Write-Host "Subnets entered: $($entries -join ', ')"
        $confirm = Read-Host "Confirm these subnets? (Y/N)"
        if ($confirm -match '^(?i)y(es)?$') {
            return @{ Addresses = $entries; Label = ($entries -join ", ") }
        }

        Write-Host "Subnets not confirmed. Please re-enter."
    }
}

$trustedSelection = Get-TrustedNetworkSelection -LogFile $LogFile
$TrustedNetwork = $trustedSelection.Addresses
$TrustedNetworkLabel = $trustedSelection.Label
Write-Log -Message "Using Trusted Network: $TrustedNetworkLabel" -Level "INFO" -LogFile $LogFile

# Helper function to add rule safely
function Add-FirewallRule {
    param(
        [string]$DisplayName,
        [string]$Direction,
        [string]$Protocol,
        [string]$LocalPort,
        [string]$RemotePort,
        [string]$RemoteAddress,
        [string]$Program,
        [string]$Service,
        [string]$Action = "Allow"
    )

    try {
        $params = @{
            DisplayName = $DisplayName
            Direction   = $Direction
            Action      = $Action
            Profile     = "Any"
        }
        if ($Protocol) { $params.Add("Protocol", $Protocol) }
        if ($LocalPort) { $params.Add("LocalPort", $LocalPort) }
        if ($RemotePort) { $params.Add("RemotePort", $RemotePort) }
        if ($RemoteAddress) { $params.Add("RemoteAddress", $RemoteAddress) }
        if ($Program) { $params.Add("Program", $Program) }
        if ($Service) { $params.Add("Service", $Service) }

        if (-not (Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule @params | Out-Null
            Write-Log -Message "Added Firewall Rule: $DisplayName" -Level "SUCCESS" -LogFile $LogFile
        } else {
            Write-Log -Message "Firewall Rule already exists: $DisplayName" -Level "INFO" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to add rule '$DisplayName': $_" -Level "ERROR" -LogFile $LogFile
    }
}

# --- 7. Common Allow Rules ---
Write-Log -Message "Applying common allow rules..." -Level "INFO" -LogFile $LogFile

# DNS Outbound (for name resolution)
Add-FirewallRule -DisplayName "Allow DNS Out (UDP)" -Direction "Outbound" -Protocol "UDP" -RemotePort "53"
Add-FirewallRule -DisplayName "Allow DNS Out (TCP)" -Direction "Outbound" -Protocol "TCP" -RemotePort "53"

# HTTP/HTTPS Outbound (for updates)
Add-FirewallRule -DisplayName "Allow HTTP Out" -Direction "Outbound" -Protocol "TCP" -RemotePort "80"
Add-FirewallRule -DisplayName "Allow HTTPS Out" -Direction "Outbound" -Protocol "TCP" -RemotePort "443"

# Kerberos (TCP/UDP 88) - for domain-joined machines
Add-FirewallRule -DisplayName "Allow Kerberos Out (TCP)" -Direction "Outbound" -Protocol "TCP" -RemotePort "88"
Add-FirewallRule -DisplayName "Allow Kerberos Out (UDP)" -Direction "Outbound" -Protocol "UDP" -RemotePort "88"

# LDAP (TCP 389) - for domain-joined machines
Add-FirewallRule -DisplayName "Allow LDAP Out (TCP)" -Direction "Outbound" -Protocol "TCP" -RemotePort "389"

# W32Time (UDP 123)
Add-FirewallRule -DisplayName "Allow NTP Out" -Direction "Outbound" -Protocol "UDP" -RemotePort "123"

# ═════════════════════════════════════════════════════════════════════════════
# DOMAIN CONTROLLER ONLY -- AD Service Inbound Rules
# ═════════════════════════════════════════════════════════════════════════════
if ($IsDomainController) {
    Write-Log -Message "Applying Domain Controller firewall rules..." -Level "INFO" -LogFile $LogFile

    # Optional: built-in AD DS group can be broad; keep opt-in.
    Write-Host ""
    Write-Host "IMPACT NOTE: If AD DS built-in rule group stays disabled, only the explicit DC rules in this script are active." -ForegroundColor Yellow
    Write-Host "  On DCs using additional AD DS ports/rules, some auth/replication workflows may fail." -ForegroundColor Yellow
    $enableAdDsGroup = Read-Host "Enable built-in 'Active Directory Domain Services' firewall rule group? [y/n]"
    if ($enableAdDsGroup -match '^(?i)y(es)?$') {
        try {
            netsh advfirewall firewall set rule group="Active Directory Domain Services" new enable=yes 2>&1 | Out-Null
            Write-Log -Message "Enabled 'Active Directory Domain Services' firewall group." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to enable AD DS firewall group: $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Skipped enabling AD DS built-in firewall group." -Level "INFO" -LogFile $LogFile
    }

    # DNS Server (UDP/TCP 53 inbound)
    Add-FirewallRule -DisplayName "DC DNS In (UDP)" -Direction "Inbound" -Protocol "UDP" -LocalPort "53" -RemoteAddress $TrustedNetwork
    Add-FirewallRule -DisplayName "DC DNS In (TCP)" -Direction "Inbound" -Protocol "TCP" -LocalPort "53" -RemoteAddress $TrustedNetwork

    # Kerberos (TCP/UDP 88 inbound)
    Add-FirewallRule -DisplayName "DC Kerberos TCP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "88" -RemoteAddress $TrustedNetwork
    Add-FirewallRule -DisplayName "DC Kerberos UDP In" -Direction "Inbound" -Protocol "UDP" -LocalPort "88" -RemoteAddress $TrustedNetwork

    # LDAP (TCP/UDP 389 inbound)
    Add-FirewallRule -DisplayName "DC LDAP TCP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "389" -RemoteAddress $TrustedNetwork
    Add-FirewallRule -DisplayName "DC LDAP UDP In" -Direction "Inbound" -Protocol "UDP" -LocalPort "389" -RemoteAddress $TrustedNetwork

    # RPC Endpoint Mapper (TCP 135)
    Add-FirewallRule -DisplayName "DC RPC Map In" -Direction "Inbound" -Protocol "TCP" -LocalPort "135" -RemoteAddress $TrustedNetwork
    Add-FirewallRule -DisplayName "DC RPC Map Out" -Direction "Outbound" -Protocol "TCP" -RemotePort "135" -RemoteAddress $TrustedNetwork

    # W32Time (UDP 123 inbound -- DC is authoritative time source)
    Add-FirewallRule -DisplayName "DC W32Time In" -Direction "Inbound" -Protocol "UDP" -LocalPort "123" -RemoteAddress $TrustedNetwork

    # Optional DC rules that are not always required/scored.
    Write-Host ""
    Write-Host "IMPACT NOTE: If SMB/NetBIOS rules are disabled on DCs that serve SYSVOL/shares or legacy clients," -ForegroundColor Yellow
    Write-Host "  GPO access, share access, and some replication-related workflows can fail." -ForegroundColor Yellow
    $enableDcSmbAndNetbios = Read-Host "Enable DC SMB/NetBIOS inbound rules (445,139,138)? [y/n]"
    if ($enableDcSmbAndNetbios -match '^(?i)y(es)?$') {
        Add-FirewallRule -DisplayName "DC SMB In" -Direction "Inbound" -Protocol "TCP" -LocalPort "445" -RemoteAddress $TrustedNetwork
        Add-FirewallRule -DisplayName "DC NetBIOS Session In" -Direction "Inbound" -Protocol "TCP" -LocalPort "139" -RemoteAddress $TrustedNetwork
        Add-FirewallRule -DisplayName "DC NetBIOS Datagram In" -Direction "Inbound" -Protocol "UDP" -LocalPort "138" -RemoteAddress $TrustedNetwork
        Write-Log -Message "Enabled optional DC SMB/NetBIOS inbound rules." -Level "INFO" -LogFile $LogFile
    } else {
        Write-Log -Message "Skipped optional DC SMB/NetBIOS inbound rules." -Level "INFO" -LogFile $LogFile
    }

    Write-Host ""
    Write-Host "IMPACT NOTE: If GC/ADWS rules are disabled on DCs that are Global Catalogs or used by AD admin tools," -ForegroundColor Yellow
    Write-Host "  forest-wide directory lookups and ADAC/AD PowerShell queries can fail." -ForegroundColor Yellow
    $enableDcGcAndAdws = Read-Host "Enable DC Global Catalog + AD Web Services inbound rules (3268,3269,9389)? [y/n]"
    if ($enableDcGcAndAdws -match '^(?i)y(es)?$') {
        Add-FirewallRule -DisplayName "DC Global Catalog In" -Direction "Inbound" -Protocol "TCP" -LocalPort "3268" -RemoteAddress $TrustedNetwork
        Add-FirewallRule -DisplayName "DC Global Catalog SSL In" -Direction "Inbound" -Protocol "TCP" -LocalPort "3269" -RemoteAddress $TrustedNetwork
        Add-FirewallRule -DisplayName "DC AD Web Services In" -Direction "Inbound" -Protocol "TCP" -LocalPort "9389" -RemoteAddress $TrustedNetwork
        Write-Log -Message "Enabled optional DC GC/ADWS inbound rules." -Level "INFO" -LogFile $LogFile
    } else {
        Write-Log -Message "Skipped optional DC GC/ADWS inbound rules." -Level "INFO" -LogFile $LogFile
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# ALL MACHINES -- Role-Specific & Blocking Rules
# ═════════════════════════════════════════════════════════════════════════════

# --- 8. Role-Specific Rules (Prompted) ---
Write-Log -Message "=== Role-Specific Firewall Rules ===" -Level "INFO" -LogFile $LogFile
Write-Host ""
Write-Host "Select any additional roles/services this machine serves:" -ForegroundColor Cyan
Write-Host "  [1] IIS / Web Server (HTTP 80, HTTPS 443 inbound)"
Write-Host "  [2] DNS Server (UDP/TCP 53 inbound)"
Write-Host "  [3] SMTP / Mail Server (TCP 25, 587, 465 inbound)"
Write-Host "  [4] FTP Server (TCP 21 inbound)"
Write-Host "  [5] WinRM / PS Remoting (TCP 5985, 5986 inbound)"
Write-Host "  [6] SMB File Server (TCP 445 inbound)"
Write-Host "  [7] None / Skip"
Write-Host "  [8] Ping In (ICMPv4 inbound)"
Write-Host "  [9] RDP In (TCP 3389 inbound)"
Write-Host "  [10] SMB Out (TCP 445 outbound)"
Write-Host "Note: If disabled where needed -> Ping monitoring fails, RDP remote admin is blocked, SMB outbound share/GPO access can fail." -ForegroundColor Yellow
$roleInput = Read-Host "Enter selections (comma-separated, e.g. 1,5)"

$roles = $roleInput -split "[,\s]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
if ($roles -contains "7") {
    Write-Log -Message "User selected to skip additional role-specific rules." -Level "INFO" -LogFile $LogFile
    $roles = @()
}

foreach ($role in $roles) {
    switch ($role) {
        "1" {
            Add-FirewallRule -DisplayName "IIS HTTP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "80" -RemoteAddress $TrustedNetwork
            Add-FirewallRule -DisplayName "IIS HTTPS In" -Direction "Inbound" -Protocol "TCP" -LocalPort "443" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added IIS/Web Server firewall rules." -Level "SUCCESS" -LogFile $LogFile
        }
        "2" {
            Add-FirewallRule -DisplayName "DNS In (UDP)" -Direction "Inbound" -Protocol "UDP" -LocalPort "53" -RemoteAddress $TrustedNetwork
            Add-FirewallRule -DisplayName "DNS In (TCP)" -Direction "Inbound" -Protocol "TCP" -LocalPort "53" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added DNS Server firewall rules." -Level "SUCCESS" -LogFile $LogFile
        }
        "3" {
            Add-FirewallRule -DisplayName "SMTP In (25)" -Direction "Inbound" -Protocol "TCP" -LocalPort "25" -RemoteAddress $TrustedNetwork
            Add-FirewallRule -DisplayName "SMTP In (587)" -Direction "Inbound" -Protocol "TCP" -LocalPort "587" -RemoteAddress $TrustedNetwork
            Add-FirewallRule -DisplayName "SMTPS In (465)" -Direction "Inbound" -Protocol "TCP" -LocalPort "465" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added Mail Server firewall rules." -Level "SUCCESS" -LogFile $LogFile
        }
        "4" {
            Add-FirewallRule -DisplayName "FTP In (21)" -Direction "Inbound" -Protocol "TCP" -LocalPort "21" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added FTP Server firewall rules." -Level "SUCCESS" -LogFile $LogFile
        }
        "5" {
            Add-FirewallRule -DisplayName "WinRM HTTP In (5985)" -Direction "Inbound" -Protocol "TCP" -LocalPort "5985" -RemoteAddress $TrustedNetwork
            Add-FirewallRule -DisplayName "WinRM HTTPS In (5986)" -Direction "Inbound" -Protocol "TCP" -LocalPort "5986" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added WinRM/PSRemoting firewall rules." -Level "SUCCESS" -LogFile $LogFile
        }
        "6" {
            Add-FirewallRule -DisplayName "SMB Server In (445)" -Direction "Inbound" -Protocol "TCP" -LocalPort "445" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added SMB File Server inbound rule." -Level "SUCCESS" -LogFile $LogFile
        }
        "8" {
            Add-FirewallRule -DisplayName "Allow Ping In" -Direction "Inbound" -Protocol "ICMPv4" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added Ping inbound rule." -Level "SUCCESS" -LogFile $LogFile
        }
        "9" {
            Add-FirewallRule -DisplayName "Allow RDP In" -Direction "Inbound" -Protocol "TCP" -LocalPort "3389" -RemoteAddress $TrustedNetwork
            Write-Log -Message "Added RDP inbound rule." -Level "SUCCESS" -LogFile $LogFile
        }
        "10" {
            Add-FirewallRule -DisplayName "Allow SMB Out" -Direction "Outbound" -Protocol "TCP" -RemotePort "445"
            Write-Log -Message "Added SMB outbound rule." -Level "SUCCESS" -LogFile $LogFile
        }
    }
}

# --- 9. Block LOLBins Outbound ---
Write-Log -Message "Blocking LOLBin outbound connections..." -Level "INFO" -LogFile $LogFile

$lolbinRuleTargets = @()

# Legacy list from legacy/windows/hehe-osint/firewall.ps1
$pairedLolbins = @(
    "calc.exe",
    "certutil.exe",
    "cmstp.exe",
    "cscript.exe",
    "esentutl.exe",
    "expand.exe",
    "extrac32.exe",
    "findstr.exe",
    "hh.exe",
    "makecab.exe",
    "mshta.exe",
    "msiexec.exe",
    "nltest.exe",
    "notepad.exe",
    "odbcconf.exe",
    "pcalua.exe",
    "regasm.exe",
    "regsvr32.exe",
    "replace.exe",
    "rundll32.exe",
    "runscripthelper.exe",
    "scriptrunner.exe",
    "SyncAppvPublishingServer.exe",
    "wscript.exe"
)

foreach ($lolbin in $pairedLolbins) {
    $lolbinRuleTargets += [pscustomobject]@{
        DisplayName = "Block LOLBin Outbound $lolbin (System32)"
        Program     = Join-Path $env:SystemRoot "System32\$lolbin"
    }
    $lolbinRuleTargets += [pscustomobject]@{
        DisplayName = "Block LOLBin Outbound $lolbin (SysWOW64)"
        Program     = Join-Path $env:SystemRoot "SysWOW64\$lolbin"
    }
}

# Additional legacy paths
if (${env:ProgramFiles(x86)}) {
    $lolbinRuleTargets += [pscustomobject]@{
        DisplayName = "Block LOLBin Outbound AppVLP.exe (ProgramFilesX86)"
        Program     = Join-Path ${env:ProgramFiles(x86)} "Microsoft Office\root\client\AppVLP.exe"
    }
}
if ($env:ProgramFiles) {
    $lolbinRuleTargets += [pscustomobject]@{
        DisplayName = "Block LOLBin Outbound AppVLP.exe (ProgramFiles)"
        Program     = Join-Path $env:ProgramFiles "Microsoft Office\root\client\AppVLP.exe"
    }
}

$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound rpcping.exe (SysWOW64)"
    Program     = Join-Path $env:SystemRoot "SysWOW64\rpcping.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound wmic.exe (System32)"
    Program     = Join-Path $env:SystemRoot "System32\wbem\wmic.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound wmic.exe (SysWOW64)"
    Program     = Join-Path $env:SystemRoot "SysWOW64\wbem\wmic.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound PSEXESVC.exe"
    Program     = Join-Path $env:SystemRoot "PSEXESVC.exe"
}

# Keep existing script engine hardening
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound cmd.exe (System32)"
    Program     = Join-Path $env:SystemRoot "System32\cmd.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound cmd.exe (SysWOW64)"
    Program     = Join-Path $env:SystemRoot "SysWOW64\cmd.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound powershell.exe (System32)"
    Program     = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound powershell.exe (SysWOW64)"
    Program     = Join-Path $env:SystemRoot "SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound powershell_ise.exe (System32)"
    Program     = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell_ise.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound powershell_ise.exe (SysWOW64)"
    Program     = Join-Path $env:SystemRoot "SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound msbuild.exe (Framework)"
    Program     = Join-Path $env:SystemRoot "Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
}
$lolbinRuleTargets += [pscustomobject]@{
    DisplayName = "Block LOLBin Outbound msbuild.exe (Framework64)"
    Program     = Join-Path $env:SystemRoot "Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
}

foreach ($target in $lolbinRuleTargets) {
    Add-FirewallRule -DisplayName $target.DisplayName -Direction "Outbound" -Protocol "TCP" -Program $target.Program -Action "Block"
}

Write-Log -Message "LOLBin outbound blocking complete. Processed $($lolbinRuleTargets.Count) targets." -Level "INFO" -LogFile $LogFile

# --- 10. Dynamic Firewall Rules (Nmap-based Service Discovery) ---
# When run standalone (not via Start-Hardening.ps1), prompt and launch here.
# When run via the controller, the scan is usually already running.
$hasNmapXmlPath = -not [string]::IsNullOrWhiteSpace($global:NmapScanXmlPath)
$hasRunningNmap = $null -ne (Get-Process -Name "nmap" -ErrorAction SilentlyContinue)
$hasNmapXmlFile = $hasNmapXmlPath -and (Test-Path $global:NmapScanXmlPath)

# Clear stale state left in the current PowerShell session.
if ($hasNmapXmlPath -and -not $hasRunningNmap -and -not $hasNmapXmlFile) {
    Write-Log -Message "Stale nmap scan state detected (no running process and XML missing). Resetting nmap scan path." -Level "WARNING" -LogFile $LogFile
    $global:NmapScanXmlPath = $null
    $hasNmapXmlPath = $false
}

if (-not $hasNmapXmlPath -and -not $hasRunningNmap) {
    Write-Host ""
    $runNmap = Read-Host "Run bundled nmap (from tools.zip) for dynamic service discovery? [y/n]"
    if ($runNmap -match '^(?i)y(es)?$') {
        & "$PSScriptRoot/../functions/Start-NmapBackgroundScan.ps1" -LogFile $LogFile
        $global:NmapTrustedNetwork = $TrustedNetwork
    } else {
        Write-Log -Message "User declined nmap dynamic scan." -Level "INFO" -LogFile $LogFile
    }
} else {
    if ($hasRunningNmap -and -not $hasNmapXmlPath) {
        Write-Log -Message "nmap process detected, but no tracked XML path is set. Dynamic rule import will be skipped unless this script launches the scan." -Level "WARNING" -LogFile $LogFile
    }
    $global:NmapTrustedNetwork = $TrustedNetwork
}

Write-Log -Message "Firewall Hardening module complete." -Level "SUCCESS" -LogFile $LogFile

# If running standalone (not via Start-Hardening.ps1), process results now
if ($global:NmapScanXmlPath -and -not $global:StartHardeningController) {
    Write-Log -Message "Processing nmap dynamic firewall rules..." -Level "INFO" -LogFile $LogFile
    try {
        & "$PSScriptRoot/../functions/Invoke-NmapRuleCreator.ps1" `
            -XmlPath $global:NmapScanXmlPath `
            -TrustedNetwork $global:NmapTrustedNetwork `
            -LogFile $LogFile
    } catch {
        Write-Log -Message "Error running Invoke-NmapRuleCreator: $_" -Level "ERROR" -LogFile $LogFile
    }
}
