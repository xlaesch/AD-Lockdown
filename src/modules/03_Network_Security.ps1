# 03_Network_Security.ps1
# Handles network-level hardening: SMB, LLMNR, NetBIOS, IPv6, NTLM, LSA,
# DNS, and -- on Domain Controllers -- LDAP/Kerberos, Zerologon, AD firewall
# rules, DNS server security, and time synchronization.

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

Write-Log -Message "Starting Network Security Hardening..." -Level "INFO" -LogFile $LogFile

# ═════════════════════════════════════════════════════════════════════════════
# ALL MACHINES
# ═════════════════════════════════════════════════════════════════════════════

# --- 1. Disable SMBv1 ---
Write-Log -Message "Disabling SMBv1 Protocol..." -Level "INFO" -LogFile $LogFile
try {
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop
        Write-Log -Message "SMBv1 disabled via Set-SmbServerConfiguration." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force
        Write-Log -Message "SMBv1 disabled via Registry." -Level "SUCCESS" -LogFile $LogFile
    }
    # Also disable via DISM
    dism /online /disable-feature /featurename:"SMB1Protocol" /NoRestart 2>&1 | Out-Null
    # Disable SMBv1 client driver
    sc.exe config mrxsmb10 start= disabled 2>&1 | Out-Null
    sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi 2>&1 | Out-Null
} catch {
    Write-Log -Message "Failed to disable SMBv1: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. SMB Hardening ---
Write-Log -Message "Applying SMB Hardening..." -Level "INFO" -LogFile $LogFile
try {
    # Ensure SMBv2 is enabled
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Disable SMB Compression (SMBGhost CVE-2020-0796)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1 -Type DWord

    # Enable SMB Signing (Server & Workstation)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord

    Write-Host "IMPACT: Requiring SMB Signing breaks access for legacy clients (WinXP/2003, old printers/scanners)." -ForegroundColor Yellow
    $smbSign = Read-Host "Require SMB signing? May break legacy clients [y/n]"
    if ($smbSign -eq 'y') {
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
        Write-Log -Message "SMB signing set to 'Required'." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "SMB signing enabled but not required (compatibility mode)." -Level "WARNING" -LogFile $LogFile
    }

    # Restrict Null Session Access
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value ([string[]]@()) -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value ([string[]]@()) -Force

    # Disable SMB Admin Shares
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Type DWord

    # Disable sending unencrypted passwords to third-party SMB servers
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0 -Type DWord
    # Disable insecure guest authentication
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord
    # Hide computer from browse list
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\Lanmanserver\Parameters" -Name "Hidden" -Value 1 -Type DWord
    # Enable SMBv1 access auditing
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -AuditSmb1Access $true -Force -Confirm:$false -ErrorAction SilentlyContinue
    }

    # SMB Encryption
    Write-Host ""
    Write-Host "IMPACT: Enabling SMB Encryption encrypts all file share traffic in transit." -ForegroundColor Yellow
    Write-Host "  Clients that do not support SMB 3.0 encryption (pre-Win8/2012) will be unable to connect." -ForegroundColor Yellow
    Write-Host "  RejectUnencryptedAccess is set to false to allow fallback for legacy clients." -ForegroundColor Yellow
    $smbEncrypt = Read-Host "Enable SMB Encryption? May break pre-Win8/2012 clients [y/n]"
    if ($smbEncrypt -eq 'y') {
        if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            Set-SmbServerConfiguration -EncryptData $true -RejectUnencryptedAccess $false -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Log -Message "SMB encryption enabled (RejectUnencryptedAccess=false for compatibility)." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "SMB encryption skipped for compatibility." -Level "WARNING" -LogFile $LogFile
    }

    Write-Log -Message "SMB hardening applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply SMB hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# DC-only: Hardened UNC Paths (MS15-011 / MS15-014)
if ($IsDomainController) {
    Write-Host "IMPACT: Hardened UNC Paths can prevent Group Policy processing on clients that can't perform mutual authentication." -ForegroundColor Yellow
    $uncPaths = Read-Host "Enable Hardened UNC Paths for SYSVOL/NETLOGON? [y/n]"
    if ($uncPaths -eq 'y') {
        try {
            $hardenedPathsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
            if (-not (Test-Path $hardenedPathsKey)) { New-Item -Path $hardenedPathsKey -Force | Out-Null }
            Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force
            Set-ItemProperty -Path $hardenedPathsKey -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force
            Write-Log -Message "Hardened UNC paths applied for SYSVOL/NETLOGON." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to apply hardened UNC paths: $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Skipping hardened UNC paths." -Level "WARNING" -LogFile $LogFile
    }
}

# --- 3. Disable LLMNR ---
Write-Log -Message "Disabling LLMNR..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Log -Message "LLMNR disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable LLMNR: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Disable NetBIOS over TCP/IP ---
Write-Log -Message "Disabling NetBIOS over TCP/IP..." -Level "INFO" -LogFile $LogFile
try {
    $regkey = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    if (Test-Path $regkey) {
        Get-ChildItem $regkey | ForEach-Object {
            Set-ItemProperty -Path "$($_.PSPath)" -Name "NetbiosOptions" -Value 2 -Force
        }
    }
    # Global NetBIOS broadcast-based name resolution disable (P-node)
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord
    # Ignore NetBIOS name release requests except from WINS servers
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord
    Write-Log -Message "NetBIOS over TCP/IP disabled on all interfaces (NodeType=P-node)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable NetBIOS: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Disable mDNS ---
Write-Log -Message "Disabling mDNS..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Value 0 -Type DWord
    Write-Log -Message "mDNS disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable mDNS: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 6. IPv6 Configuration (Prompted) ---
Write-Log -Message "=== IPv6 Configuration ===" -Level "INFO" -LogFile $LogFile
Write-Host ""
Write-Host "CAUTION: Disabling IPv6 may affect scoring if IPv6 services are being monitored." -ForegroundColor Red
Write-Host "  [1] Disable IPv6 entirely" -ForegroundColor Yellow
Write-Host "  [2] Disable IPv6 tunnel interfaces only (ISATAP, Teredo, 6to4)" -ForegroundColor Yellow
Write-Host "  [3] Skip - leave IPv6 as-is" -ForegroundColor Yellow
$ipv6Choice = Read-Host "IPv6 configuration [1/2/3]"

switch ($ipv6Choice) {
    "1" {
        Write-Log -Message "Disabling IPv6 entirely..." -Level "WARNING" -LogFile $LogFile
        try {
            Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF -Type DWord
            Write-Log -Message "IPv6 disabled entirely (requires reboot)." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to disable IPv6: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    "2" {
        Write-Log -Message "Disabling IPv6 tunnel interfaces only..." -Level "INFO" -LogFile $LogFile
        try {
            Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0x01 -Type DWord
            netsh interface teredo set state disabled 2>&1 | Out-Null
            netsh interface isatap set state disabled 2>&1 | Out-Null
            netsh interface 6to4 set state disabled 2>&1 | Out-Null
            Write-Log -Message "IPv6 tunnel interfaces disabled, native IPv6 preserved." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to disable IPv6 tunnels: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    default {
        Write-Log -Message "Skipping IPv6 configuration per user request." -Level "INFO" -LogFile $LogFile
    }
}

# --- 7. NTLM Hardening ---
Write-Log -Message "Configuring NTLM security..." -Level "INFO" -LogFile $LogFile
try {
    # Enforce NTLMv2 (Level 5 = Send NTLMv2, refuse LM & NTLM)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord
    # Disable LM Hash storage
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord
    # Allow Local System to use machine identity for NTLM
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1 -Type DWord
    # Prevent null session fallback
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "allownullsessionfallback" -Value 0 -Type DWord
    Write-Log -Message "NTLMv2-only enforced (refuse LM/NTLM), LM hash storage disabled." -Level "SUCCESS" -LogFile $LogFile

    Write-Host "IMPACT: Requiring NTLMv2+128bit breaks authentication for very old devices (pre-Win7, old NAS/printers)." -ForegroundColor Yellow
    $ntlmStrict = Read-Host "Enforce strict NTLM minimum security (NTLMv2 + 128-bit)? [y/n]"
    if ($ntlmStrict -eq 'y') {
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -Type DWord
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord
        Write-Log -Message "Strict NTLM minimum security enforced." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "Strict NTLM minimum security skipped for compatibility." -Level "WARNING" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to configure NTLM security: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 8. LSA Hardening ---
Write-Log -Message "Applying LSA hardening..." -Level "INFO" -LogFile $LogFile
try {
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-RegistryValue -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord
    Set-RegistryValue -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
    Set-RegistryValue -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
    # Disable submit control (prevent credential submission)
    Set-RegistryValue -Path $lsaPath -Name "SubmitControl" -Value 0 -Type DWord
    # Set token leak detection delay (clear credentials from memory after 30 sec)
    Set-RegistryValue -Path $lsaPath -Name "TokenLeakDetectDelaySecs" -Value 30 -Type DWord
    # Restrict remote calls to SAM to Administrators only
    Set-RegistryValue -Path $lsaPath -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type String
    Write-Log -Message "LSA hardening applied (anonymous access, remote SAM, token leak)." -Level "SUCCESS" -LogFile $LogFile

    # DC-only: Disable storing domain credentials in memory
    if ($IsDomainController) {
        Set-RegistryValue -Path $lsaPath -Name "DisableDomainCreds" -Value 1 -Type DWord
        Write-Log -Message "Domain credential caching disabled (DC-specific)." -Level "SUCCESS" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to apply LSA hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9. DNS Client Hardening ---
Write-Log -Message "Applying DNS client hardening..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DisableParallelAandAAAA" -Value 1 -Type DWord
    ipconfig /flushdns 2>&1 | Out-Null
    Write-Log -Message "DNS client hardening applied, cache flushed." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply DNS client hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9a. WPAD Attack Mitigation (CVE-2016-3236) ---
Write-Log -Message "Disabling WPAD (Web Proxy Auto-Discovery)..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -Value 1 -Type DWord
    Write-Log -Message "WPAD disabled (proxy auto-detection off)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable WPAD: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9b. RPC Hardening (CVE-2022-26809) ---
Write-Log -Message "Applying RPC hardening..." -Level "INFO" -LogFile $LogFile
try {
    $rpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
    Set-RegistryValue -Path $rpcPath -Name "RestrictRemoteClients" -Value 1 -Type DWord
    Set-RegistryValue -Path $rpcPath -Name "EnableAuthEpResolution" -Value 1 -Type DWord
    # Disable RPC usage from remote asset interacting with scheduled tasks
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1 -Type DWord
    # Disable RPC usage from remote asset interacting with services
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "DisableRemoteScmEndpoints" -Value 1 -Type DWord
    Write-Log -Message "RPC hardening applied (restrict remote clients, authenticated EP resolution)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply RPC hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9c. DNS-over-HTTPS (DoH) Enforcement ---
Write-Log -Message "Enabling DNS-over-HTTPS..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2 -Type DWord
    Write-Log -Message "DNS-over-HTTPS enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable DNS-over-HTTPS: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9d. TCP/IP Stack Hardening ---
Write-Log -Message "Applying TCP/IP stack hardening..." -Level "INFO" -LogFile $LogFile
try {
    $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    # Disable IP source routing (IPv4 and IPv6)
    Set-RegistryValue -Path $tcpipPath -Name "DisableIPSourceRouting" -Value 2 -Type DWord
    Set-RegistryValue -Path $tcpip6Path -Name "DisableIPSourceRouting" -Value 2 -Type DWord
    # Disable automatic detection of dead gateways
    Set-RegistryValue -Path $tcpipPath -Name "EnableDeadGWDetect" -Value 0 -Type DWord
    # Disable ICMP redirect
    Set-RegistryValue -Path $tcpipPath -Name "EnableICMPRedirect" -Value 0 -Type DWord
    # Disable IRDP (Router Discovery)
    Set-RegistryValue -Path $tcpipPath -Name "PerformRouterDiscovery" -Value 0 -Type DWord
    # Disable IGMP
    Set-RegistryValue -Path $tcpipPath -Name "IGMPLevel" -Value 0 -Type DWord
    # SYN attack protection
    Set-RegistryValue -Path $tcpipPath -Name "SynAttackProtect" -Value 1 -Type DWord
    # Limit SYN-ACK retransmissions
    Set-RegistryValue -Path $tcpipPath -Name "TcpMaxConnectResponseRetransmissions" -Value 2 -Type DWord
    # Disable dial-up password saving
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "DisableSavePassword" -Value 1 -Type DWord
    Write-Log -Message "TCP/IP stack hardened (source routing, ICMP redirect, IRDP, IGMP, SYN protection)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply TCP/IP stack hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9e. BITS Transfer Limiting ---
Write-Log -Message "Limiting BITS transfer speeds..." -Level "INFO" -LogFile $LogFile
try {
    $bitsPath = "HKLM:\Software\Policies\Microsoft\Windows\BITS"
    Set-RegistryValue -Path $bitsPath -Name "EnableBITSMaxBandwidth" -Value 1 -Type DWord
    Set-RegistryValue -Path $bitsPath -Name "MaxTransferRateOffSchedule" -Value 1 -Type DWord
    Set-RegistryValue -Path $bitsPath -Name "MaxDownloadTime" -Value 1 -Type DWord
    Write-Log -Message "BITS transfer speeds limited." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to limit BITS: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9f. Credential Delegation & Remote Credential Guard ---
Write-Log -Message "Configuring Credential Delegation settings..." -Level "INFO" -LogFile $LogFile
try {
    $credDelegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
    # Enable support for Remote Credential Guard / Restricted Admin
    Set-RegistryValue -Path $credDelegPath -Name "AllowProtectedCreds" -Value 1 -Type DWord
    # Enable Restricted Admin mode
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -Type DWord
    # Disable Restricted Admin outbound creds
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdminOutboundCreds" -Value 1 -Type DWord
    # Enforce credential delegation (Remote Credential Guard)
    Set-RegistryValue -Path $credDelegPath -Name "RestrictedRemoteAdministration" -Value 1 -Type DWord
    Set-RegistryValue -Path $credDelegPath -Name "RestrictedRemoteAdministrationType" -Value 3 -Type DWord
    Write-Log -Message "Credential Delegation configured (Remote Credential Guard enabled)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure Credential Delegation: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9g. SChannel Cipher Configuration ---
Write-Log -Message "Configuring SChannel ciphers, hashes, protocols..." -Level "INFO" -LogFile $LogFile
try {
    $schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

    # --- Ciphers: AES only ---
    Set-RegistryValue -Path "$schannelBase\Ciphers\AES 128/128" -Name "Enabled" -Value 0xffffffff -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\AES 256/256" -Name "Enabled" -Value 0xffffffff -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\DES 56/56" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\NULL" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\RC2 128/128" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\RC2 40/128" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\RC2 56/128" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\RC4 128/128" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\RC4 40/128" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\RC4 56/128" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\RC4 64/128" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Ciphers\Triple DES 168" -Name "Enabled" -Value 0 -Type DWord
    Write-Log -Message "SChannel ciphers configured (AES only)." -Level "SUCCESS" -LogFile $LogFile

    # --- Hashes: SHA256+ only ---
    Set-RegistryValue -Path "$schannelBase\Hashes\MD5" -Name "Enabled" -Value 0x0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Hashes\SHA" -Name "Enabled" -Value 0x0 -Type DWord
    Set-RegistryValue -Path "$schannelBase\Hashes\SHA256" -Name "Enabled" -Value 0xffffffff -Type DWord
    Set-RegistryValue -Path "$schannelBase\Hashes\SHA384" -Name "Enabled" -Value 0xffffffff -Type DWord
    Set-RegistryValue -Path "$schannelBase\Hashes\SHA512" -Name "Enabled" -Value 0xffffffff -Type DWord
    Write-Log -Message "SChannel hashes configured (SHA256+ only)." -Level "SUCCESS" -LogFile $LogFile

    # --- Key Exchanges ---
    Set-RegistryValue -Path "$schannelBase\KeyExchangeAlgorithms\Diffie-Hellman" -Name "Enabled" -Value 0xffffffff -Type DWord
    Set-RegistryValue -Path "$schannelBase\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Value 0x00001000 -Type DWord
    Set-RegistryValue -Path "$schannelBase\KeyExchangeAlgorithms\ECDH" -Name "Enabled" -Value 0xffffffff -Type DWord
    Set-RegistryValue -Path "$schannelBase\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -Value 0xffffffff -Type DWord
    Write-Log -Message "SChannel key exchange algorithms configured (DH 4096-bit min)." -Level "SUCCESS" -LogFile $LogFile

    # --- Protocols: Disable everything below TLS 1.2 ---
    $disableProtocols = @(
        "Multi-Protocol Unified Hello",
        "PCT 1.0",
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1"
    )
    foreach ($proto in $disableProtocols) {
        foreach ($side in @("Client", "Server")) {
            Set-RegistryValue -Path "$schannelBase\Protocols\$proto\$side" -Name "Enabled" -Value 0 -Type DWord
            Set-RegistryValue -Path "$schannelBase\Protocols\$proto\$side" -Name "DisabledByDefault" -Value 1 -Type DWord
        }
    }
    # Enable TLS 1.2
    foreach ($side in @("Client", "Server")) {
        Set-RegistryValue -Path "$schannelBase\Protocols\TLS 1.2\$side" -Name "Enabled" -Value 0xffffffff -Type DWord
        Set-RegistryValue -Path "$schannelBase\Protocols\TLS 1.2\$side" -Name "DisabledByDefault" -Value 0 -Type DWord
    }
    Write-Log -Message "SChannel protocols configured (TLS 1.2 only)." -Level "SUCCESS" -LogFile $LogFile

    # --- Cipher Suite Order ---
    $cipherSuites = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384," +
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256," +
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384," +
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256," +
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384," +
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256," +
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384," +
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256," +
        "TLS_RSA_WITH_AES_256_GCM_SHA384," +
        "TLS_RSA_WITH_AES_128_GCM_SHA256," +
        "TLS_RSA_WITH_AES_256_CBC_SHA256," +
        "TLS_RSA_WITH_AES_128_CBC_SHA256"
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherSuites -Type String
    Write-Log -Message "SChannel cipher suite order configured." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure SChannel: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 10. Disable TCP Timestamps ---
Write-Log -Message "Disabling TCP Timestamps..." -Level "INFO" -LogFile $LogFile
try {
    netsh int tcp set global timestamps=disabled 2>&1 | Out-Null
    Write-Log -Message "TCP Timestamps disabled (prevents OS fingerprinting and uptime leakage)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable TCP Timestamps: $_" -Level "WARNING" -LogFile $LogFile
}

# ═════════════════════════════════════════════════════════════════════════════
# DOMAIN CONTROLLER ONLY
# ═════════════════════════════════════════════════════════════════════════════
if ($IsDomainController) {

    # --- 10. LDAP & Kerberos Hardening ---
    Write-Log -Message "Applying LDAP & Kerberos Hardening..." -Level "INFO" -LogFile $LogFile
    try {
        # Enforce LDAP Client Signing
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 2 -Type DWord

        # Kerberos Encryption Types (AES + RC4 for compatibility)
        # 2147483644 = AES128 + AES256 + RC4
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483644 -Type DWord

        # CVE-2014-6324 (MS14-068) - Limit Kerberos TGT renewal lifetime
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "MaxLifetimeForUserTgtRenewal" -Value 10 -Type DWord

        # LDAP Server Integrity (Signing)
        Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord

        # LDAP Channel Binding
        Write-Host "IMPACT: Enforcing LDAP Channel Binding breaks legacy LDAP clients/apps that don't support Channel Binding Tokens (CBT) over SSL." -ForegroundColor Yellow
        $ldapBinding = Read-Host "Enforce LDAP Channel Binding? [y/n]"
        if ($ldapBinding -eq 'y') {
            Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
            Write-Log -Message "LDAP Channel Binding enforcement enabled." -Level "SUCCESS" -LogFile $LogFile
        } else {
            Write-Log -Message "Skipping LDAP channel binding enforcement." -Level "WARNING" -LogFile $LogFile
        }

        # Disable Unauthenticated LDAP (dsHeuristics)
        $DN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName)
        $DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
        $Heuristic = $DirectoryService.dsHeuristics
        if (-not $Heuristic) { $Heuristic = "0000000" }
        if ($Heuristic.Length -ge 7) {
            $Array = $Heuristic.ToCharArray()
            $Array[6] = "0"
            $Heuristic = "$Array".Replace(" ", "")
            Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic}
            Write-Log -Message "Disabled Anonymous LDAP via dsHeuristics." -Level "SUCCESS" -LogFile $LogFile
        }

        Write-Log -Message "LDAP & Kerberos hardening applied." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to apply LDAP/Kerberos hardening: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 11. DNS Server Security ---
    Write-Log -Message "Applying DNS Server Security..." -Level "INFO" -LogFile $LogFile
    try {
        # SIGRed Mitigation (CVE-2020-1350)
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "TcpReceivePacketSize" -Value 0xFF00 -Type DWord
        # CVE-2020-25705 - Limit UDP packet size
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "MaximumUdpPacketSize" -Value 0x4C5 -Type DWord

        # Global Query Block List
        dnscmd /config /enableglobalqueryblocklist 1 | Out-Null

        # Response Rate Limiting
        if (Get-Command Set-DnsServerResponseRateLimiting -ErrorAction SilentlyContinue) {
            Set-DnsServerRRL -Mode Enable -Force -ErrorAction SilentlyContinue
        }

        # DNS Socket Pool Size (Anti-DDoS)
        dnscmd /config /SocketPoolSize 10000 | Out-Null
        Write-Log -Message "DNS Socket Pool Size set to 10000." -Level "SUCCESS" -LogFile $LogFile

        # DNS Cache Locking (Anti-Cache Poisoning)
        dnscmd /config /CacheLockingPercent 100 | Out-Null
        Write-Log -Message "DNS Cache Locking set to 100%." -Level "SUCCESS" -LogFile $LogFile

        Write-Log -Message "DNS server security settings applied." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to apply DNS server security: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 11.1 Advanced DNS Hardening ---
    Write-Log -Message "Applying Advanced DNS Hardening..." -Level "INFO" -LogFile $LogFile
    try {
        # Recursion
        Write-Host "IMPACT: Disabling DNS Recursion prevents this server from resolving external internet domains." -ForegroundColor Yellow
        $dnsRecursion = Read-Host "Disable DNS recursion? [y/n]"
        if ($dnsRecursion -eq 'y') {
            if (Get-Command Set-DnsServerRecursion -ErrorAction SilentlyContinue) {
                Set-DnsServerRecursion -Enable $false -ErrorAction SilentlyContinue
            } else {
                dnscmd /config /norecursion 1 | Out-Null
            }
            Write-Log -Message "DNS recursion disabled." -Level "SUCCESS" -LogFile $LogFile
        } else {
            Write-Log -Message "Skipping DNS recursion disable to avoid resolver outages." -Level "WARNING" -LogFile $LogFile
        }

        # Diagnostics
        Set-DnsServerDiagnostics -EventLogLevel 4 -UseSystemEventLog $True -EnableLogFileRollover $False -ErrorAction SilentlyContinue

        # Cache & TTL
        Set-DnsServerCache -MaxTtl "24.00:00:00" -MaxNegativeTtl "00:15:00" -PollutionProtection $True -ErrorAction SilentlyContinue

        # Zone Transfers (Secure Only)
        $zones = Get-DnsServerZone
        foreach ($zone in $zones) {
            if ($zone.ZoneType -eq "Primary" -and $zone.IsAutoCreated -eq $false) {
                try {
                    Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate Secure -ErrorAction SilentlyContinue
                    Set-DnsServerZoneTransfer -Name $zone.ZoneName -SecureSecondaries TransferToSecureServers -ErrorAction SilentlyContinue
                } catch {
                    Write-Log -Message "Failed to harden zone $($zone.ZoneName): $_" -Level "WARNING" -LogFile $LogFile
                }
            }
        }

        # Scavenging
        Set-DnsServerScavenging -ScavengingInterval "7.00:00:00" -ErrorAction SilentlyContinue

        # Additional dnscmd hardening
        dnscmd /config /bindsecondaries 0 | Out-Null
        dnscmd /config /bootmethod 3 | Out-Null
        dnscmd /config /disableautoreversezones 1 | Out-Null
        dnscmd /config /disablensrecordsautocreation 1 | Out-Null
        dnscmd /config /enableglobalnamessupport 0 | Out-Null
        dnscmd /config /enableglobalqueryblocklist 1 | Out-Null
        dnscmd /config /globalqueryblocklist isatap wpad | Out-Null
        dnscmd /config /roundrobin 1 | Out-Null
        dnscmd /config /secureresponses 1 | Out-Null
        dnscmd /config /strictfileparsing 1 | Out-Null
        dnscmd /config /writeauthorityns 0 | Out-Null

        # ServerLevelPluginDll Check (often malicious)
        $dnsParams = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
        if ($dnsParams.ServerLevelPluginDll) {
            Write-Log -Message "WARNING: ServerLevelPluginDll found: $($dnsParams.ServerLevelPluginDll). This is often malicious." -Level "WARNING" -LogFile $LogFile
        }

        Write-Log -Message "Advanced DNS Hardening applied." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to apply Advanced DNS Hardening: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 12. Zerologon Mitigation & Netlogon Hardening ---
    Write-Log -Message "Applying Zerologon Mitigation and Netlogon Hardening..." -Level "INFO" -LogFile $LogFile
    try {
        $netlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

        # Zerologon Protection
        Set-RegistryValue -Path $netlogonPath -Name "FullSecureChannelProtection" -Value 1 -Type DWord
        Write-Log -Message "FullSecureChannelProtection enabled." -Level "SUCCESS" -LogFile $LogFile

        # Remove Vulnerable Channel Allowlist
        if (Test-Path -Path "$netlogonPath\vulnerablechannelallowlist") {
            Remove-ItemProperty -Path $netlogonPath -Name "vulnerablechannelallowlist" -Force | Out-Null
            Write-Log -Message "vulnerablechannelallowlist removed." -Level "SUCCESS" -LogFile $LogFile
        }

        # Netlogon Secure Channel Hardening
        Set-RegistryValue -Path $netlogonPath -Name "RequireSignOrSeal" -Value 1 -Type DWord
        Set-RegistryValue -Path $netlogonPath -Name "SealSecureChannel" -Value 1 -Type DWord
        Set-RegistryValue -Path $netlogonPath -Name "SignSecureChannel" -Value 1 -Type DWord
        Set-RegistryValue -Path $netlogonPath -Name "RequireStrongKey" -Value 1 -Type DWord
        Write-Log -Message "Netlogon secure channel hardening applied (Sign/Seal/StrongKey)." -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to apply Netlogon hardening: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 12a. noPac / SamAccountName Spoofing (CVE-2021-42287/CVE-2021-42278) ---
    Write-Log -Message "Applying noPac mitigation (CVE-2021-42287/42278)..." -Level "INFO" -LogFile $LogFile
    try {
        Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} -ErrorAction Stop
        Write-Log -Message "ms-DS-MachineAccountQuota set to 0 (noPac mitigation)." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to apply noPac mitigation: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 13. Time Synchronization (Critical for Kerberos) ---
    Write-Log -Message "Synchronizing System Time..." -Level "INFO" -LogFile $LogFile
    try {
        tzutil /s "UTC" | Out-Null
        w32tm /resync /force | Out-Null
        Write-Log -Message "System time synchronized successfully." -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to synchronize system time: $_" -Level "ERROR" -LogFile $LogFile
    }

} # end DC-only block

# ═════════════════════════════════════════════════════════════════════════════
# ALL MACHINES -- SMB Share Management (interactive, at the end)
# ═════════════════════════════════════════════════════════════════════════════
Write-Log -Message "=== SMB Share Management ===" -Level "INFO" -LogFile $LogFile
Write-Host ""
Write-Host "  [1] Enumerate shares and select which to remove" -ForegroundColor Yellow
Write-Host "  [2] Disable SMB server entirely" -ForegroundColor Yellow
Write-Host "  [3] Skip SMB share management" -ForegroundColor Yellow
$smbShareChoice = Read-Host "SMB share action [1/2/3]"

switch ($smbShareChoice) {
    "1" {
        Write-Log -Message "Enumerating SMB shares..." -Level "INFO" -LogFile $LogFile
        try {
            $allShares = Get-SmbShare -ErrorAction Stop
            if (-not $allShares -or $allShares.Count -eq 0) {
                Write-Log -Message "No SMB shares found." -Level "INFO" -LogFile $LogFile
            } else {
                Write-Host "`n===== Current SMB Shares =====" -ForegroundColor Cyan
                foreach ($share in $allShares) {
                    $accessRules = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                    Write-Host "`n  Share: " -NoNewline; Write-Host $share.Name -ForegroundColor Yellow
                    Write-Host "  Path:  $($share.Path)"
                    if ($accessRules) {
                        foreach ($rule in $accessRules) {
                            Write-Host "    - $($rule.AccountName): $($rule.AccessRight) ($($rule.AccessControlType))" -ForegroundColor Gray
                        }
                    }
                }
                Write-Host "`n==============================`n" -ForegroundColor Cyan

                $shareLabels = $allShares | ForEach-Object {
                    $perms = (Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue |
                              ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ", "
                    if ($perms) { "$($_.Name)  [$($_.Path)]  ($perms)" }
                    else        { "$($_.Name)  [$($_.Path)]" }
                }

                Write-Host "Enter share names to REMOVE (comma-separated), or press Enter to skip:" -ForegroundColor Cyan
                $removeInput = Read-Host "Shares to remove"

                if (-not [string]::IsNullOrWhiteSpace($removeInput)) {
                    $criticalShares = @("ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL")
                    $toRemove = $removeInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    $shareNames = $allShares | ForEach-Object { $_.Name }

                    foreach ($shareName in $toRemove) {
                        if ($shareName -in $shareNames) {
                            if ($shareName -in $criticalShares) {
                                Write-Host "WARNING: '$shareName' is a critical system/AD share. Removing it may break functionality." -ForegroundColor Red
                                $confirm = Read-Host "Are you SURE you want to remove '$shareName'? [yes/no]"
                                if ($confirm -ne "yes") {
                                    Write-Log -Message "Skipped removal of critical share '$shareName' (user declined)." -Level "INFO" -LogFile $LogFile
                                    continue
                                }
                            }
                            try {
                                Remove-SmbShare -Name $shareName -Force -ErrorAction Stop
                                Write-Log -Message "Removed SMB share: $shareName" -Level "SUCCESS" -LogFile $LogFile
                            } catch {
                                Write-Log -Message "Failed to remove share '$shareName': $_" -Level "WARNING" -LogFile $LogFile
                            }
                        } else {
                            Write-Log -Message "Share '$shareName' not found, skipping." -Level "WARNING" -LogFile $LogFile
                        }
                    }
                }
            }
        } catch {
            Write-Log -Message "Failed during SMB share enumeration: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    "2" {
        Write-Log -Message "Disabling SMB server entirely..." -Level "WARNING" -LogFile $LogFile
        Write-Host "WARNING: This will disable ALL file sharing on this machine." -ForegroundColor Red
        $confirmDisable = Read-Host "Are you sure? [yes/no]"
        if ($confirmDisable -eq 'yes') {
            try {
                if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
                    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -Confirm:$false -ErrorAction Stop
                }
                Stop-Service -Name LanmanServer -Force -ErrorAction SilentlyContinue
                Set-Service -Name LanmanServer -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log -Message "SMB server disabled entirely." -Level "SUCCESS" -LogFile $LogFile
            } catch {
                Write-Log -Message "Failed to disable SMB server: $_" -Level "ERROR" -LogFile $LogFile
            }
        } else {
            Write-Log -Message "SMB server disable cancelled." -Level "INFO" -LogFile $LogFile
        }
    }
    default {
        Write-Log -Message "Skipping SMB share management." -Level "INFO" -LogFile $LogFile
    }
}

Write-Log -Message "Network Security module complete." -Level "SUCCESS" -LogFile $LogFile
