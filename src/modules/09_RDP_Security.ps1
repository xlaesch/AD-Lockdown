# 09_RDP_Security.ps1
# Handles Remote Desktop Protocol security configuration

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

Write-Log -Message "Starting RDP Security Configuration..." -Level "INFO" -LogFile $LogFile

# --- 1. Enable RDP ---
Write-Log -Message "Ensuring RDP is enabled..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "AllowTSConnections" -Value 1 -Type DWord
    netsh advfirewall firewall set rule group="remote desktop" new enable=yes 2>&1 | Out-Null
    Write-Log -Message "RDP enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable RDP: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Network Level Authentication (NLA) ---
Write-Log -Message "Enforcing Network Level Authentication (NLA)..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord
    Write-Log -Message "NLA enforced for RDP connections." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enforce NLA: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. RDP Encryption ---
Write-Log -Message "Configuring RDP encryption..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fDisableEncryption" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Type DWord
    # Require encrypted RPC connections to Terminal Services
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord
    Write-Log -Message "RDP encryption set to High with SSL/TLS security layer, RPC encryption required." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure RDP encryption: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Disable Remote Assistance ---
Write-Log -Message "Disabling Remote Assistance..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\ControlSet001\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\ControlSet001\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\ControlSet001\Control\Remote Assistance" -Name "CreateEncryptedOnlyTickets" -Value 1 -Type DWord
    # GPO-level disable (ensures policy enforcement)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord
    Write-Log -Message "Remote Assistance disabled, encrypted tickets only." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Remote Assistance: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4a. Prevent Local Drive Sharing via RDP ---
Write-Log -Message "Preventing local drive sharing via RDP sessions..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord
    Write-Log -Message "Local drive sharing via RDP disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable RDP drive sharing: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Disable Remote RPC for Terminal Services ---
Write-Log -Message "Disabling Remote RPC for Terminal Services..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "AllowRemoteRPC" -Value 0 -Type DWord
    Write-Log -Message "Remote RPC for Terminal Services disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Remote RPC: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 6. Session Timeout Configuration ---
Write-Log -Message "Configuring RDP session timeouts..." -Level "INFO" -LogFile $LogFile
try {
    $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-RegistryValue -Path $tsPath -Name "MaxIdleTime" -Value 1800000 -Type DWord
    Set-RegistryValue -Path $tsPath -Name "MaxDisconnectionTime" -Value 900000 -Type DWord
    Set-RegistryValue -Path $tsPath -Name "fResetBroken" -Value 1 -Type DWord
    Write-Log -Message "RDP session timeouts configured (idle=30min, disconnected=15min)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure session timeouts: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 7. RDP Port Configuration (Optional) ---
Write-Log -Message "=== RDP Port Configuration ===" -Level "INFO" -LogFile $LogFile
Write-Host "Current RDP port: 3389 (default)" -ForegroundColor Cyan
Write-Host "IMPACT: Changing RDP port requires updating firewall rules and may confuse scoring engines." -ForegroundColor Yellow
$changePort = Read-Host "Change RDP port from default 3389? [y/n]"
if ($changePort -eq 'y') {
    $newPort = Read-Host "Enter new RDP port number"
    if ($newPort -match '^\d+$' -and [int]$newPort -gt 0 -and [int]$newPort -le 65535) {
        try {
            Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value ([int]$newPort) -Type DWord
            $ruleName = "RDP Custom Port ($newPort)"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $newPort -Action Allow -Profile Any | Out-Null
            }
            Write-Log -Message "RDP port changed to $newPort (requires restart of TermService)." -Level "SUCCESS" -LogFile $LogFile
            Write-Host "NOTE: Restart the TermService or reboot for the port change to take effect." -ForegroundColor Yellow
        } catch {
            Write-Log -Message "Failed to change RDP port: $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Invalid port number. Keeping default 3389." -Level "WARNING" -LogFile $LogFile
    }
} else {
    Write-Log -Message "RDP port left at default 3389." -Level "INFO" -LogFile $LogFile
}

# --- 8. Restrict RDP Access (Optional) ---
Write-Log -Message "Checking Remote Desktop Users group membership..." -Level "INFO" -LogFile $LogFile
try {
    $rdpGroup = net localgroup "Remote Desktop Users" 2>&1
    Write-Host "`nCurrent Remote Desktop Users group:" -ForegroundColor Cyan
    $rdpGroup | ForEach-Object { Write-Host "  $_" }
    Write-Log -Message "Remote Desktop Users group listed for review." -Level "INFO" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enumerate Remote Desktop Users: $_" -Level "WARNING" -LogFile $LogFile
}

Write-Log -Message "RDP Security module complete." -Level "SUCCESS" -LogFile $LogFile
