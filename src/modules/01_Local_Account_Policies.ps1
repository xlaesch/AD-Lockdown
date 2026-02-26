# 01_Local_Account_Policies.ps1
# Handles local account policies, password requirements, and user hardening
# Runs on ALL machines (DCs and non-DCs alike).

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

Write-Log -Message "Starting Local Account Policies..." -Level "INFO" -LogFile $LogFile

# --- 1. Disable Guest Account ---
Write-Log -Message "Disabling Guest account..." -Level "INFO" -LogFile $LogFile
try {
    net user Guest /active:no 2>&1 | Out-Null
    Write-Log -Message "Guest account disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Guest account: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Local Account Password Policy ---
Write-Log -Message "Configuring local password policy..." -Level "INFO" -LogFile $LogFile
try {
    # MinPwLen=10, MaxPwAge=90, MinPwAge=1, UniquePasswords=5, Lockout after 5 attempts, 30min window/duration
    net accounts /MINPWLEN:10 /MAXPWAGE:90 /MINPWAGE:1 /UNIQUEPW:5 /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30 /FORCELOGOFF:30 2>&1 | Out-Null
    Write-Log -Message "Password policy configured (MinLen=10, Lockout=5 attempts/30min)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure password policy: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Disable Auto Admin Logon ---
Write-Log -Message "Disabling automatic admin logon..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Type DWord
    # Clear any stored default password
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (Get-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed stored DefaultPassword from Winlogon." -Level "SUCCESS" -LogFile $LogFile
    }
    Write-Log -Message "Auto admin logon disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable auto admin logon: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Limit Blank Password Use ---
Write-Log -Message "Limiting blank password use..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
    Write-Log -Message "Blank password use limited for network logons." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to limit blank password use: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Remove LSA Notification Packages (Potential Password Stealers) ---
Write-Log -Message "Checking LSA Notification Packages..." -Level "INFO" -LogFile $LogFile
try {
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $notifPkgs = (Get-ItemProperty -Path $lsaPath -Name "Notification Packages" -ErrorAction SilentlyContinue)."Notification Packages"
    if ($notifPkgs) {
        # Known safe packages: scecli, rassfm
        $safePackages = @("scecli", "rassfm")
        $suspiciousPackages = $notifPkgs | Where-Object { $_ -and ($safePackages -notcontains $_) }
        if ($suspiciousPackages) {
            Write-Log -Message "SUSPICIOUS LSA Notification Packages found: $($suspiciousPackages -join ', ')" -Level "WARNING" -LogFile $LogFile
            Write-Host "Found non-standard LSA Notification Packages (potential password stealers):" -ForegroundColor Red
            $suspiciousPackages | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
            $removePkgs = Read-Host "Remove suspicious packages and keep only safe defaults (scecli)? [y/n]"
            if ($removePkgs -eq 'y') {
                Set-ItemProperty -Path $lsaPath -Name "Notification Packages" -Value @("scecli") -Force
                Write-Log -Message "LSA Notification Packages reset to safe defaults." -Level "SUCCESS" -LogFile $LogFile
            } else {
                Write-Log -Message "Skipping LSA Notification Package cleanup." -Level "WARNING" -LogFile $LogFile
            }
        } else {
            Write-Log -Message "LSA Notification Packages appear clean." -Level "INFO" -LogFile $LogFile
        }
    }
} catch {
    Write-Log -Message "Failed to check LSA Notification Packages: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 6. Disable Domain Credential Caching (Optional) ---
Write-Log -Message "Configuring credential caching..." -Level "INFO" -LogFile $LogFile
try {
    # Reduce cached logon count (default is 10, set to 2 for competition)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "2" -Type String
    Write-Log -Message "Cached logon count reduced to 2." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure credential caching: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 7. Allocate CD-ROMs to Logged-On User Only ---
Write-Log -Message "Restricting CD-ROM access to logged-on user..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1 -Type DWord
    Write-Log -Message "CD-ROM allocation restricted." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure CD-ROM allocation: $_" -Level "ERROR" -LogFile $LogFile
}

Write-Log -Message "Local Account Policies module complete." -Level "SUCCESS" -LogFile $LogFile
