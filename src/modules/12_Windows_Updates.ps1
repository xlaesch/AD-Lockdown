# 12_Windows_Updates.ps1
# Handles Windows Update configuration and triggers update checks

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

Write-Log -Message "Starting Windows Update Configuration..." -Level "INFO" -LogFile $LogFile

# --- 1. Enable Windows Update Service ---
Write-Log -Message "Ensuring Windows Update service is enabled and running..." -Level "INFO" -LogFile $LogFile
try {
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Log -Message "Windows Update service set to Automatic and started." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable Windows Update service: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Remove Update Blockers ---
Write-Log -Message "Removing Windows Update blockers..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ElevateNonAdmins" -Value 0 -Type DWord

    $updateBlockPaths = @(
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoWindowsUpdate"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoWindowsUpdate"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\Internet Communication Management\Internet Communication"; Name = "DisableWindowsUpdateAccess"; Value = 0 }
    )
    foreach ($item in $updateBlockPaths) {
        Set-RegistryValue -Path $item.Path -Name $item.Name -Value $item.Value -Type DWord
    }

    Write-Log -Message "Windows Update blockers removed, auto-install configured." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to remove update blockers: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Don't Defer Updates ---
Write-Log -Message "Ensuring updates are not deferred..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value 0 -Type DWord
    Write-Log -Message "Update deferral policies cleared." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to clear deferral policies: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Include Recommended Updates ---
Write-Log -Message "Enabling recommended updates..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "IncludeRecommendedUpdates" -Value 1 -Type DWord
    Write-Log -Message "Recommended updates enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable recommended updates: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Trigger Update Check ---
Write-Log -Message "Triggering Windows Update check..." -Level "INFO" -LogFile $LogFile
Write-Host "IMPACT: Starting a Windows Update check in the background. This won't auto-reboot." -ForegroundColor Yellow
$triggerUpdate = Read-Host "Trigger Windows Update check now? [y/n]"
if ($triggerUpdate -eq 'y') {
    try {
        if (Get-Command UsoClient.exe -ErrorAction SilentlyContinue) {
            Start-Process UsoClient.exe -ArgumentList "StartScan" -WindowStyle Hidden
            Write-Log -Message "Windows Update scan triggered via UsoClient." -Level "SUCCESS" -LogFile $LogFile
        } else {
            wuauclt /detectnow /updatenow 2>&1 | Out-Null
            Write-Log -Message "Windows Update scan triggered via wuauclt." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to trigger update check: $_" -Level "WARNING" -LogFile $LogFile
    }
} else {
    Write-Log -Message "Update check deferred." -Level "INFO" -LogFile $LogFile
}

Write-Log -Message "Windows Update module complete." -Level "SUCCESS" -LogFile $LogFile
