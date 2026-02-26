# 06_Windows_Defender.ps1
# Handles Windows Defender configuration and anti-malware hardening

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

Write-Log -Message "Starting Windows Defender Configuration..." -Level "INFO" -LogFile $LogFile

# --- 1. Ensure Defender is Enabled ---
Write-Log -Message "Ensuring Windows Defender is enabled..." -Level "INFO" -LogFile $LogFile
try {
    # Remove policies that disable Defender
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord

    # Prevent Defender passive mode
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -Value 0 -Type DWord
    # Start the service
    Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    # Enable Defender sandboxing
    cmd /c "setx /M MP_FORCE_USE_SANDBOX 1" 2>&1 | Out-Null
    Write-Log -Message "Windows Defender enabled, sandboxed, and running." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable Windows Defender: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Clear Suspicious Exclusions ---
Write-Log -Message "Checking for suspicious Defender exclusions..." -Level "INFO" -LogFile $LogFile
try {
    $prefs = Get-MpPreference -ErrorAction SilentlyContinue
    $hasExclusions = $false

    if ($prefs.ExclusionPath -and $prefs.ExclusionPath.Count -gt 0) {
        Write-Host "Exclusion Paths:" -ForegroundColor Yellow
        $prefs.ExclusionPath | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        $hasExclusions = $true
    }
    if ($prefs.ExclusionProcess -and $prefs.ExclusionProcess.Count -gt 0) {
        Write-Host "Exclusion Processes:" -ForegroundColor Yellow
        $prefs.ExclusionProcess | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        $hasExclusions = $true
    }
    if ($prefs.ExclusionExtension -and $prefs.ExclusionExtension.Count -gt 0) {
        Write-Host "Exclusion Extensions:" -ForegroundColor Yellow
        $prefs.ExclusionExtension | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        $hasExclusions = $true
    }

    if ($hasExclusions) {
        $clearExclusions = Read-Host "Clear all Defender exclusions? [y/n]"
        if ($clearExclusions -eq 'y') {
            if ($prefs.ExclusionPath) {
                $prefs.ExclusionPath | ForEach-Object { Remove-MpPreference -ExclusionPath $_ -ErrorAction SilentlyContinue }
            }
            if ($prefs.ExclusionProcess) {
                $prefs.ExclusionProcess | ForEach-Object { Remove-MpPreference -ExclusionProcess $_ -ErrorAction SilentlyContinue }
            }
            if ($prefs.ExclusionExtension) {
                $prefs.ExclusionExtension | ForEach-Object { Remove-MpPreference -ExclusionExtension $_ -ErrorAction SilentlyContinue }
            }
            if ($prefs.ExclusionIpAddress) {
                $prefs.ExclusionIpAddress | ForEach-Object { Remove-MpPreference -ExclusionIpAddress $_ -ErrorAction SilentlyContinue }
            }
            Write-Log -Message "All Defender exclusions cleared (path, process, extension, IP)." -Level "SUCCESS" -LogFile $LogFile
        } else {
            Write-Log -Message "Defender exclusions left as-is." -Level "WARNING" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "No Defender exclusions found." -Level "INFO" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to check/clear Defender exclusions: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Configure Defender Preferences ---
Write-Log -Message "Configuring Defender scan and protection preferences..." -Level "INFO" -LogFile $LogFile
try {
    Set-MpPreference `
        -DisableArchiveScanning $false `
        -DisableBehaviorMonitoring $false `
        -DisableBlockAtFirstSeen $false `
        -DisableEmailScanning $false `
        -DisableIOAVProtection $false `
        -DisableIntrusionPreventionSystem $false `
        -DisableRealtimeMonitoring $false `
        -DisableRemovableDriveScanning $false `
        -DisableScanningMappedNetworkDrivesForFullScan $false `
        -DisableScanningNetworkFiles $false `
        -DisableScriptScanning $false `
        -PUAProtection Enabled `
        -HighThreatDefaultAction Remove `
        -SevereThreatDefaultAction Remove `
        -ModerateThreatDefaultAction Quarantine `
        -LowThreatDefaultAction Quarantine `
        -UnknownThreatDefaultAction Quarantine `
        -ScanAvgCPULoadFactor 50 `
        -CheckForSignaturesBeforeRunningScan $true `
        -SignatureUpdateInterval 1 `
        -Force -ErrorAction Stop

    Write-Log -Message "Defender preferences configured (all protections enabled, PUA enabled)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure Defender preferences: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Heuristics & Scan Settings ---
Write-Log -Message "Configuring Defender heuristics and scan policies..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableHeuristics" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "CheckForSignaturesBeforeRunningScan" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3 -Type DWord
    Write-Log -Message "Defender heuristics enabled, attachment scanning enforced." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure Defender heuristics: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4a. Additional Defender Registry Settings ---
Write-Log -Message "Applying additional Defender registry hardening..." -Level "INFO" -LogFile $LogFile
try {
    # Expose exclusions to local admins for visibility
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "HideExclusionsFromLocalAdmins" -Value 0 -Type DWord
    # Cloud-delivered protection block level
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpCloudBlockLevel" -Value 1 -Type DWord
    # Enable PUP protection (legacy key)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 1 -Type DWord
    Write-Log -Message "Additional Defender registry settings applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply additional Defender settings: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4b. Exploit Guard Network Protection ---
Write-Log -Message "Enabling Defender Exploit Guard Network Protection..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord
    Write-Log -Message "Exploit Guard network protection enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable network protection: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Tamper Protection ---
Write-Log -Message "Enabling Tamper Protection..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 5 -Type DWord
    Write-Log -Message "Tamper Protection enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable Tamper Protection: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 6. Disable Telemetry/Sample Submission (Competition Privacy) ---
Write-Log -Message "Configuring Defender telemetry for competition environment..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value 1 -Type DWord
    Write-Log -Message "Defender telemetry configured for competition (MAPS/sample submission disabled)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure Defender telemetry: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 7. Attack Surface Reduction (ASR) Rules ---
Write-Log -Message "Enabling Windows Defender Attack Surface Reduction rules..." -Level "INFO" -LogFile $LogFile
try {
    $asrRules = @(
        @{ Id = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"; Desc = "Block executable content from email client and webmail" }
        @{ Id = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; Desc = "Block all Office applications from creating child processes" }
        @{ Id = "3B576869-A4EC-4529-8536-B80A7769E899"; Desc = "Block Office applications from creating executable content" }
        @{ Id = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"; Desc = "Block Office applications from injecting code into other processes" }
        @{ Id = "D3E037E1-3EB8-44C8-A917-57927947596D"; Desc = "Block JavaScript or VBScript from launching downloaded executable content" }
        @{ Id = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"; Desc = "Block execution of potentially obfuscated scripts" }
        @{ Id = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"; Desc = "Block Win32 API calls from Office macros" }
        @{ Id = "01443614-CD74-433A-B99E-2ECDC07BFC25"; Desc = "Block executable files from running unless they meet prevalence/age/trusted list criterion" }
        @{ Id = "C1DB55AB-C21A-4637-BB3F-A12568109D35"; Desc = "Use advanced protection against ransomware" }
        @{ Id = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"; Desc = "Block credential stealing from LSASS" }
        @{ Id = "D1E49AAC-8F56-4280-B9BA-993A6D77406C"; Desc = "Block process creations originating from PSExec and WMI commands" }
        @{ Id = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"; Desc = "Block untrusted and unsigned processes that run from USB" }
        @{ Id = "26190899-1602-49E8-8B27-EB1D0A1CE869"; Desc = "Block Office communication application from creating child processes" }
        @{ Id = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"; Desc = "Block Adobe Reader from creating child processes" }
        @{ Id = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"; Desc = "Block persistence through WMI event subscription" }
    )

    foreach ($rule in $asrRules) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Write-Log -Message "ASR rule enabled: $($rule.Desc)" -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to enable ASR rule '$($rule.Desc)': $_" -Level "WARNING" -LogFile $LogFile
        }
    }

    # Remove any ASR exceptions
    $asrExclusions = (Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionOnlyExclusions
    if ($asrExclusions) {
        foreach ($ex in $asrExclusions) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ex -ErrorAction SilentlyContinue
        }
        Write-Log -Message "ASR exclusions removed." -Level "SUCCESS" -LogFile $LogFile
    }

    Write-Log -Message "All ASR rules applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure ASR rules: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 8. Update Signatures ---
Write-Log -Message "Triggering Defender signature update..." -Level "INFO" -LogFile $LogFile
try {
    Update-MpSignature -ErrorAction SilentlyContinue
    Write-Log -Message "Defender signature update triggered." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to update Defender signatures: $_" -Level "WARNING" -LogFile $LogFile
}

Write-Log -Message "Windows Defender module complete." -Level "SUCCESS" -LogFile $LogFile
