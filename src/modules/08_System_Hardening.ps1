# 08_System_Hardening.ps1
# Handles OS-level hardening: UAC, DEP, autorun, accessibility backdoors, startup cleanup

param(
    [string]$LogFile,
    [bool]$IsDomainController = $global:IsDomainController,
    [switch]$SkipSFC
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command Set-RegistryValue -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Set-RegistryValue.ps1"
}

Write-Log -Message "Starting System Hardening..." -Level "INFO" -LogFile $LogFile

# ═════════════════════════════════════════════════════════════════════════════
# GROUP POLICY RESET
# ═════════════════════════════════════════════════════════════════════════════

# --- 0. Reset Local Group Policy ---
Write-Log -Message "=== Local Group Policy Reset ===" -Level "INFO" -LogFile $LogFile
Write-Host "IMPACT: This backs up and resets local group policy objects to defaults." -ForegroundColor Yellow
$resetGP = Read-Host "Reset local group policy? [y/n]"
if ($resetGP -eq 'y') {
    try {
        $gpBackup = Join-Path -Path $PSScriptRoot -ChildPath "../../results/gp"
        if (-not (Test-Path $gpBackup)) { New-Item -Path $gpBackup -ItemType Directory -Force | Out-Null }
        Copy-Item "C:\Windows\System32\GroupPolicy*" $gpBackup -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\System32\GroupPolicy*" -Recurse -Force -ErrorAction SilentlyContinue
        gpupdate /force 2>&1 | Out-Null
        Write-Log -Message "Local group policy reset (backup at $gpBackup)." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to reset local group policy: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "Local group policy reset skipped." -Level "INFO" -LogFile $LogFile
}

# Note: Domain GPO wipe (delete all + dcgpofix) is now handled in
# 02_Domain_Account_Policies.ps1 which runs earlier in the hardening sequence.

# ═════════════════════════════════════════════════════════════════════════════
# CVE MITIGATIONS
# ═════════════════════════════════════════════════════════════════════════════

# --- 0a. CVE-2021-36934 (HiveNightmare/SeriousSAM) ---
Write-Log -Message "Applying HiveNightmare mitigation (CVE-2021-36934)..." -Level "INFO" -LogFile $LogFile
try {
    icacls "$env:windir\system32\config\*.*" /inheritance:e 2>&1 | Out-Null
    Write-Log -Message "HiveNightmare mitigation applied (SAM/SYSTEM/SECURITY ACL inheritance reset)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply HiveNightmare mitigation: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0b. Winlogon Persistence Protection (MITRE T1547.001) ---
Write-Log -Message "Applying Winlogon persistence protections..." -Level "INFO" -LogFile $LogFile
try {
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    # Remove cached default credentials (CVE-2022-21919)
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultDomainName" -Force -ErrorAction SilentlyContinue
    # Force Shell and Userinit to safe defaults
    Set-RegistryValue -Path $winlogonPath -Name "Shell" -Value "explorer.exe" -Type String
    Set-RegistryValue -Path $winlogonPath -Name "Userinit" -Value "C:\Windows\system32\userinit.exe," -Type String
    # Remove UIHost persistence point
    Remove-ItemProperty -Path $winlogonPath -Name "UIHost" -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Winlogon persistence protections applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Winlogon protections: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0c. DLL Hijacking Protections (CVE-2020-0668) ---
Write-Log -Message "Applying DLL hijacking protections..." -Level "INFO" -LogFile $LogFile
try {
    $sessionMgrPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    # Remove service tracing keys (CVE-2020-0668)
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Tracing" -Recurse -Force -ErrorAction SilentlyContinue
    # Prevent DLL search order hijacking
    Set-RegistryValue -Path $sessionMgrPath -Name "SafeProcessSearchMode" -Value 1 -Type DWord
    Set-RegistryValue -Path $sessionMgrPath -Name "SafeDllSearchMode" -Value 1 -Type DWord
    # Block DLL loading from remote/CWD folders
    Set-RegistryValue -Path $sessionMgrPath -Name "CWDIllegalInDllSearch" -Value 2 -Type DWord
    # Block AppInit_DLLs
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 0 -Type DWord
    Write-Log -Message "DLL hijacking protections applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply DLL hijacking protections: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0d. Disable Windows Script Host ---
Write-Log -Message "Disabling Windows Script Host..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
    Write-Log -Message "Windows Script Host disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Windows Script Host: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0e. CredSSP Encryption Oracle Mitigation (CVE-2018-0886) ---
Write-Log -Message "Applying CredSSP mitigation (CVE-2018-0886)..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value 0 -Type DWord
    Write-Log -Message "CredSSP encryption oracle vulnerability mitigated." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply CredSSP mitigation: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0f. Disable Legacy AT Command in Task Scheduler ---
Write-Log -Message "Disabling legacy AT command in Task Scheduler..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration" -Name "EnableAt" -Value 0 -Type DWord
    Write-Log -Message "Legacy AT command disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable AT command: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0g. Prevent MS Office DDE Attacks (CVE-2017-11826, CVE-2017-8759) ---
Write-Log -Message "Applying Office DDE attack protections..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options\WordMail" -Name "DontUpdateLinks" -Value 1 -Type DWord
    Write-Log -Message "Office DDE attack protections applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Office DDE protections: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0h. Disable Windows Error Reporting ---
Write-Log -Message "Disabling Windows Error Reporting..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Value 1 -Type DWord
    Write-Log -Message "Windows Error Reporting disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Windows Error Reporting: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0i. BitLocker Hardening ---
Write-Log -Message "Applying BitLocker hardening..." -Level "INFO" -LogFile $LogFile
try {
    $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    Set-RegistryValue -Path $fvePath -Name "UseAdvancedStartup" -Value 1 -Type DWord
    Set-RegistryValue -Path $fvePath -Name "EnableBDEWithNoTPM" -Value 0 -Type DWord
    Set-RegistryValue -Path $fvePath -Name "UseTPM" -Value 2 -Type DWord
    Set-RegistryValue -Path $fvePath -Name "UseTPMPIN" -Value 2 -Type DWord
    Write-Log -Message "BitLocker hardening applied (require TPM+PIN)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply BitLocker hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 0j. Microsoft Defender SmartScreen Enforcement ---
Write-Log -Message "Enforcing Microsoft Defender SmartScreen..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String
    Write-Log -Message "SmartScreen enforced (Block level, require admin)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enforce SmartScreen: $_" -Level "ERROR" -LogFile $LogFile
}

# ═════════════════════════════════════════════════════════════════════════════
# OS-LEVEL HARDENING
# ═════════════════════════════════════════════════════════════════════════════

# --- 1. UAC Configuration ---
Write-Log -Message "Configuring User Account Control (UAC)..." -Level "INFO" -LogFile $LogFile
try {
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-RegistryValue -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "FilterAdministratorToken" -Value 1 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "EnableVirtualization" -Value 1 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "EnableUIADesktopToggle" -Value 0 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "EnableInstallerDetection" -Value 1 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "ValidateAdminCodeSignatures" -Value 1 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "EnableSecureUIAPaths" -Value 1 -Type DWord
    Set-RegistryValue -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
    # Restrict local accounts on network logons
    Set-RegistryValue -Path $uacPath -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord
    Write-Log -Message "UAC configured (full hardening, secure desktop, code signature validation)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure UAC: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Data Execution Prevention (DEP) ---
Write-Log -Message "Enabling DEP (AlwaysOn)..." -Level "INFO" -LogFile $LogFile
try {
    bcdedit.exe /set "{current}" nx AlwaysOn 2>&1 | Out-Null
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Value 0 -Type DWord
    Write-Log -Message "DEP set to AlwaysOn." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable DEP: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Disable AutoRun/AutoPlay ---
Write-Log -Message "Disabling AutoRun/AutoPlay..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    Write-Log -Message "AutoRun/AutoPlay disabled for all drives." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable AutoRun: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Remove Accessibility Tool Backdoors ---
Write-Log -Message "Removing accessibility tool backdoors..." -Level "INFO" -LogFile $LogFile
$accessibilityTools = @(
    @{ Name = "sethc.exe";    Desc = "Sticky Keys" },
    @{ Name = "Utilman.exe";  Desc = "Utility Manager" },
    @{ Name = "osk.exe";      Desc = "On-Screen Keyboard" },
    @{ Name = "Narrator.exe"; Desc = "Narrator" },
    @{ Name = "Magnify.exe";  Desc = "Magnifier" }
)

foreach ($tool in $accessibilityTools) {
    $toolPath = "C:\Windows\System32\$($tool.Name)"
    try {
        # Remove IFEO debugger hijacks first
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($tool.Name)"
        if (Test-Path $ifeoPath) {
            $debugger = Get-ItemProperty -Path $ifeoPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($debugger) {
                Remove-ItemProperty -Path $ifeoPath -Name "Debugger" -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed IFEO debugger hijack for $($tool.Name): $($debugger.Debugger)" -Level "WARNING" -LogFile $LogFile
            }
        }

        # Take ownership and delete the binary
        if (Test-Path $toolPath) {
            takeown /F $toolPath /A 2>&1 | Out-Null
            icacls $toolPath /grant administrators:F 2>&1 | Out-Null
            Remove-Item $toolPath -Force -ErrorAction Stop
            Write-Log -Message "Removed $($tool.Desc) ($($tool.Name))." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to remove $($tool.Name): $_" -Level "WARNING" -LogFile $LogFile
    }
}

# Disable Sticky Keys shortcut via registry
Set-RegistryValue -Path "HKU:\.DEFAULT\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type String 2>$null

# --- 5. Clean Startup Items (PROMPTED) ---
Write-Log -Message "=== Startup Item Cleanup ===" -Level "INFO" -LogFile $LogFile
Write-Host "IMPACT: Cleaning startup items removes ALL auto-start programs, scheduled tasks, and startup scripts." -ForegroundColor Yellow
Write-Host "  This is aggressive but removes common persistence mechanisms." -ForegroundColor Yellow
$cleanStartup = Read-Host "Clean startup items and persistence locations? [y/n]"

if ($cleanStartup -eq 'y') {
    try {
        # Startup folders
        $startupPaths = @(
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*",
            "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
        )
        foreach ($path in $startupPaths) {
            Remove-Item -Force $path -ErrorAction SilentlyContinue
        }
        Write-Log -Message "Startup folders cleaned." -Level "SUCCESS" -LogFile $LogFile

        # Autoexec.bat
        if (Test-Path "C:\autoexec.bat") {
            Remove-Item -Force "C:\autoexec.bat" -ErrorAction SilentlyContinue
            Write-Log -Message "Removed autoexec.bat." -Level "SUCCESS" -LogFile $LogFile
        }

        # Group Policy startup/shutdown scripts
        $gpPaths = @(
            "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup",
            "C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown",
            "C:\Windows\System32\GroupPolicy\User\Scripts\Logon",
            "C:\Windows\System32\GroupPolicy\User\Scripts\Logoff"
        )
        foreach ($path in $gpPaths) {
            if (Test-Path $path) {
                Remove-Item -Force -Recurse $path -ErrorAction SilentlyContinue
            }
        }
        Write-Log -Message "Group Policy startup/shutdown scripts cleaned." -Level "SUCCESS" -LogFile $LogFile

        # Registry Run keys
        $runKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($props) {
                    $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | Select-Object -ExpandProperty Name
                    foreach ($propName in $propNames) {
                        Write-Log -Message "Removing Run key: $key\$propName = $($props.$propName)" -Level "WARNING" -LogFile $LogFile
                        Remove-ItemProperty -Path $key -Name $propName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        Write-Log -Message "Registry Run keys cleaned." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed during startup cleanup: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "Startup cleanup skipped per user request." -Level "INFO" -LogFile $LogFile
}

# --- 6. Scheduled Task Audit (PROMPTED) ---
Write-Log -Message "=== Scheduled Task Audit ===" -Level "INFO" -LogFile $LogFile
Write-Host "IMPACT: Removing scheduled tasks is aggressive. Some may be required for scoring." -ForegroundColor Yellow
Write-Host "  [1] Remove ALL non-system scheduled tasks" -ForegroundColor Yellow
Write-Host "  [2] List tasks and choose which to disable" -ForegroundColor Yellow
Write-Host "  [3] Skip" -ForegroundColor Yellow
$taskChoice = Read-Host "Scheduled task action [1/2/3]"

switch ($taskChoice) {
    "1" {
        try {
            Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log -Message "Non-system scheduled tasks removed." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to remove scheduled tasks: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    "2" {
        try {
            $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" })
            if ($tasks.Count -gt 0) {
                Write-Host "`nNon-system scheduled tasks:" -ForegroundColor Cyan
                for ($i = 0; $i -lt $tasks.Count; $i++) {
                    $t = $tasks[$i]
                    Write-Host "  [$($i + 1)] [$($t.State)] $($t.TaskPath)$($t.TaskName)" -ForegroundColor Yellow
                    foreach ($action in $t.Actions) {
                        if ($action.Execute) {
                            Write-Host "       Execute: $($action.Execute) $($action.Arguments)" -ForegroundColor Gray
                        }
                    }
                }
                Write-Host ""
                Write-Host "Enter task numbers to DISABLE (comma-separated, e.g. 1,3,5), 'all' for all, or 'none' to skip:" -ForegroundColor Cyan
                $selection = Read-Host "Selection"

                $toDisable = @()
                if ($selection -match '^[Aa]ll$') {
                    $toDisable = $tasks
                } elseif ($selection -notmatch '^[Nn]one$' -and $selection.Trim() -ne '') {
                    $indices = $selection -split ',' | ForEach-Object {
                        $num = $_.Trim() -as [int]
                        if ($num -and $num -ge 1 -and $num -le $tasks.Count) { $num - 1 }
                    }
                    $toDisable = $indices | ForEach-Object { $tasks[$_] }
                }

                if ($toDisable.Count -gt 0) {
                    foreach ($task in $toDisable) {
                        try {
                            $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null
                            Write-Log -Message "Disabled scheduled task: $($task.TaskPath)$($task.TaskName)" -Level "SUCCESS" -LogFile $LogFile
                        } catch {
                            Write-Log -Message "Failed to disable task $($task.TaskPath)$($task.TaskName): $_" -Level "ERROR" -LogFile $LogFile
                        }
                    }
                    Write-Host ""
                    Write-Host "Do you also want to REMOVE (unregister) these disabled tasks? [y/n]" -ForegroundColor Yellow
                    $removeChoice = Read-Host "Remove"
                    if ($removeChoice -match '^[Yy]$') {
                        foreach ($task in $toDisable) {
                            try {
                                $task | Unregister-ScheduledTask -Confirm:$false -ErrorAction Stop
                                Write-Log -Message "Removed scheduled task: $($task.TaskPath)$($task.TaskName)" -Level "SUCCESS" -LogFile $LogFile
                            } catch {
                                Write-Log -Message "Failed to remove task $($task.TaskPath)$($task.TaskName): $_" -Level "ERROR" -LogFile $LogFile
                            }
                        }
                    }
                } else {
                    Write-Log -Message "Scheduled task audit complete (no tasks selected)." -Level "INFO" -LogFile $LogFile
                }
            } else {
                Write-Host "No non-system scheduled tasks found." -ForegroundColor Green
                Write-Log -Message "Scheduled task audit complete -- no non-system tasks found." -Level "INFO" -LogFile $LogFile
            }
        } catch {
            Write-Log -Message "Failed to list scheduled tasks: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    default {
        Write-Log -Message "Scheduled task audit skipped." -Level "INFO" -LogFile $LogFile
    }
}

# --- 7. Disable Cortana & Cloud Search ---
Write-Log -Message "Disabling Cortana and cloud search..." -Level "INFO" -LogFile $LogFile
try {
    $searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-RegistryValue -Path $searchPath -Name "AllowCloudSearch" -Value 0 -Type DWord
    Set-RegistryValue -Path $searchPath -Name "AllowCortana" -Value 0 -Type DWord
    Set-RegistryValue -Path $searchPath -Name "AllowCortanaAboveLock" -Value 0 -Type DWord
    Set-RegistryValue -Path $searchPath -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
    Set-RegistryValue -Path $searchPath -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord
    Set-RegistryValue -Path $searchPath -Name "DisableWebSearch" -Value 1 -Type DWord
    Write-Log -Message "Cortana and cloud search disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Cortana: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 8. Lock Screen Hardening ---
Write-Log -Message "Hardening lock screen..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type DWord
    Write-Log -Message "Lock screen hardened (camera, slideshow, input personalization disabled)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to harden lock screen: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9. Show File Extensions & Hidden Files ---
Write-Log -Message "Configuring Explorer to show file extensions and hidden files..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" -Name "CheckedValue" -Value 0 -Type DWord
    Write-Log -Message "Explorer configured to show file extensions and hidden/system files." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure Explorer: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 10. System File Integrity Check ---
if (-not $SkipSFC) {
    $runSfc = $null
    while ($runSfc -notmatch '^[YyNn]$') {
        $runSfc = Read-Host "Run SFC /scannow? This can take 5+ minutes (Y/N)"
    }
    if ($runSfc -match '^[Yy]$') {
        Write-Log -Message "Running system file integrity checks..." -Level "INFO" -LogFile $LogFile
        try {
            Write-Host "Running SFC /scannow (this may produce output)..." -ForegroundColor Cyan
            sfc /scannow 2>&1 | Out-Null
            Write-Log -Message "SFC scan completed." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "SFC scan failed or produced errors: $_" -Level "WARNING" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "SFC scan skipped by user." -Level "INFO" -LogFile $LogFile
    }
} else {
    Write-Log -Message "SFC scan skipped (SkipSFC flag set)." -Level "INFO" -LogFile $LogFile
}

$runDism = $null
while ($runDism -notmatch '^[YyNn]$') {
    $runDism = Read-Host "Run DISM /RestoreHealth? This can take 10-20+ minutes (Y/N)"
}
if ($runDism -match '^[Yy]$') {
    Write-Log -Message "Running DISM RestoreHealth..." -Level "INFO" -LogFile $LogFile
    try {
        sc.exe config trustedinstaller start= auto 2>&1 | Out-Null
        Write-Host "Running DISM /Online /Cleanup-Image /RestoreHealth (this will take a while)..." -ForegroundColor Cyan
        DISM /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-Null
        Write-Log -Message "DISM RestoreHealth completed." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "DISM RestoreHealth failed: $_" -Level "WARNING" -LogFile $LogFile
    }
} else {
    Write-Log -Message "DISM RestoreHealth skipped by user." -Level "INFO" -LogFile $LogFile
}

# --- 11. Disable CMD System-Wide ---
Write-Log -Message "Disabling CMD access system-wide..." -Level "INFO" -LogFile $LogFile
try {
    # Value 1 = Disable CMD completely (interactive + inline) -- HKLM applies to all users
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableCMD" -Value 1 -Type DWord
    # AutoRun exit as fallback -- apply to default profile (all users) and current user
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "AutoRun" -Value "exit" -Type String
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Command Processor" -Name "AutoRun" -Value "exit" -Type String
    Write-Log -Message "CMD disabled system-wide (DisableCMD policy + AutoRun exit)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable CMD: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12. Kernel & Boot Security ---
Write-Log -Message "Applying kernel and boot security settings..." -Level "INFO" -LogFile $LogFile
try {
    # Disable test-signed kernel drivers
    bcdedit.exe /set TESTSIGNING OFF 2>&1 | Out-Null
    bcdedit.exe /set loadoptions ENABLE_INTEGRITY_CHECKS 2>&1 | Out-Null
    # Enforce driver signature verification
    bcdedit.exe /set nointegritychecks off 2>&1 | Out-Null
    Write-Log -Message "Test-signed drivers disabled, integrity checks enforced." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure boot security: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12a. Crash Dump & Recovery ---
Write-Log -Message "Configuring crash dump and recovery settings..." -Level "INFO" -LogFile $LogFile
try {
    # Disable crash dump generation (prevents memory dumping for credential theft)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Type DWord
    # Enable automatic reboot after crash
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value 1 -Type DWord
    Write-Log -Message "Crash dumps disabled, auto-reboot on crash enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure crash dump settings: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12b. Disable AlwaysInstallElevated ---
Write-Log -Message "Disabling AlwaysInstallElevated for Windows Installer..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Type DWord
    Write-Log -Message "AlwaysInstallElevated disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable AlwaysInstallElevated: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12c. Require Password on Wakeup ---
Write-Log -Message "Requiring password on wakeup..." -Level "INFO" -LogFile $LogFile
try {
    powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1 2>&1 | Out-Null
    Write-Log -Message "Password required on wakeup." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to set wakeup password requirement: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12d. Screen Saver Grace Period ---
Write-Log -Message "Setting screen saver grace period to 0..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value 0 -Type DWord
    Write-Log -Message "Screen saver grace period set to 0 seconds." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to set screen saver grace period: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12e. Reassociate Dangerous File Types to Notepad ---
Write-Log -Message "Reassociating dangerous file types to Notepad..." -Level "INFO" -LogFile $LogFile
try {
    $dangerousTypes = @("htafile", "wshfile", "wsffile", "batfile", "jsfile", "jsefile", "vbefile", "vbsfile")
    foreach ($ftype in $dangerousTypes) {
        cmd /c "ftype $ftype=`"%SystemRoot%\system32\NOTEPAD.EXE`" `"%1`"" 2>&1 | Out-Null
    }
    Write-Log -Message "Dangerous file types reassociated to Notepad." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to reassociate file types: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12f. Disable 8.3 Filename Creation ---
Write-Log -Message "Disabling 8.3 filename creation..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -Value 1 -Type DWord
    Write-Log -Message "8.3 filename creation disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable 8.3 filenames: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12g. Remove "Run As Different User" from Context Menus ---
Write-Log -Message "Removing 'Run As Different User' from context menus..." -Level "INFO" -LogFile $LogFile
try {
    $shellTypes = @("batfile", "cmdfile", "exefile", "mscfile")
    foreach ($st in $shellTypes) {
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Classes\$st\shell\runasuser" -Name "SuppressionPolicy" -Value 4096 -Type DWord
    }
    Write-Log -Message "'Run As Different User' removed from context menus." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to remove RunAsUser context menu: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12h. Explorer Hardening ---
Write-Log -Message "Applying Explorer hardening..." -Level "INFO" -LogFile $LogFile
try {
    # Enable heap termination on corruption for Explorer
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0 -Type DWord
    # Enable shell protocol protected mode
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value 0 -Type DWord
    # Strengthen default permissions of internal system objects
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord
    Write-Log -Message "Explorer hardening applied (heap termination, shell protocol, object permissions)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Explorer hardening: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12i. Disable Remote Registry Access Paths ---
Write-Log -Message "Clearing remote registry access paths..." -Level "INFO" -LogFile $LogFile
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" -Name "Machine" -Value ([string[]]@()) -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" -Name "Machine" -Value ([string[]]@()) -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Remote registry access paths cleared." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to clear remote registry paths: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12j. Disable RunOnce Key Processing ---
Write-Log -Message "Disabling RunOnce key processing..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableLocalMachineRunOnce" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableLocalMachineRunOnce" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableLocalMachineRunOnce" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableLocalMachineRunOnce" -Value 1 -Type DWord
    Write-Log -Message "RunOnce key processing disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable RunOnce processing: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12k. Reset Service Control Manager SDDL ---
Write-Log -Message "Resetting Service Control Manager SDDL..." -Level "INFO" -LogFile $LogFile
try {
    sc.exe sdset scmanager "D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)" 2>&1 | Out-Null
    Write-Log -Message "SCM SDDL reset to secure defaults." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to reset SCM SDDL: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12l. Enable SEHOP ---
Write-Log -Message "Enabling Structured Exception Handler Overwrite Protection (SEHOP)..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord
    Write-Log -Message "SEHOP enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable SEHOP: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12m. Early Launch Antimalware Boot-Start Driver ---
Write-Log -Message "Configuring early launch antimalware driver policy..." -Level "INFO" -LogFile $LogFile
try {
    # 3 = Good, unknown, and bad but critical
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -Type DWord
    Write-Log -Message "Early launch antimalware driver scan enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to configure ELAM: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12n. Block PsExec via IFEO ---
Write-Log -Message "Blocking PsExec via Image File Execution Options..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PSEXESVC.exe" -Name "Debugger" -Value "svchost.exe" -Type String
    Write-Log -Message "PsExec blocked via IFEO redirect." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to block PsExec: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12o. Disable Offline Files ---
Write-Log -Message "Disabling Offline Files (CSC)..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CSC" -Name "Start" -Value 4 -Type DWord
    Write-Log -Message "Offline Files service disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Offline Files: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12p. Disable UPnP ---
Write-Log -Message "Disabling UPnP..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" -Name "UPnPMode" -Value 2 -Type DWord
    Write-Log -Message "UPnP disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable UPnP: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12q. Disable DCOM ---
Write-Log -Message "Disabling DCOM..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\OLE" -Name "EnableDCOM" -Value "N" -Type String
    Write-Log -Message "DCOM disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable DCOM: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 12r. Ease of Access Registry Completions ---
Write-Log -Message "Hardening Ease of Access registry keys..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type String
    Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -Type String
    Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -Name "ShowTabletKeyboard" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" -Name "BrandingNeutral" -Value 8 -Type DWord
    Write-Log -Message "Ease of Access registry keys hardened." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to harden Ease of Access keys: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 13. Spectre/Meltdown Mitigations ---
Write-Log -Message "Applying Spectre/Meltdown CPU mitigations..." -Level "INFO" -LogFile $LogFile
try {
    $memMgmtPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    # CVE-2017-5715 (Spectre v2), CVE-2017-5753 (Spectre v1), CVE-2017-5754 (Meltdown)
    Set-RegistryValue -Path $memMgmtPath -Name "FeatureSettingsOverride" -Value 72 -Type DWord
    Set-RegistryValue -Path $memMgmtPath -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord
    # CVE-2018-3639 (Spectre v4 - Speculative Store Bypass)
    Set-RegistryValue -Path $memMgmtPath -Name "FeatureSettings" -Value 1 -Type DWord
    # CVE-2018-11091 (Microarchitectural Data Sampling - MDS)
    Set-RegistryValue -Path $memMgmtPath -Name "EnableCfg" -Value 1 -Type DWord
    # Extend mitigations to Hyper-V VMs
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name "MinVmVersionForCpuBasedMitigations" -Value "1.0" -Type String
    Write-Log -Message "Spectre/Meltdown/MDS mitigations applied (requires reboot)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Spectre/Meltdown mitigations: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 13. PowerShell Constrained Language Mode ---
Write-Log -Message "Enabling PowerShell Constrained Language Mode..." -Level "INFO" -LogFile $LogFile
try {
    # __PSLockdownPolicy=4 enforces Constrained Language Mode system-wide
    [System.Environment]::SetEnvironmentVariable("__PSLockdownPolicy", "4", "Machine")
    Write-Log -Message "PowerShell Constrained Language Mode enabled via environment variable (effective on new sessions)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable Constrained Language Mode: $_" -Level "ERROR" -LogFile $LogFile
}

Write-Log -Message "System Hardening module complete." -Level "SUCCESS" -LogFile $LogFile
