<#
.SYNOPSIS
    Interactive State Restoration Script
.DESCRIPTION
    Restores system state from backups created by the hardening pipeline.
    Presents an interactive menu to selectively restore: GPOs, DNS zones,
    Firewall rules, Scheduled tasks, Services, and SYSVOL policies.
    AD (IFM) restoration requires DSRM and is guidance-only.
.EXAMPLE
    .\Restore-State.ps1
#>

$ScriptRoot = $PSScriptRoot
$LogDir = "$ScriptRoot/logs"
$LogFile = "$LogDir/restore_$(Get-Date -Format 'yyyy-MM-dd').log"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Import functions
. "$ScriptRoot/src/functions/Write-Log.ps1"

# ── Admin check ──────────────────────────────────────────────────────────────
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Attempting to elevate..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -Wait
    } catch {
        Write-Host "Failed to elevate: $_" -ForegroundColor Red
    }
    exit
}

# ── DC detection ─────────────────────────────────────────────────────────────
$IsDomainController = $null -ne (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")

Write-Log -Message "=== Starting State Restoration ===" -Level "INFO" -LogFile $LogFile
Write-Log -Message "Hostname: $env:COMPUTERNAME | DC: $IsDomainController" -Level "INFO" -LogFile $LogFile

$backupRoot = "C:\Program Files\Windows Mail_Backup"

if (-not (Test-Path $backupRoot)) {
    Write-Host "No backup directory found at $backupRoot" -ForegroundColor Red
    Write-Log -Message "Backup root not found: $backupRoot" -Level "ERROR" -LogFile $LogFile
    exit 1
}

# ── Discover available backup categories ─────────────────────────────────────
function Get-BackupSets {
    param([string]$Category, [string]$Pattern)
    $catPath = Join-Path $backupRoot $Category
    if (-not (Test-Path $catPath)) { return @() }
    return Get-ChildItem -Path $catPath -Filter $Pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
}

$RestoreOptions = @()
$RestoreDetails = @{}

# GPOs (DC only)
if ($IsDomainController) {
    $gpoDirs = Get-ChildItem -Path "$backupRoot\GPO" -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($gpoDirs) {
        $label = "GPOs ($($gpoDirs.Count) backup set(s) available)"
        $RestoreOptions += $label
        $RestoreDetails[$label] = @{ Category = "GPO"; Items = $gpoDirs }
    }
}

# DNS (DC only)
if ($IsDomainController) {
    $dnsFiles = Get-BackupSets -Category "DNS" -Pattern "*.dns"
    if ($dnsFiles) {
        $label = "DNS Zones ($($dnsFiles.Count) zone file(s) available)"
        $RestoreOptions += $label
        $RestoreDetails[$label] = @{ Category = "DNS"; Items = $dnsFiles }
    }
}

# SYSVOL (DC only)
if ($IsDomainController) {
    $sysvolDirs = Get-ChildItem -Path "$backupRoot\SYSVOL" -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($sysvolDirs) {
        $label = "SYSVOL Policies ($($sysvolDirs.Count) backup set(s) available)"
        $RestoreOptions += $label
        $RestoreDetails[$label] = @{ Category = "SYSVOL"; Items = $sysvolDirs }
    }
}

# Firewall
$fwFiles = Get-BackupSets -Category "Firewall" -Pattern "firewall_rules_*.xml"
if ($fwFiles) {
    $label = "Firewall Rules ($($fwFiles.Count) backup(s) available)"
    $RestoreOptions += $label
    $RestoreDetails[$label] = @{ Category = "Firewall"; Items = $fwFiles }
}

# Scheduled Tasks
$taskFiles = Get-BackupSets -Category "Tasks" -Pattern "scheduled_tasks_*.xml"
if ($taskFiles) {
    $label = "Scheduled Tasks ($($taskFiles.Count) backup(s) available)"
    $RestoreOptions += $label
    $RestoreDetails[$label] = @{ Category = "Tasks"; Items = $taskFiles }
}

# Services
$svcFiles = Get-BackupSets -Category "Services" -Pattern "services_*.csv"
if ($svcFiles) {
    $label = "Service StartTypes ($($svcFiles.Count) backup(s) available)"
    $RestoreOptions += $label
    $RestoreDetails[$label] = @{ Category = "Services"; Items = $svcFiles }
}

# AD (guidance only)
if ($IsDomainController) {
    $adDirs = Get-ChildItem -Path "$backupRoot\AD" -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($adDirs) {
        $label = "Active Directory [GUIDANCE ONLY] ($($adDirs.Count) IFM backup(s))"
        $RestoreOptions += $label
        $RestoreDetails[$label] = @{ Category = "AD"; Items = $adDirs }
    }
}

if ($RestoreOptions.Count -eq 0) {
    Write-Host "No restorable backups found in $backupRoot" -ForegroundColor Yellow
    Write-Log -Message "No restorable backups found." -Level "WARNING" -LogFile $LogFile
    exit
}

# ── Interactive selection ────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              State Restoration - Select Categories          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

for ($i = 0; $i -lt $RestoreOptions.Count; $i++) {
    Write-Host "  [$($i + 1)] $($RestoreOptions[$i])"
}
Write-Host ""

$prompt = "Select categories to restore (comma-separated numbers, 'all', or 'q' to quit)"
while ($true) {
    $selection = Read-Host $prompt

    if ($selection -match '^\s*(q|quit|exit)\s*$') {
        Write-Host "Restoration cancelled." -ForegroundColor Yellow
        exit
    }

    if ($selection -match '^\s*all\s*$') {
        $selectedOptions = $RestoreOptions
        break
    }

    $indices = $selection -split "[,\s]+" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^\d+$' } |
        ForEach-Object { [int]$_ - 1 } |
        Where-Object { $_ -ge 0 -and $_ -lt $RestoreOptions.Count } |
        Sort-Object -Unique

    if ($indices.Count -gt 0) {
        $selectedOptions = $indices | ForEach-Object { $RestoreOptions[$_] }
        break
    }

    Write-Warning "Invalid selection. Enter numbers from 1 to $($RestoreOptions.Count)."
}

Write-Host ""
Write-Log -Message "Categories selected for restoration: $($selectedOptions -join ', ')" -Level "INFO" -LogFile $LogFile

# ── Helper: pick a backup set when multiple exist ────────────────────────────
function Select-BackupSet {
    param(
        [string]$CategoryName,
        [array]$Items
    )

    if ($Items.Count -eq 1) {
        Write-Host "  Using: $($Items[0].Name)" -ForegroundColor Gray
        return $Items[0]
    }

    Write-Host ""
    Write-Host "  Multiple $CategoryName backups found. Select one:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $ts = $Items[$i].LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "    [$($i + 1)] $($Items[$i].Name)  ($ts)"
    }

    while ($true) {
        $pick = Read-Host "  Selection (1-$($Items.Count))"
        if ($pick -match '^\d+$') {
            $idx = [int]$pick - 1
            if ($idx -ge 0 -and $idx -lt $Items.Count) {
                return $Items[$idx]
            }
        }
        Write-Warning "  Invalid. Enter a number from 1 to $($Items.Count)."
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# RESTORE HANDLERS
# ═════════════════════════════════════════════════════════════════════════════

foreach ($option in $selectedOptions) {
    $detail = $RestoreDetails[$option]
    $category = $detail.Category

    Write-Host ""
    Write-Host "── Restoring: $category ──" -ForegroundColor Cyan

    switch ($category) {

        # ── GPO Restore ──────────────────────────────────────────────────
        "GPO" {
            $backupSet = Select-BackupSet -CategoryName "GPO" -Items $detail.Items
            if (-not $backupSet) { continue }

            Write-Log -Message "Restoring GPOs from $($backupSet.FullName)..." -Level "INFO" -LogFile $LogFile
            try {
                Import-Module GroupPolicy -ErrorAction Stop

                $gpoBackups = Get-ChildItem -Path $backupSet.FullName -Directory -ErrorAction Stop
                $restoredCount = 0

                foreach ($gpoDir in $gpoBackups) {
                    try {
                        # Each Backup-GPO creates a GUID-named subfolder with a bkupInfo.xml
                        $bkupInfo = Get-ChildItem -Path $gpoDir.FullName -Filter "bkupInfo.xml" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($bkupInfo) {
                            $backupId = $gpoDir.Name
                            Restore-GPO -BackupId $backupId -Path $backupSet.FullName -ErrorAction Stop | Out-Null
                            Write-Log -Message "  Restored GPO backup: $backupId" -Level "SUCCESS" -LogFile $LogFile
                            $restoredCount++
                        }
                    } catch {
                        Write-Log -Message "  Failed to restore GPO from $($gpoDir.Name): $_" -Level "WARNING" -LogFile $LogFile
                    }
                }

                gpupdate /force 2>&1 | Out-Null
                Write-Log -Message "GPO restore completed: $restoredCount GPOs restored." -Level "SUCCESS" -LogFile $LogFile
                Write-Host "  Restored $restoredCount GPOs." -ForegroundColor Green
            } catch {
                Write-Log -Message "GPO restore failed: $_" -Level "ERROR" -LogFile $LogFile
                Write-Host "  GPO restore failed: $_" -ForegroundColor Red
            }
        }

        # ── DNS Restore ──────────────────────────────────────────────────
        "DNS" {
            Write-Log -Message "Restoring DNS zones..." -Level "INFO" -LogFile $LogFile
            try {
                Import-Module DnsServer -ErrorAction Stop

                $dnsBackupPath = Join-Path $backupRoot "DNS"
                $dnsFiles = Get-ChildItem -Path $dnsBackupPath -Filter "*.dns" -ErrorAction Stop
                $restoredCount = 0

                foreach ($dnsFile in $dnsFiles) {
                    $zoneName = $dnsFile.BaseName
                    try {
                        # Copy zone file to DNS directory
                        $dnsDataPath = "$env:SystemRoot\System32\dns\$($dnsFile.Name)"
                        Copy-Item -Path $dnsFile.FullName -Destination $dnsDataPath -Force

                        # Check if zone already exists
                        $existingZone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue
                        if ($existingZone) {
                            # Reload by removing and re-adding
                            Write-Log -Message "  Zone $zoneName exists, reloading from file..." -Level "INFO" -LogFile $LogFile
                            dnscmd /ZoneReload $zoneName 2>&1 | Out-Null
                        } else {
                            # Add as primary file-backed zone
                            dnscmd /ZoneAdd $zoneName /Primary /file $($dnsFile.Name) /load 2>&1 | Out-Null
                        }
                        Write-Log -Message "  Restored DNS zone: $zoneName" -Level "SUCCESS" -LogFile $LogFile
                        $restoredCount++
                    } catch {
                        Write-Log -Message "  Failed to restore DNS zone $zoneName : $_" -Level "WARNING" -LogFile $LogFile
                    }
                }

                Write-Log -Message "DNS restore completed: $restoredCount zones." -Level "SUCCESS" -LogFile $LogFile
                Write-Host "  Restored $restoredCount DNS zones." -ForegroundColor Green
            } catch {
                Write-Log -Message "DNS restore failed: $_" -Level "ERROR" -LogFile $LogFile
                Write-Host "  DNS restore failed: $_" -ForegroundColor Red
            }
        }

        # ── SYSVOL Restore ───────────────────────────────────────────────
        "SYSVOL" {
            $backupSet = Select-BackupSet -CategoryName "SYSVOL" -Items $detail.Items
            if (-not $backupSet) { continue }

            Write-Log -Message "Restoring SYSVOL policies from $($backupSet.FullName)..." -Level "INFO" -LogFile $LogFile
            try {
                $domain = (Get-ADDomain).DNSRoot
                $sysvolDest = "C:\Windows\SYSVOL\sysvol\$domain\Policies"

                if (Test-Path $sysvolDest) {
                    Copy-Item -Path "$($backupSet.FullName)\*" -Destination $sysvolDest -Recurse -Force -ErrorAction Stop
                    Write-Log -Message "SYSVOL policies restored to $sysvolDest" -Level "SUCCESS" -LogFile $LogFile
                    Write-Host "  SYSVOL policies restored." -ForegroundColor Green
                } else {
                    Write-Log -Message "SYSVOL destination not found: $sysvolDest" -Level "ERROR" -LogFile $LogFile
                    Write-Host "  SYSVOL destination path not found." -ForegroundColor Red
                }
            } catch {
                Write-Log -Message "SYSVOL restore failed: $_" -Level "ERROR" -LogFile $LogFile
                Write-Host "  SYSVOL restore failed: $_" -ForegroundColor Red
            }
        }

        # ── Firewall Restore ────────────────────────────────────────────
        "Firewall" {
            $backupFile = Select-BackupSet -CategoryName "Firewall" -Items $detail.Items
            if (-not $backupFile) { continue }

            Write-Log -Message "Restoring firewall rules from $($backupFile.Name)..." -Level "INFO" -LogFile $LogFile
            Write-Host "  This will remove all current firewall rules and replace them." -ForegroundColor Yellow
            $confirmFw = Read-Host "  Proceed? [y/n]"
            if ($confirmFw -eq 'y') {
                try {
                    $rules = Import-Clixml -Path $backupFile.FullName -ErrorAction Stop

                    # Remove existing rules
                    Get-NetFirewallRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue

                    $restoredCount = 0
                    foreach ($rule in $rules) {
                        try {
                            $params = @{
                                Name        = $rule.Name
                                DisplayName = $rule.DisplayName
                                Direction   = $rule.Direction.ToString()
                                Action      = $rule.Action.ToString()
                                Enabled     = $rule.Enabled.ToString()
                            }
                            if ($rule.Profile)     { $params.Profile     = $rule.Profile.ToString() }
                            if ($rule.Description) { $params.Description = $rule.Description }

                            New-NetFirewallRule @params -ErrorAction SilentlyContinue | Out-Null
                            $restoredCount++
                        } catch {
                            # Skip rules that fail (duplicates, invalid params)
                        }
                    }

                    # Restore profiles if available
                    $profileBaseName = $backupFile.Name -replace 'firewall_rules_', 'firewall_profiles_'
                    $profileFile = Join-Path $backupFile.DirectoryName $profileBaseName
                    if (Test-Path $profileFile) {
                        $profiles = Import-Clixml -Path $profileFile
                        foreach ($prof in $profiles) {
                            Set-NetFirewallProfile -Name $prof.Name `
                                -DefaultInboundAction $prof.DefaultInboundAction.ToString() `
                                -DefaultOutboundAction $prof.DefaultOutboundAction.ToString() `
                                -Enabled $prof.Enabled.ToString() -ErrorAction SilentlyContinue
                        }
                        Write-Log -Message "  Firewall profiles restored." -Level "SUCCESS" -LogFile $LogFile
                    }

                    Write-Log -Message "Firewall restore completed: $restoredCount rules restored." -Level "SUCCESS" -LogFile $LogFile
                    Write-Host "  Restored $restoredCount firewall rules." -ForegroundColor Green
                } catch {
                    Write-Log -Message "Firewall restore failed: $_" -Level "ERROR" -LogFile $LogFile
                    Write-Host "  Firewall restore failed: $_" -ForegroundColor Red
                }
            } else {
                Write-Log -Message "Firewall restore skipped by operator." -Level "INFO" -LogFile $LogFile
            }
        }

        # ── Scheduled Tasks Restore ─────────────────────────────────────
        "Tasks" {
            $backupFile = Select-BackupSet -CategoryName "Tasks" -Items $detail.Items
            if (-not $backupFile) { continue }

            Write-Log -Message "Restoring scheduled tasks from $($backupFile.Name)..." -Level "INFO" -LogFile $LogFile
            Write-Host "  This will re-register tasks from the backup. Existing tasks are not removed." -ForegroundColor Yellow
            $confirmTasks = Read-Host "  Proceed? [y/n]"
            if ($confirmTasks -eq 'y') {
                try {
                    $tasks = Import-Clixml -Path $backupFile.FullName -ErrorAction Stop
                    $restoredCount = 0

                    foreach ($task in $tasks) {
                        try {
                            # Only restore non-Microsoft tasks
                            if ($task.TaskPath -like "\Microsoft\*") { continue }

                            $existingTask = Get-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
                            if (-not $existingTask) {
                                # Export XML from backup and re-register
                                $xmlPath = "$env:TEMP\task_restore_$($task.TaskName).xml"
                                try {
                                    Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop |
                                        Out-File -FilePath $xmlPath -Encoding UTF8
                                    Register-ScheduledTask -Xml (Get-Content $xmlPath -Raw) -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                                    $restoredCount++
                                    Write-Log -Message "  Restored task: $($task.TaskPath)$($task.TaskName)" -Level "SUCCESS" -LogFile $LogFile
                                } finally {
                                    Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
                                }
                            } else {
                                Write-Log -Message "  Task already exists, skipping: $($task.TaskName)" -Level "INFO" -LogFile $LogFile
                            }
                        } catch {
                            Write-Log -Message "  Failed to restore task $($task.TaskName): $_" -Level "WARNING" -LogFile $LogFile
                        }
                    }

                    Write-Log -Message "Task restore completed: $restoredCount tasks restored." -Level "SUCCESS" -LogFile $LogFile
                    Write-Host "  Restored $restoredCount scheduled tasks." -ForegroundColor Green
                } catch {
                    Write-Log -Message "Task restore failed: $_" -Level "ERROR" -LogFile $LogFile
                    Write-Host "  Task restore failed: $_" -ForegroundColor Red
                }
            } else {
                Write-Log -Message "Task restore skipped by operator." -Level "INFO" -LogFile $LogFile
            }
        }

        # ── Services Restore ────────────────────────────────────────────
        "Services" {
            $backupFile = Select-BackupSet -CategoryName "Services" -Items $detail.Items
            if (-not $backupFile) { continue }

            Write-Log -Message "Restoring service StartTypes from $($backupFile.Name)..." -Level "INFO" -LogFile $LogFile
            try {
                $services = Import-Csv -Path $backupFile.FullName -ErrorAction Stop
                $restoredCount = 0
                $failedCount = 0

                foreach ($svc in $services) {
                    try {
                        $currentSvc = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
                        if ($currentSvc -and $currentSvc.StartType -ne $svc.StartType) {
                            Set-Service -Name $svc.Name -StartupType $svc.StartType -ErrorAction Stop
                            $restoredCount++
                        }
                    } catch {
                        $failedCount++
                    }
                }

                Write-Log -Message "Services restore completed: $restoredCount StartTypes changed, $failedCount failed." -Level "SUCCESS" -LogFile $LogFile
                Write-Host "  Restored $restoredCount service StartTypes ($failedCount failed)." -ForegroundColor Green
            } catch {
                Write-Log -Message "Services restore failed: $_" -Level "ERROR" -LogFile $LogFile
                Write-Host "  Services restore failed: $_" -ForegroundColor Red
            }
        }

        # ── AD Guidance ─────────────────────────────────────────────────
        "AD" {
            Write-Host ""
            Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
            Write-Host "  ║  Active Directory restore requires DSRM (Directory      ║" -ForegroundColor Yellow
            Write-Host "  ║  Services Restore Mode). This cannot be automated        ║" -ForegroundColor Yellow
            Write-Host "  ║  on a running domain controller.                         ║" -ForegroundColor Yellow
            Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
            Write-Host "  ║  Available IFM backups:                                  ║" -ForegroundColor Yellow
            Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

            foreach ($adDir in $detail.Items) {
                $ts = $adDir.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "    - $($adDir.FullName)  ($ts)" -ForegroundColor Gray
            }

            Write-Host ""
            Write-Host "  To restore:" -ForegroundColor Yellow
            Write-Host "    1. Boot into DSRM (bcdedit /set safeboot dsrepair)" -ForegroundColor White
            Write-Host "    2. Use ntdsutil: 'activate instance ntds' > 'authoritative restore'" -ForegroundColor White
            Write-Host "    3. Or promote a new DC using IFM: Install-ADDSDomainController -InstallationMediaPath <path>" -ForegroundColor White
            Write-Host ""

            Write-Log -Message "AD restore guidance displayed. IFM backups at: $($detail.Items | ForEach-Object { $_.FullName })" -Level "INFO" -LogFile $LogFile
        }
    }
}

Write-Host ""
Write-Log -Message "=== State Restoration Complete ===" -Level "SUCCESS" -LogFile $LogFile
Write-Host "Restoration complete. Review log at: $LogFile" -ForegroundColor Green
