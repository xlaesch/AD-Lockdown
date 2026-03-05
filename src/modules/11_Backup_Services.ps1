# 11_Backup_Services.ps1
# Comprehensive backup: GPOs, DNS, AD (IFM), SYSVOL, IIS, CA,
# Firewall rules, Scheduled tasks, and running services.
# DC-specific items (GPO, DNS, AD, SYSVOL) are skipped on non-DC machines.
# IIS and CA backups run only when those roles are installed.
# Universal items (Firewall, Tasks, Services) run on all machines.
# Supports a -Phase parameter for automatic pre/post hardening snapshots.

param(
    [string]$LogFile,
    [bool]$IsDomainController = $global:IsDomainController,
    [ValidateSet("Pre", "Post", "Manual")]
    [string]$Phase = "Manual"
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

Write-Log -Message "Starting Backup Services (Phase: $Phase)..." -Level "INFO" -LogFile $LogFile

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$phaseLabel = "${Phase}_${timestamp}"

# --- 1. Create Backup Directory Structure ---
Write-Log -Message "Creating backup directory structure..." -Level "INFO" -LogFile $LogFile
$backupRoot = "C:\Program Files\Windows Mail_Backup"
try {
    $subDirs = @("DNS", "AD", "SYSVOL", "GPO", "IIS", "CA", "Firewall", "Tasks", "Services")
    foreach ($dir in $subDirs) {
        $path = Join-Path $backupRoot $dir
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }
    }
    Write-Log -Message "Backup directories created under $backupRoot." -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to create backup directories: $_" -Level "ERROR" -LogFile $LogFile
    return
}

# ═════════════════════════════════════════════════════════════════════════════
# DC-SPECIFIC BACKUPS
# ═════════════════════════════════════════════════════════════════════════════

if ($IsDomainController) {

    # --- 2. GPO Backup (Backup-GPO for every domain GPO) ---
    Write-Log -Message "Backing up all domain GPOs..." -Level "INFO" -LogFile $LogFile
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoBackupPath = Join-Path $backupRoot "GPO\$phaseLabel"
        New-Item -Path $gpoBackupPath -ItemType Directory -Force | Out-Null

        $allGPOs = Get-GPO -All -ErrorAction Stop
        $gpoCount = 0
        foreach ($gpo in $allGPOs) {
            try {
                Backup-GPO -Guid $gpo.Id -Path $gpoBackupPath -ErrorAction Stop | Out-Null
                $gpoCount++
            } catch {
                Write-Log -Message "Failed to backup GPO '$($gpo.DisplayName)': $_" -Level "WARNING" -LogFile $LogFile
            }
        }
        Write-Log -Message "GPO backup completed: $gpoCount GPOs saved to $gpoBackupPath" -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to backup GPOs: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 3. DNS Zone Backup ---
    Write-Log -Message "Backing up DNS zones..." -Level "INFO" -LogFile $LogFile
    $dnsBackupPath = Join-Path $backupRoot "DNS"
    try {
        Import-Module DnsServer -ErrorAction Stop

        $zones = Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq "Primary" }
        $exportedCount = 0

        foreach ($zone in $zones) {
            try {
                $zoneName = $zone.ZoneName
                $exportFileName = "$zoneName.dns"

                dnscmd /ZoneExport $zoneName $exportFileName 2>&1 | Out-Null

                $dnsDataPath = "$env:SystemRoot\System32\dns\$exportFileName"
                $backupFilePath = "$dnsBackupPath\$exportFileName"

                if (Test-Path $dnsDataPath) {
                    Copy-Item -Path $dnsDataPath -Destination $backupFilePath -Force -ErrorAction Stop
                    Write-Log -Message "Exported DNS zone: $zoneName to $backupFilePath" -Level "SUCCESS" -LogFile $LogFile
                    $exportedCount++
                }
                else {
                    Write-Log -Message "DNS export file not found for zone: $zoneName" -Level "WARNING" -LogFile $LogFile
                }
            }
            catch {
                Write-Log -Message "Failed to export DNS zone $($zone.ZoneName): $_" -Level "WARNING" -LogFile $LogFile
            }
        }

        Write-Log -Message "DNS backup completed. Exported $exportedCount zones." -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to backup DNS zones: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 4. Active Directory Backup (IFM - Install From Media) ---
    Write-Log -Message "Creating Active Directory IFM backup..." -Level "INFO" -LogFile $LogFile
    try {
        $adBackupPath = Join-Path $backupRoot "AD"
        $adBackupFullPath = "$adBackupPath\ADBackup_$phaseLabel"

        New-Item -Path $adBackupFullPath -ItemType Directory -Force | Out-Null

        $ntdsutilScript = @"
activate instance ntds
ifm
create full "$adBackupFullPath"
quit
quit
"@

        Write-Log -Message "Running ntdsutil to create IFM backup (this may take several minutes)..." -Level "INFO" -LogFile $LogFile

        $ntdsutilScript | ntdsutil 2>&1 | Out-Null

        if (Test-Path "$adBackupFullPath\Active Directory") {
            $backupSize = (Get-ChildItem -Path $adBackupFullPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
            Write-Log -Message "AD IFM backup created at: $adBackupFullPath (Size: $([math]::Round($backupSize, 2)) MB)" -Level "SUCCESS" -LogFile $LogFile
        }
        else {
            Write-Log -Message "AD backup directory structure not found. Backup may have failed." -Level "ERROR" -LogFile $LogFile
        }
    }
    catch {
        Write-Log -Message "Failed to create AD backup: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 5. SYSVOL Backup (Critical for GPO recovery) ---
    Write-Log -Message "Backing up SYSVOL policies..." -Level "INFO" -LogFile $LogFile
    try {
        $sysvolBackupPath = Join-Path $backupRoot "SYSVOL"

        $domain = (Get-ADDomain).DNSRoot
        $sysvolSource = "C:\Windows\SYSVOL\sysvol\$domain\Policies"

        if (Test-Path $sysvolSource) {
            $sysvolBackupDest = "$sysvolBackupPath\Policies_$phaseLabel"
            Copy-Item -Path $sysvolSource -Destination $sysvolBackupDest -Recurse -Force -ErrorAction Stop
            Write-Log -Message "SYSVOL Policies backed up to: $sysvolBackupDest" -Level "SUCCESS" -LogFile $LogFile
        }
        else {
            Write-Log -Message "SYSVOL source path not found: $sysvolSource" -Level "WARNING" -LogFile $LogFile
        }
    }
    catch {
        Write-Log -Message "Failed to backup SYSVOL: $_" -Level "ERROR" -LogFile $LogFile
    }

} else {
    Write-Log -Message "Skipping DC-specific backups (GPO, DNS, AD, SYSVOL) -- not a Domain Controller." -Level "INFO" -LogFile $LogFile
}

# ═════════════════════════════════════════════════════════════════════════════
# ROLE-SPECIFIC BACKUPS (IIS, CA — only when installed)
# ═════════════════════════════════════════════════════════════════════════════

# --- 6. IIS Configuration Backup ---
$iisInstalled = (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue).Installed -eq $true
if ($iisInstalled) {
    Write-Log -Message "Backing up IIS configuration..." -Level "INFO" -LogFile $LogFile
    try {
        $iisBackupPath = Join-Path $backupRoot "IIS\IIS_$phaseLabel"
        New-Item -Path $iisBackupPath -ItemType Directory -Force | Out-Null

        # Backup applicationHost.config (master IIS config)
        $appHostConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
        if (Test-Path $appHostConfig) {
            Copy-Item -Path $appHostConfig -Destination "$iisBackupPath\applicationHost.config" -Force
            Write-Log -Message "Backed up applicationHost.config" -Level "SUCCESS" -LogFile $LogFile
        }

        # Backup administration.config and redirection.config
        foreach ($cfgFile in @("administration.config", "redirection.config")) {
            $cfgPath = "$env:SystemRoot\System32\inetsrv\config\$cfgFile"
            if (Test-Path $cfgPath) {
                Copy-Item -Path $cfgPath -Destination "$iisBackupPath\$cfgFile" -Force
            }
        }

        # Backup web.config from each site's physical path
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-Website -ErrorAction SilentlyContinue
        $siteCount = 0
        foreach ($site in $sites) {
            $siteName = $site.Name -replace '[\\/:*?"<>|]', '_'
            $siteDir = Join-Path $iisBackupPath "Sites\$siteName"
            New-Item -Path $siteDir -ItemType Directory -Force | Out-Null

            # Export site config
            $site | Export-Clixml -Path "$siteDir\site_config.xml" -Force

            # Copy web.config if it exists
            $physPath = $site.PhysicalPath
            if ($physPath -and (Test-Path "$physPath\web.config")) {
                Copy-Item -Path "$physPath\web.config" -Destination "$siteDir\web.config" -Force
            }
            $siteCount++
        }

        # Use appcmd to create a named backup
        $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
        if (Test-Path $appcmd) {
            & $appcmd add backup "Backup_$phaseLabel" 2>&1 | Out-Null
            Write-Log -Message "Created IIS appcmd backup: Backup_$phaseLabel" -Level "SUCCESS" -LogFile $LogFile
        }

        Write-Log -Message "IIS backup completed: $siteCount sites backed up to $iisBackupPath" -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to backup IIS configuration: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "Skipping IIS backup -- Web-Server role not installed." -Level "INFO" -LogFile $LogFile
}

# --- 7. Certificate Authority (CA) Backup ---
$caInstalled = (Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue).Installed -eq $true
if ($caInstalled) {
    Write-Log -Message "Backing up Certificate Authority..." -Level "INFO" -LogFile $LogFile
    try {
        $caBackupPath = Join-Path $backupRoot "CA\CA_$phaseLabel"
        New-Item -Path $caBackupPath -ItemType Directory -Force | Out-Null

        # Backup CA database and logs using certutil
        $caDbBackupPath = Join-Path $caBackupPath "Database"
        New-Item -Path $caDbBackupPath -ItemType Directory -Force | Out-Null
        $certutilResult = & certutil -backup $caDbBackupPath 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Message "CA database backed up to $caDbBackupPath" -Level "SUCCESS" -LogFile $LogFile
        } else {
            Write-Log -Message "certutil -backup returned exit code $LASTEXITCODE. Output: $certutilResult" -Level "WARNING" -LogFile $LogFile
        }

        # Export CA configuration from registry
        $caRegPath = "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
        $caRegBackup = Join-Path $caBackupPath "CA_Registry_$phaseLabel.reg"
        & reg export $caRegPath $caRegBackup /y 2>&1 | Out-Null
        if (Test-Path $caRegBackup) {
            Write-Log -Message "CA registry configuration exported to $caRegBackup" -Level "SUCCESS" -LogFile $LogFile
        }

        # Backup CA templates list
        try {
            $templates = & certutil -catemplates 2>&1
            $templatesFile = Join-Path $caBackupPath "CA_Templates_$phaseLabel.txt"
            $templates | Out-File -FilePath $templatesFile -Encoding UTF8 -Force
            Write-Log -Message "CA templates list saved to $templatesFile" -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Could not export CA templates: $_" -Level "WARNING" -LogFile $LogFile
        }

        # Backup CA certificate
        try {
            $caCertPath = Join-Path $caBackupPath "CACert_$phaseLabel.cer"
            & certutil -ca.cert $caCertPath 2>&1 | Out-Null
            if (Test-Path $caCertPath) {
                Write-Log -Message "CA certificate exported to $caCertPath" -Level "SUCCESS" -LogFile $LogFile
            }
        } catch {
            Write-Log -Message "Could not export CA certificate: $_" -Level "WARNING" -LogFile $LogFile
        }

        Write-Log -Message "Certificate Authority backup completed at $caBackupPath" -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to backup Certificate Authority: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Log -Message "Skipping CA backup -- ADCS-Cert-Authority role not installed." -Level "INFO" -LogFile $LogFile
}

# ═════════════════════════════════════════════════════════════════════════════
# UNIVERSAL BACKUPS (all machines)
# ═════════════════════════════════════════════════════════════════════════════

# --- 8. Firewall Rules Export ---
Write-Log -Message "Backing up firewall rules and profiles..." -Level "INFO" -LogFile $LogFile
try {
    $fwBackupPath = Join-Path $backupRoot "Firewall"

    $rulesFile = Join-Path $fwBackupPath "firewall_rules_$phaseLabel.xml"
    Get-NetFirewallRule | Export-Clixml -Path $rulesFile -Force -ErrorAction Stop

    $profilesFile = Join-Path $fwBackupPath "firewall_profiles_$phaseLabel.xml"
    Get-NetFirewallProfile | Export-Clixml -Path $profilesFile -Force -ErrorAction Stop

    $ruleCount = (Get-NetFirewallRule | Measure-Object).Count
    Write-Log -Message "Firewall backup completed: $ruleCount rules saved to $rulesFile" -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to backup firewall rules: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9. Scheduled Tasks Export ---
Write-Log -Message "Backing up scheduled tasks..." -Level "INFO" -LogFile $LogFile
try {
    $tasksBackupPath = Join-Path $backupRoot "Tasks"
    $tasksFile = Join-Path $tasksBackupPath "scheduled_tasks_$phaseLabel.xml"

    Get-ScheduledTask | Export-Clixml -Path $tasksFile -Force -ErrorAction Stop

    $taskCount = (Get-ScheduledTask | Measure-Object).Count
    Write-Log -Message "Scheduled tasks backup completed: $taskCount tasks saved to $tasksFile" -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to backup scheduled tasks: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 10. Running Services Export ---
Write-Log -Message "Backing up service configuration..." -Level "INFO" -LogFile $LogFile
try {
    $svcBackupPath = Join-Path $backupRoot "Services"
    $svcFile = Join-Path $svcBackupPath "services_$phaseLabel.csv"

    Get-Service | Select-Object Name, DisplayName, Status, StartType |
        Export-Csv -Path $svcFile -NoTypeInformation -Force -ErrorAction Stop

    $svcCount = (Get-Service | Measure-Object).Count
    Write-Log -Message "Services backup completed: $svcCount services saved to $svcFile" -Level "SUCCESS" -LogFile $LogFile
}
catch {
    Write-Log -Message "Failed to backup services: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 11. Backup Summary ---
Write-Log -Message "=== Backup Summary (Phase: $Phase) ===" -Level "INFO" -LogFile $LogFile
try {
    $totalSize = (Get-ChildItem -Path $backupRoot -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum / 1GB
    Write-Log -Message "Total backup size: $([math]::Round($totalSize, 2)) GB" -Level "INFO" -LogFile $LogFile
    Write-Log -Message "Backup location: $backupRoot" -Level "INFO" -LogFile $LogFile
}
catch {
    Write-Log -Message "Could not calculate backup size." -Level "WARNING" -LogFile $LogFile
}

Write-Log -Message "Backup Services module complete (Phase: $Phase)." -Level "SUCCESS" -LogFile $LogFile
