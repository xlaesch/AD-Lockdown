# 14_EDR_Deployment.ps1
# Deploys local EDR: Sysmon (kernel-level telemetry) + BLUESPAWN (active threat monitor)

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

Write-Log -Message "Starting Local EDR Deployment (Sysmon + BLUESPAWN)..." -Level "INFO" -LogFile $LogFile

# ============================================================
# --- 1. Install / Update Sysmon ---
# ============================================================
Write-Log -Message "Deploying Sysmon for endpoint telemetry..." -Level "INFO" -LogFile $LogFile

$ToolsDir         = "$PSScriptRoot/../../tools"
$SysmonConfigPath = "$ToolsDir/sysmonconfig.xml"

# Locate Sysmon binary directly in tools/ (prefer 64-bit)
$SysmonExePath = $null
$SysmonServiceName = $null

if (Test-Path "$ToolsDir/Sysmon64.exe") {
    $SysmonExePath     = "$ToolsDir/Sysmon64.exe"
    $SysmonServiceName = "Sysmon64"
} elseif (Test-Path "$ToolsDir/Sysmon.exe") {
    $SysmonExePath     = "$ToolsDir/Sysmon.exe"
    $SysmonServiceName = "Sysmon"
}

if (-not $SysmonExePath) {
    Write-Log -Message "No Sysmon executable found in $ToolsDir. Skipping Sysmon deployment." -Level "WARNING" -LogFile $LogFile
} else {
    try {
        $SysmonInstalled = Get-Service -Name $SysmonServiceName -ErrorAction SilentlyContinue

        # Build config argument if config file exists
        $ConfigArg = @()
        if (Test-Path $SysmonConfigPath) {
            $ConfigArg = @("-i", $SysmonConfigPath)
            Write-Log -Message "Using Sysmon config: $SysmonConfigPath" -Level "INFO" -LogFile $LogFile
        } else {
            $ConfigArg = @("-i")
            Write-Log -Message "No sysmonconfig.xml found. Installing Sysmon with default configuration." -Level "WARNING" -LogFile $LogFile
        }

        if ($SysmonInstalled) {
            # Sysmon already installed -- update configuration
            Write-Log -Message "Sysmon service '$SysmonServiceName' already exists. Updating configuration..." -Level "INFO" -LogFile $LogFile
            if (Test-Path $SysmonConfigPath) {
                & $SysmonExePath -c $SysmonConfigPath -accepteula 2>&1 | Out-Null
            } else {
                Write-Log -Message "Sysmon already installed and no config to apply. Skipping update." -Level "INFO" -LogFile $LogFile
            }
            Write-Log -Message "Sysmon configuration updated." -Level "SUCCESS" -LogFile $LogFile
        } else {
            # Fresh install
            Write-Log -Message "Installing Sysmon ($(Split-Path $SysmonExePath -Leaf))..." -Level "INFO" -LogFile $LogFile
            $InstallArgs = @("-accepteula") + $ConfigArg
            & $SysmonExePath @InstallArgs 2>&1 | Out-Null
            Write-Log -Message "Sysmon installation command completed." -Level "INFO" -LogFile $LogFile
        }

        # Verify the service is running
        Start-Sleep -Seconds 2
        $SvcCheck = Get-Service -Name $SysmonServiceName -ErrorAction SilentlyContinue
        if ($SvcCheck -and $SvcCheck.Status -eq 'Running') {
            Write-Log -Message "Sysmon service '$SysmonServiceName' is running. Events will appear in: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational" -Level "SUCCESS" -LogFile $LogFile
        } elseif ($SvcCheck) {
            Write-Log -Message "Sysmon service exists but status is: $($SvcCheck.Status). Attempting to start..." -Level "WARNING" -LogFile $LogFile
            Start-Service -Name $SysmonServiceName -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            $SvcRecheck = Get-Service -Name $SysmonServiceName -ErrorAction SilentlyContinue
            if ($SvcRecheck.Status -eq 'Running') {
                Write-Log -Message "Sysmon service started successfully." -Level "SUCCESS" -LogFile $LogFile
            } else {
                Write-Log -Message "Failed to start Sysmon service. Status: $($SvcRecheck.Status)" -Level "ERROR" -LogFile $LogFile
            }
        } else {
            Write-Log -Message "Sysmon service '$SysmonServiceName' not found after installation. Installation may have failed." -Level "ERROR" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed during Sysmon deployment: $_" -Level "ERROR" -LogFile $LogFile
    }
}

# ============================================================
# --- 2. Launch BLUESPAWN in Monitor Mode ---
# ============================================================
Write-Log -Message "Deploying BLUESPAWN threat monitor..." -Level "INFO" -LogFile $LogFile

$BluespawnExePath = "$PSScriptRoot/../../tools/BLUESPAWN-client-x64.exe"
$LogsDir          = "$PSScriptRoot/../../logs"
$BluespawnLogFile = "$LogsDir/bluespawn_$(Get-Date -Format 'yyyy-MM-dd').log"

if (-not (Test-Path $BluespawnExePath)) {
    Write-Log -Message "BLUESPAWN-client-x64.exe not found at $BluespawnExePath. Skipping BLUESPAWN deployment." -Level "WARNING" -LogFile $LogFile
} else {
    try {
        # Check if BLUESPAWN is already running
        $ExistingProcess = Get-Process -Name "BLUESPAWN-client-x64" -ErrorAction SilentlyContinue
        if ($ExistingProcess) {
            Write-Log -Message "BLUESPAWN is already running (PID: $($ExistingProcess.Id -join ', ')). Skipping launch." -Level "INFO" -LogFile $LogFile
        } else {
            # Ensure logs directory exists
            if (-not (Test-Path $LogsDir)) {
                New-Item -Path $LogsDir -ItemType Directory -Force | Out-Null
            }

            Write-Log -Message "Starting BLUESPAWN in monitor mode..." -Level "INFO" -LogFile $LogFile
            Write-Log -Message "BLUESPAWN log output: $BluespawnLogFile" -Level "INFO" -LogFile $LogFile

            # Launch BLUESPAWN in monitor mode as a hidden background process
            $BluespawnProcess = Start-Process -FilePath $BluespawnExePath `
                -ArgumentList "--monitor", "--log", $BluespawnLogFile `
                -WindowStyle Hidden `
                -PassThru `
                -ErrorAction Stop

            Start-Sleep -Seconds 2

            # Verify the process is running
            if ($BluespawnProcess -and -not $BluespawnProcess.HasExited) {
                Write-Log -Message "BLUESPAWN is running in monitor mode (PID: $($BluespawnProcess.Id))." -Level "SUCCESS" -LogFile $LogFile
            } else {
                Write-Log -Message "BLUESPAWN process started but may have exited. Check $BluespawnLogFile for details." -Level "WARNING" -LogFile $LogFile
            }
        }
    } catch {
        Write-Log -Message "Failed to launch BLUESPAWN: $_" -Level "ERROR" -LogFile $LogFile
    }
}

# ============================================================
# --- 3. Deployment Verification Summary ---
# ============================================================
Write-Log -Message "--- EDR Deployment Summary ---" -Level "INFO" -LogFile $LogFile

# Sysmon status -- check both service names
$SysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $SysmonSvc) { $SysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
if ($SysmonSvc -and $SysmonSvc.Status -eq 'Running') {
    Write-Log -Message "  [Sysmon]    ACTIVE  -- Service '$($SysmonSvc.Name)' running. Logs: Event Viewer > Sysmon/Operational" -Level "SUCCESS" -LogFile $LogFile
} elseif ($SysmonSvc) {
    Write-Log -Message "  [Sysmon]    WARNING -- Service exists but status: $($SysmonSvc.Status)" -Level "WARNING" -LogFile $LogFile
} else {
    Write-Log -Message "  [Sysmon]    NOT DEPLOYED -- Service not found." -Level "WARNING" -LogFile $LogFile
}

# BLUESPAWN status
$BluespawnProc = Get-Process -Name "BLUESPAWN-client-x64" -ErrorAction SilentlyContinue
if ($BluespawnProc) {
    Write-Log -Message "  [BLUESPAWN] ACTIVE  -- PID: $($BluespawnProc.Id -join ', '). Log: $BluespawnLogFile" -Level "SUCCESS" -LogFile $LogFile
} else {
    Write-Log -Message "  [BLUESPAWN] NOT RUNNING -- Process not found." -Level "WARNING" -LogFile $LogFile
}

Write-Log -Message "Local EDR Deployment module completed." -Level "INFO" -LogFile $LogFile
