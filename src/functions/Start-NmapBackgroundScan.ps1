# Start-NmapBackgroundScan.ps1
# Uses bundled tools.zip nmap.exe (preferred), then launches a full nmap scan
# of localhost in a background process. Sets $global:NmapScanXmlPath
# so the caller can later invoke Invoke-NmapRuleCreator.ps1.
#
# Safe to call multiple times -- skips if a scan is already running.

param(
    [Parameter(Mandatory = $true)]
    [string]$LogFile
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/Write-Log.ps1"
}

# Guard: don't launch twice
if ($global:NmapScanXmlPath) {
    Write-Log -Message "Nmap background scan already launched -- skipping." -Level "INFO" -LogFile $LogFile
    return
}

Write-Log -Message "=== Dynamic Service Discovery (Nmap) ===" -Level "INFO" -LogFile $LogFile

# --- Locate nmap (prefer bundled tools.zip binary) ---
$nmapExe = $null
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$toolsDir = Join-Path $projectRoot "tools"
$toolsZip = Join-Path $projectRoot "tools.zip"

if (Test-Path $toolsZip) {
    if (-not (Test-Path $toolsDir)) {
        New-Item -Path $toolsDir -ItemType Directory -Force | Out-Null
    }

    $bundledNmap = Get-ChildItem -Path $toolsDir -Filter "nmap.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $bundledNmap) {
        Write-Log -Message "Extracting tools.zip to locate bundled nmap.exe..." -Level "INFO" -LogFile $LogFile
        try {
            Expand-Archive -Path $toolsZip -DestinationPath $toolsDir -Force
            Write-Log -Message "tools.zip extracted to $toolsDir" -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to extract tools.zip: $_" -Level "ERROR" -LogFile $LogFile
        }
        $bundledNmap = Get-ChildItem -Path $toolsDir -Filter "nmap.exe" -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if ($bundledNmap) {
        $nmapExe = $bundledNmap.FullName
        Write-Log -Message "Using bundled nmap binary: $nmapExe" -Level "INFO" -LogFile $LogFile
    } else {
        Write-Log -Message "Bundled nmap.exe was not found after extracting tools.zip." -Level "WARNING" -LogFile $LogFile
    }
} else {
    Write-Log -Message "tools.zip not found at $toolsZip." -Level "WARNING" -LogFile $LogFile
}

# Fallback: use existing local nmap install if bundled binary is unavailable.
if (-not $nmapExe) {
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        $nmapExe = (Get-Command nmap).Source
        Write-Log -Message "Using nmap from PATH: $nmapExe" -Level "INFO" -LogFile $LogFile
    } elseif (Test-Path "C:\Program Files (x86)\Nmap\nmap.exe") {
        $nmapExe = "C:\Program Files (x86)\Nmap\nmap.exe"
        Write-Log -Message "Using nmap from default install path: $nmapExe" -Level "INFO" -LogFile $LogFile
    } else {
        Write-Log -Message "No usable nmap executable found (bundled or local). Skipping dynamic scan." -Level "WARNING" -LogFile $LogFile
    }
}

if ($nmapExe -and -not (Test-Path $nmapExe)) {
    Write-Log -Message "Resolved nmap path does not exist: $nmapExe" -Level "ERROR" -LogFile $LogFile
    $nmapExe = $null
}

# --- Launch background scan ---
if ($nmapExe) {
    $global:NmapScanXmlPath = Join-Path $env:TEMP "nmap_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

    $scanScript = @"
try {
    & '$nmapExe' -sT -sU -sV -O -T4 -p- -oX '$($global:NmapScanXmlPath)' localhost 2>&1 | Out-Null
} catch {
    `$_ | Out-File '$($global:NmapScanXmlPath).err'
}
"@

    Write-Log -Message "Launching background nmap scan -> $($global:NmapScanXmlPath)" -Level "INFO" -LogFile $LogFile
    Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $scanScript -WindowStyle Hidden
    Write-Log -Message "Nmap scan running in background (full TCP+UDP, all ports). Results will be processed after all modules complete." -Level "INFO" -LogFile $LogFile
} else {
    Write-Log -Message "Nmap not available -- skipping dynamic service discovery." -Level "WARNING" -LogFile $LogFile
}
