<#
.SYNOPSIS
    Windows Hardening Controller Script
.DESCRIPTION
    Orchestrates the execution of hardening modules for all Windows machines
    in Red vs Blue (CCDC) competition environments. Automatically detects
    whether it is running on a Domain Controller and adjusts behavior
    accordingly -- running AD-specific modules on DCs and general hardening
    modules on workstations, member servers, IIS boxes, etc.
.PARAMETER IncludeModule
    Specify module name patterns to run (e.g. "Network", "Firewall").
.PARAMETER All
    Run all available modules without prompting for selection.
.PARAMETER DebugMode
    Skip admin/DC validation for testing purposes.
.PARAMETER ForceDC
    Force Domain Controller mode (override auto-detection).
.EXAMPLE
    .\Start-Hardening.ps1
    .\Start-Hardening.ps1 -All
    .\Start-Hardening.ps1 -ForceDC
    .\Start-Hardening.ps1 -IncludeModule "Network","Firewall"
#>

param (
    [string[]]$IncludeModule,
    [switch]$All,
    [switch]$ForceDC,
    [Alias("debug")]
    [switch]$DebugMode
)

$ScriptRoot = $PSScriptRoot
$LogDir = "$ScriptRoot/logs"
$LogFile = "$LogDir/hardening_$(Get-Date -Format 'yyyy-MM-dd').log"
$ToolsDir = Join-Path $ScriptRoot "tools"
$ToolsZip = Join-Path $ScriptRoot "tools.zip"

# Ensure Log Directory Exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Import Functions
. "$ScriptRoot/src/functions/Write-Log.ps1"
. "$ScriptRoot/src/functions/Set-RegistryValue.ps1"
. "$ScriptRoot/src/functions/New-RandomPassword.ps1"
. "$ScriptRoot/src/functions/Read-ConfirmedPassword.ps1"
. "$ScriptRoot/src/functions/Protect-SecretsFile.ps1"
. "$ScriptRoot/src/functions/Unprotect-SecretsFile.ps1"

# Flag so modules know they're running under the controller
$global:StartHardeningController = $true

# ── Domain Controller Detection ──────────────────────────────────────────────
# ProductType 2 = Domain Controller.  This flag is exposed globally so every
# module can branch on it without needing extra WMI queries of their own.
if ($ForceDC) {
    $global:IsDomainController = $true
    Write-Log -Message "ForceDC flag set: treating host as Domain Controller." -Level "WARNING" -LogFile $LogFile
} elseif ($DebugMode) {
    # In debug mode default to non-DC unless explicitly forced via -ForceDC.
    $global:IsDomainController = $false
    Write-Log -Message "Debug mode: IsDomainController forced to false (use -ForceDC to override)." -Level "WARNING" -LogFile $LogFile
} else {
    $global:IsDomainController = $null -ne (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")
}

if ($global:IsDomainController) {
    Write-Log -Message "Domain Controller detected -- AD hardening path will be used." -Level "INFO" -LogFile $LogFile
    Write-Host "Domain Controller detected." -ForegroundColor Yellow
} else {
    Write-Log -Message "Non-DC machine detected -- general hardening path will be used." -Level "INFO" -LogFile $LogFile
    Write-Host "Workstation / Member Server detected." -ForegroundColor Yellow
}

function Select-ArrowMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [string[]]$Options,
        [switch]$MultiSelect,
        [switch]$AllowSelectAll
    )

    if (-not $Options -or $Options.Count -eq 0) {
        return @()
    }

    Write-Host $Title -ForegroundColor Cyan
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "[$($i + 1)] $($Options[$i])"
    }

    if ($MultiSelect) {
        $prompt = "Selection (comma-separated numbers"
        if ($AllowSelectAll) {
            $prompt += " or 'all'"
        }
        $prompt += ", 'q' to cancel)"

        while ($true) {
            $selection = Read-Host $prompt
            if ($selection -match '^\s*(q|quit|exit)\s*$') {
                return @()
            }
            if ($AllowSelectAll -and $selection -match '^\s*all\s*$') {
                return $Options
            }

            $indices = $selection -split "[,\\s]+" |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^\d+$' } |
                ForEach-Object { [int]$_ - 1 } |
                Where-Object { $_ -ge 0 -and $_ -lt $Options.Count } |
                Sort-Object -Unique

            if ($indices.Count -gt 0) {
                return $indices | ForEach-Object { $Options[$_] }
            }

            Write-Warning "Invalid selection. Enter numbers from 1 to $($Options.Count)."
        }
    }

    $prompt = "Selection (number, 'q' to cancel)"
    while ($true) {
        $selection = Read-Host $prompt
        if ($selection -match '^\s*(q|quit|exit)\s*$') {
            return $null
        }
        if ($selection -match '^\d+$') {
            $index = [int]$selection - 1
            if ($index -ge 0 -and $index -lt $Options.Count) {
                return $Options[$index]
            }
        }

        Write-Warning "Invalid selection. Enter a number from 1 to $($Options.Count)."
    }
}

Write-Log -Message "=== Starting Windows Hardening Process ===" -Level "INFO" -LogFile $LogFile

# Check for Administrator privileges
if ($DebugMode) {
    Write-Log -Message "Debug mode enabled: skipping admin validation." -Level "WARNING" -LogFile $LogFile
} else {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $IsAdmin = $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $IsAdmin) {
        Write-Log -Message "This script must be run as Administrator. Attempting to elevate..." -Level "WARNING" -LogFile $LogFile

        $ScriptPath = $PSCommandPath
        $ArgsString = ""
        if ($All) { $ArgsString += " -All" }
        if ($IncludeModule) {
            $modules = $IncludeModule -join ","
            $ArgsString += " -IncludeModule $modules"
        }
        if ($DebugMode) { $ArgsString += " -DebugMode" }
        if ($ForceDC) { $ArgsString += " -ForceDC" }

        try {
            Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$ScriptPath`"$ArgsString" -Verb RunAs -Wait
            Write-Log -Message "Elevated process finished." -Level "INFO" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to elevate: $_" -Level "ERROR" -LogFile $LogFile
        }
        exit
    }
}

Write-Log -Message "Running as Administrator. Proceeding with hardening..." -Level "INFO" -LogFile $LogFile
Write-Log -Message "Hostname: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO" -LogFile $LogFile

# ── SYSTEM Elevation ─────────────────────────────────────────────────────────
# Some operations (Defender when Tamper Protection is active, SAM hive access)
# require NT AUTHORITY\SYSTEM. Offer to re-launch via PsExec -s.
$isSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18")

if ($isSystem) {
    Write-Log -Message "Running as SYSTEM." -Level "INFO" -LogFile $LogFile
    Write-Host "Running as SYSTEM." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Some hardening operations require SYSTEM privileges:" -ForegroundColor Yellow
    Write-Host "  - Windows Defender changes when Tamper Protection is active" -ForegroundColor Yellow
    Write-Host "  - SAM registry access (RID hijacking mitigation)" -ForegroundColor Yellow
    $elevateSystem = Read-Host "Re-launch as SYSTEM via PsExec? [y/n]"
    if ($elevateSystem -match '^(?i)y(es)?$') {
        # Locate PsExec in known locations first.
        $psExecPath = @(
            "$ScriptRoot\PsExec64.exe",
            "$ScriptRoot\PsExec.exe",
            (Join-Path $ToolsDir "PsExec64.exe"),
            (Join-Path $ToolsDir "PsExec.exe")
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1

        # If not already extracted, pull tools.zip before giving up.
        if (-not $psExecPath -and (Test-Path $ToolsZip)) {
            Write-Log -Message "PsExec not found in extracted tools. Extracting tools.zip..." -Level "INFO" -LogFile $LogFile
            try {
                if (-not (Test-Path $ToolsDir)) {
                    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
                }
                Expand-Archive -Path $ToolsZip -DestinationPath $ToolsDir -Force
                Write-Log -Message "tools.zip extracted to $ToolsDir for PsExec lookup." -Level "SUCCESS" -LogFile $LogFile
            } catch {
                Write-Log -Message "Failed to extract tools.zip for PsExec lookup: $_" -Level "ERROR" -LogFile $LogFile
            }
        }

        # Search recursively under tools after extraction.
        if (-not $psExecPath -and (Test-Path $ToolsDir)) {
            $psExecPath = Get-ChildItem -Path $ToolsDir -Filter "PsExec64.exe" -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty FullName -First 1
            if (-not $psExecPath) {
                $psExecPath = Get-ChildItem -Path $ToolsDir -Filter "PsExec.exe" -File -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty FullName -First 1
            }
        }
        if (-not $psExecPath) {
            $psExecPath = Get-Command PsExec64.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        }
        if (-not $psExecPath) {
            $psExecPath = Get-Command PsExec.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        }

        if ($psExecPath) {
            Write-Log -Message "Re-launching as SYSTEM via $psExecPath" -Level "INFO" -LogFile $LogFile
            $ScriptPath = $PSCommandPath
            $ArgsString = ""
            if ($All) { $ArgsString += " -All" }
            if ($IncludeModule) {
                $modules = $IncludeModule -join ","
                $ArgsString += " -IncludeModule $modules"
            }
            if ($DebugMode) { $ArgsString += " -DebugMode" }
            if ($ForceDC) { $ArgsString += " -ForceDC" }

            & $psExecPath -s -i -accepteula powershell.exe -ExecutionPolicy Bypass -File "$ScriptPath" $ArgsString
            exit
        } else {
            Write-Host "PsExec not found. Place PsExec.exe or PsExec64.exe in the script root or on PATH." -ForegroundColor Red
            Write-Host "Continuing as Administrator (some operations may fail)." -ForegroundColor Yellow
            Write-Log -Message "PsExec not found -- continuing as Administrator." -Level "WARNING" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "User declined SYSTEM elevation -- continuing as Administrator." -Level "INFO" -LogFile $LogFile
    }
}

# ── Early Nmap Background Scan ───────────────────────────────────────────────
# Prompt now so the scan runs in the background while all modules execute.
Write-Host ""
$runNmap = Read-Host "Run bundled nmap (from tools.zip) for dynamic service discovery? [y/n]"
if ($runNmap -match '^(?i)y(es)?$') {
    & "$ScriptRoot/src/functions/Start-NmapBackgroundScan.ps1" -LogFile $LogFile
}

# Define Available Modules
# Backup module is controller-managed via dedicated pre/post snapshot steps.
$AvailableModules = @(
    "00_Password_Rotation.ps1",
    "01_Local_Account_Policies.ps1",
    "02_Domain_Account_Policies.ps1",
    "03_Network_Security.ps1",
    "04_Service_Hardening.ps1",
    "05_Audit_Logging.ps1",
    "06_Windows_Defender.ps1",
    "07_Firewall_Hardening.ps1",
    "08_System_Hardening.ps1",
    "09_RDP_Security.ps1",
    "10_Cert_Authority.ps1",
    "12_Windows_Updates.ps1",
    "13_Post_Analysis.ps1",
    "14_EDR_Deployment.ps1"
)

# Validate modules exist
$ValidModules = @()
foreach ($mod in $AvailableModules) {
    $modPath = "$ScriptRoot/src/modules/$mod"
    if (Test-Path $modPath) {
        $ValidModules += $mod
    } else {
        Write-Log -Message "Module file not found, skipping: $mod" -Level "WARNING" -LogFile $LogFile
    }
}

$ModulesToExecute = @()

if ($All) {
    $ModulesToExecute = $ValidModules
}
elseif ($IncludeModule) {
    foreach ($m in $IncludeModule) {
        $match = $ValidModules | Where-Object { $_ -like "*$m*" }
        if ($match) {
            $ModulesToExecute += $match
        } else {
            Write-Warning "Module '$m' not found."
        }
    }
}
else {
    $ModulesToExecute = Select-ArrowMenu -Title "Select modules to run" -Options $ValidModules -MultiSelect -AllowSelectAll
}

# Remove duplicates
$ModulesToExecute = $ModulesToExecute | Select-Object -Unique

if ($ModulesToExecute.Count -eq 0) {
    Write-Warning "No modules selected. Exiting."
    exit
}

Write-Log -Message "Modules selected: $($ModulesToExecute -join ', ')" -Level "INFO" -LogFile $LogFile

# If any password-rotation module is selected, prompt for secrets encryption
# password up front so the module can defer encryption until all modules finish.
$SecretsModules = @("00_Password_Rotation.ps1", "02_Domain_Account_Policies.ps1")
if ($ModulesToExecute | Where-Object { $SecretsModules -contains $_ }) {
    $global:SecretsEncryptionDeferred = $true
    $global:SecretsFilePassword = Read-ConfirmedPassword -Prompt "Enter secrets file password" -ConfirmPrompt "Confirm secrets file password"
    Write-Log -Message "Secrets output will be encrypted after module execution." -Level "INFO" -LogFile $LogFile
}

# ── Pre-Hardening Backup ─────────────────────────────────────────────────────
Write-Log -Message "=== Running Pre-Hardening Backup ===" -Level "INFO" -LogFile $LogFile
try {
    $backupModule = "$ScriptRoot/src/modules/11_Backup_Services.ps1"
    if (Test-Path $backupModule) {
        & $backupModule -LogFile $LogFile -IsDomainController $global:IsDomainController -Phase "Pre"
    } else {
        Write-Log -Message "Backup module not found -- skipping pre-hardening backup." -Level "WARNING" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Pre-hardening backup failed: $_" -Level "ERROR" -LogFile $LogFile
}

foreach ($Module in $ModulesToExecute) {
    $ModulePath = "$ScriptRoot/src/modules/$Module"
    if (Test-Path $ModulePath) {
        Write-Log -Message "Executing module: $Module" -Level "INFO" -LogFile $LogFile
        try {
            & $ModulePath -LogFile $LogFile -IsDomainController $global:IsDomainController
        }
        catch {
            Write-Log -Message "Error executing module $Module : $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Module not found: $Module" -Level "WARNING" -LogFile $LogFile
    }
}

# ── Post-Hardening Backup ────────────────────────────────────────────────────
Write-Log -Message "=== Running Post-Hardening Backup ===" -Level "INFO" -LogFile $LogFile
try {
    $backupModule = "$ScriptRoot/src/modules/11_Backup_Services.ps1"
    if (Test-Path $backupModule) {
        & $backupModule -LogFile $LogFile -IsDomainController $global:IsDomainController -Phase "Post"
    } else {
        Write-Log -Message "Backup module not found -- skipping post-hardening backup." -Level "WARNING" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Post-hardening backup failed: $_" -Level "ERROR" -LogFile $LogFile
}

# Encrypt the secrets file if password rotation was run and encryption was deferred
if ($global:SecretsFilePassword -and $global:RotatedPasswordFile) {
    Protect-SecretsFile -FilePath $global:RotatedPasswordFile -Password $global:SecretsFilePassword -LogFile $LogFile
}

# Process nmap dynamic firewall rules if a tracked background scan is active or output exists
$hasNmapXmlPath = -not [string]::IsNullOrWhiteSpace($global:NmapScanXmlPath)
$hasRunningNmap = $null -ne (Get-Process -Name "nmap" -ErrorAction SilentlyContinue)
$hasNmapXmlFile = $hasNmapXmlPath -and (Test-Path $global:NmapScanXmlPath)

if ($hasNmapXmlPath -and -not $hasRunningNmap -and -not $hasNmapXmlFile) {
    Write-Log -Message "Stale nmap scan state detected (no running process and XML missing). Skipping dynamic firewall rule processing." -Level "WARNING" -LogFile $LogFile
    $global:NmapScanXmlPath = $null
    $hasNmapXmlPath = $false
}

if ($hasNmapXmlPath) {
    Write-Log -Message "Processing nmap dynamic firewall rules..." -Level "INFO" -LogFile $LogFile
    try {
        & "$ScriptRoot/src/functions/Invoke-NmapRuleCreator.ps1" `
            -XmlPath $global:NmapScanXmlPath `
            -TrustedNetwork $global:NmapTrustedNetwork `
            -LogFile $LogFile
    } catch {
        Write-Log -Message "Error running Invoke-NmapRuleCreator: $_" -Level "ERROR" -LogFile $LogFile
    }
} elseif ($hasRunningNmap) {
    Write-Log -Message "nmap process detected, but this run has no tracked XML path. Dynamic firewall rule processing skipped." -Level "WARNING" -LogFile $LogFile
}

# Offer to disable Constrained Language Mode if it was enabled during this run
$clmValue = [System.Environment]::GetEnvironmentVariable("__PSLockdownPolicy", "Machine")
if ($clmValue -eq "4") {
    Write-Host ""
    Write-Host "PowerShell Constrained Language Mode is currently ENABLED (Machine-level)." -ForegroundColor Yellow
    Write-Host "This restricts script execution and may interfere with administration tasks." -ForegroundColor Yellow
    $disableCLM = $null
    while ($disableCLM -notmatch '^[YyNn]$') {
        $disableCLM = Read-Host "Disable Constrained Language Mode? (Y/N)"
    }
    if ($disableCLM -match '^[Yy]$') {
        [System.Environment]::SetEnvironmentVariable("__PSLockdownPolicy", $null, "Machine")
        Write-Log -Message "PowerShell Constrained Language Mode disabled (Machine environment variable removed)." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "PowerShell Constrained Language Mode left enabled." -Level "INFO" -LogFile $LogFile
    }
}

Write-Log -Message "=== Windows Hardening Process Complete ===" -Level "INFO" -LogFile $LogFile
Write-Host "`nHardening complete. Review log at: $LogFile" -ForegroundColor Green
