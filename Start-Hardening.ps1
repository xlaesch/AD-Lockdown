<#
.SYNOPSIS
    AD Hardening Controller Script
.DESCRIPTION
    Orchestrates the execution of hardening modules for Active Directory environments.
.PARAMETER ConfigFile
    Path to the configuration file (default: conf/defaults.json)
#>

param (
    [string]$ConfigFile = "conf/defaults.json"
)

$ScriptRoot = $PSScriptRoot
$LogDir = "$ScriptRoot/logs"
$LogFile = "$LogDir/hardening_$(Get-Date -Format 'yyyy-MM-dd').log"

# Ensure Log Directory Exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Import Functions
. "$ScriptRoot/src/functions/Write-Log.ps1"
. "$ScriptRoot/src/functions/Set-RegistryValue.ps1"
. "$ScriptRoot/src/functions/New-RandomPassword.ps1"

Write-Log -Message "=== Starting AD Hardening Process ===" -Level "INFO" -LogFile $LogFile

# Define Modules to Run
$Modules = @(
    "01_Account_Policies.ps1",
    "02_Network_Security.ps1",
    "03_Service_Hardening.ps1",
    "04_Audit_Logging.ps1",
    "05_Cert_Authority.ps1",
    "06_Firewall_Hardening.ps1"
)

foreach ($Module in $Modules) {
    $ModulePath = "$ScriptRoot/src/modules/$Module"
    if (Test-Path $ModulePath) {
        Write-Log -Message "Executing module: $Module" -Level "INFO" -LogFile $LogFile
        try {
            & $ModulePath -LogFile $LogFile
        }
        catch {
            Write-Log -Message "Error executing module $Module : $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Module not found: $Module" -Level "WARNING" -LogFile $LogFile
    }
}

Write-Log -Message "=== AD Hardening Process Complete ===" -Level "INFO" -LogFile $LogFile
