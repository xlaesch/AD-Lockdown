function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",

        [string]$LogFile
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"

    # Color coding for console output
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
    }

    if (-not [string]::IsNullOrWhiteSpace($LogFile)) {
        # Ensure directory exists
        $LogDir = Split-Path -Parent $LogFile
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
}
