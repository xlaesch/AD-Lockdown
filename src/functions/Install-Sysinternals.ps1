function Install-Sysinternals {
    param (
        [string]$DestinationPath = "C:\Sysinternals",
        [string]$SourceZipPath = (Join-Path $PSScriptRoot "..\\..\\tools.zip"),
        [string]$LogFile
    )

    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # Check if PsExec exists to avoid overwriting in use files or redundant downloads
    if (Test-Path (Join-Path $DestinationPath "PsExec.exe")) {
        if ($LogFile) { Write-Log -Message "Sysinternals (PsExec) already installed at $DestinationPath. Skipping download." -Level "INFO" -LogFile $LogFile }
        return
    }

    try {
        if (-not (Test-Path $SourceZipPath)) {
            if ($LogFile) { Write-Log -Message "Sysinternals bundle not found at $SourceZipPath. Skipping install." -Level "WARNING" -LogFile $LogFile }
            return
        }

        if ($LogFile) { Write-Log -Message "Extracting Sysinternals bundle from $SourceZipPath..." -Level "INFO" -LogFile $LogFile }
        Expand-Archive -Path $SourceZipPath -DestinationPath $DestinationPath -Force
        if ($LogFile) { Write-Log -Message "Sysinternals bundle extracted successfully." -Level "INFO" -LogFile $LogFile }
    }
    catch {
        if ($LogFile) { Write-Log -Message "Failed to install PSTools: $_" -Level "ERROR" -LogFile $LogFile }
        throw $_
    }
}
