function Install-Sysinternals {
    param (
        [string]$DestinationPath = "C:\Sysinternals",
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

    $ZipPath = Join-Path $DestinationPath "PSTools.zip"
    $Url = "https://download.sysinternals.com/files/PSTools.zip"

    try {
        if ($LogFile) { Write-Log -Message "Downloading PSTools (PsExec) to $ZipPath..." -Level "INFO" -LogFile $LogFile }
        Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
        
        if ($LogFile) { Write-Log -Message "Extracting PSTools..." -Level "INFO" -LogFile $LogFile }
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
        
        Remove-Item -Path $ZipPath -Force
        
        if ($LogFile) { Write-Log -Message "PSTools installed successfully." -Level "INFO" -LogFile $LogFile }
    }
    catch {
        if ($LogFile) { Write-Log -Message "Failed to install PSTools: $_" -Level "ERROR" -LogFile $LogFile }
        throw $_
    }
}
