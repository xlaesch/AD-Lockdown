param(
    [Parameter(Mandatory = $false)]
    [Alias("FilePath")]
    [string]$EncryptedPath,
    [string]$OutputPath,
    [switch]$RemoveEncrypted
)

$ScriptRoot = $PSScriptRoot
$SecretsDir = Join-Path $ScriptRoot "secrets"

# If no path provided, list files in secrets directory
if ([string]::IsNullOrEmpty($EncryptedPath)) {
    if (Test-Path $SecretsDir) {
        $EncryptedFiles = Get-ChildItem -Path $SecretsDir -Filter "*.enc" | Sort-Object Name
        
        if ($EncryptedFiles.Count -eq 0) {
            Write-Warning "No encrypted files found in $SecretsDir"
            return
        }

        Write-Host "Select a file to decrypt:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $EncryptedFiles.Count; $i++) {
            Write-Host "$($i+1): $($EncryptedFiles[$i].Name)"
        }

        do {
            $Selection = Read-Host "Enter number (1-$($EncryptedFiles.Count))"
            if ($Selection -match '^\d+$' -and $Selection -ge 1 -and $Selection -le $EncryptedFiles.Count) {
                $EncryptedPath = $EncryptedFiles[$Selection-1].FullName
                break
            }
            Write-Warning "Invalid selection. Please try again."
        } while ($true)
    }
    else {
        Write-Error "Secrets directory not found at $SecretsDir"
        return
    }
}

. "$ScriptRoot/src/functions/Unprotect-SecretsFile.ps1"

if ($EncryptedPath) {
    Unprotect-SecretsFile -FilePath $EncryptedPath -OutputPath $OutputPath -RemoveEncrypted:$RemoveEncrypted
}
