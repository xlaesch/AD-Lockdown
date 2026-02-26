function Set-RegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$Value,

        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord", "Unknown")]
        [string]$Type = "DWord"
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
    catch {
        Write-Error "Failed to set registry value: $_"
    }
}
