function New-RandomPassword {
    param (
        [int]$Length = 12
    )

    $upper   = (65..90   | ForEach-Object {[char]$_}) # A-Z
    $lower   = (97..122  | ForEach-Object {[char]$_}) # a-z
    $numbers = (48..57   | ForEach-Object {[char]$_}) # 0-9
    $special = "!@#$%^&*()-_=+[]{}<>?|".ToCharArray() # Special characters
    $all     = $upper + $lower + $numbers + $special

    $passwordArray = @(
        ($upper   | Get-Random -Count 1) +
        ($lower   | Get-Random -Count 1) +
        ($numbers | Get-Random -Count 1) +
        ($special | Get-Random -Count 1) +
        ($all     | Get-Random -Count ($Length - 4))
    )

    $passwordArray    = $passwordArray -join ''
    $shuffledPassword = ($passwordArray.ToCharArray() | Sort-Object {Get-Random}) -join ''
    $finalPassword = $shuffledPassword -replace '\s', ''

    return $finalPassword
}
