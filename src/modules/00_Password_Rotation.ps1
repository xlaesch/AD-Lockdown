# 00_Password_Rotation.ps1
# Handles password rotation for both domain (AD) and local accounts.
# On Domain Controllers: offers backup admin creation + domain user rotation.
# On all machines: offers local account password rotation.

param(
    [string]$LogFile,
    [bool]$IsDomainController = $global:IsDomainController
)

# Import helper functions if running standalone
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command New-RandomPassword -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/New-RandomPassword.ps1"
}
if (-not (Get-Command Select-ArrowMenu -ErrorAction SilentlyContinue)) {
    throw "Select-ArrowMenu is not loaded. Run Start-Hardening.ps1 or load the function before running this module."
}
if (-not (Get-Command Read-ConfirmedPassword -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Read-ConfirmedPassword.ps1"
}
if (-not (Get-Command Protect-SecretsFile -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Protect-SecretsFile.ps1"
}

Write-Log -Message "Starting Password Rotation..." -Level "INFO" -LogFile $LogFile

# ── Setup Secrets Directory & File ───────────────────────────────────────────
$SecretsDir = "$PSScriptRoot/../../secrets"
if (-not (Test-Path $SecretsDir)) { New-Item -ItemType Directory -Path $SecretsDir -Force | Out-Null }
$PasswordFile = "$SecretsDir/rotated_passwords_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').csv"
if (-not (Test-Path $PasswordFile)) {
    "AccountName,Type,Password" | Out-File -FilePath $PasswordFile -Encoding ASCII
}
Write-Log -Message "Passwords will be saved to $PasswordFile and encrypted after execution." -Level "INFO" -LogFile $LogFile
$global:RotatedPasswordFile = $PasswordFile

$serviceAccountPattern = '^svc'

# ═════════════════════════════════════════════════════════════════════════════
# DOMAIN PASSWORD ROTATION  (DC only)
# ═════════════════════════════════════════════════════════════════════════════
if ($IsDomainController) {

    # ── Create Backup Domain Admin ───────────────────────────────────────────
    Write-Log -Message "=== Backup Domain Admin Creation ===" -Level "INFO" -LogFile $LogFile

    $createBackupAdmin = Select-ArrowMenu -Title "Create a backup Domain Admin account?" -Options @("Yes", "No")
    if ($createBackupAdmin -eq "Yes") {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop

            $backupAdminName = Read-Host "Enter backup admin username (default: CCDCAdmin)"
            if ([string]::IsNullOrWhiteSpace($backupAdminName)) {
                $backupAdminName = "CCDCAdmin"
            }

            $existingAccount = Get-ADUser -Filter "SamAccountName -eq '$backupAdminName'" -ErrorAction SilentlyContinue
            if ($existingAccount) {
                Write-Log -Message "Account '$backupAdminName' already exists. Resetting password and ensuring group memberships." -Level "WARNING" -LogFile $LogFile
                $backupPassword = New-RandomPassword -Length 24
                $secureBackupPassword = ConvertTo-SecureString -String $backupPassword -AsPlainText -Force
                Set-ADAccountPassword -Identity $backupAdminName -NewPassword $secureBackupPassword -Reset
                Enable-ADAccount -Identity $backupAdminName -ErrorAction SilentlyContinue
            } else {
                $backupPassword = New-RandomPassword -Length 24
                $secureBackupPassword = ConvertTo-SecureString -String $backupPassword -AsPlainText -Force
                $domainDN = (Get-ADDomain).DistinguishedName
                New-ADUser -Name $backupAdminName `
                           -SamAccountName $backupAdminName `
                           -UserPrincipalName "$backupAdminName@$((Get-ADDomain).DNSRoot)" `
                           -AccountPassword $secureBackupPassword `
                           -Enabled $true `
                           -PasswordNeverExpires $true `
                           -CannotChangePassword $false `
                           -Description "CCDC Backup Domain Admin - failsafe account" `
                           -Path "CN=Users,$domainDN"
                Write-Log -Message "Created backup admin account: $backupAdminName" -Level "SUCCESS" -LogFile $LogFile
            }

            $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Group Policy Creator Owners")
            foreach ($group in $privilegedGroups) {
                try {
                    Add-ADGroupMember -Identity $group -Members $backupAdminName -ErrorAction Stop
                    Write-Log -Message "Added '$backupAdminName' to '$group'." -Level "SUCCESS" -LogFile $LogFile
                } catch {
                    if ($_.Exception.Message -match "already a member") {
                        Write-Log -Message "'$backupAdminName' is already a member of '$group'." -Level "INFO" -LogFile $LogFile
                    } else {
                        Write-Log -Message "Failed to add '$backupAdminName' to '$group': $_" -Level "ERROR" -LogFile $LogFile
                    }
                }
            }

            "$backupAdminName,Domain,$backupPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
            Write-Host "Backup admin '$backupAdminName' created/updated. Credentials saved to secrets file." -ForegroundColor Green
            Write-Log -Message "Backup admin credentials written to $PasswordFile" -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to create backup Domain Admin: $_" -Level "ERROR" -LogFile $LogFile
            Write-Warning "Backup admin creation failed. See log for details."
        }
    } else {
        Write-Log -Message "Skipped backup Domain Admin creation per user request." -Level "INFO" -LogFile $LogFile
    }

    # ── Domain User Password Rotation ────────────────────────────────────────
    $domainRotationOptions = @(
        "Rotate ALL domain user passwords",
        "Rotate selected domain user accounts",
        "Skip domain password rotation"
    )

    $rotationChoice = Select-ArrowMenu -Title "Domain password rotation options" -Options $domainRotationOptions
    if (-not $rotationChoice) {
        $rotationChoice = "Skip domain password rotation"
    }

    switch ($rotationChoice) {
        "Rotate ALL domain user passwords" {
            Write-Log -Message "Rotating ALL Domain User Passwords..." -Level "INFO" -LogFile $LogFile
            try {
                Import-Module ActiveDirectory -ErrorAction Stop

                $excludedGroups = @("Domain Admins", "Enterprise Admins")
                $excludedUsers = foreach ($group in $excludedGroups) {
                    Get-ADGroupMember -Identity $group -Recursive | Select-Object -ExpandProperty SamAccountName
                }
                $excludedUsers = $excludedUsers | Select-Object -Unique
                $excludedUsers += @("Administrator", "krbtgt", "Guest", "DefaultAccount")

                $users = Get-ADUser -Filter * | Where-Object {
                    ($_.SamAccountName -notin $excludedUsers) -and
                    ($_.SamAccountName -notmatch $serviceAccountPattern)
                }

                foreach ($user in $users) {
                    try {
                        $newPassword    = New-RandomPassword -Length 16
                        $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
                        Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset

                        Write-Log -Message "Password changed for domain user: $($user.SamAccountName)" -Level "SUCCESS" -LogFile $LogFile
                        Write-Host "$($user.SamAccountName) (Domain),$newPassword"
                        "$($user.SamAccountName),Domain,$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                    }
                    catch {
                        Write-Log -Message "Failed to set password for domain user $($user.SamAccountName): $_" -Level "ERROR" -LogFile $LogFile
                    }
                }
            }
            catch {
                Write-Log -Message "Failed to load ActiveDirectory module or query users: $_" -Level "ERROR" -LogFile $LogFile
            }
        }
        "Rotate selected domain user accounts" {
            Write-Log -Message "Rotating Selected Domain User Passwords..." -Level "INFO" -LogFile $LogFile
            try {
                Import-Module ActiveDirectory -ErrorAction Stop

                $userList = Get-ADUser -Filter * | Where-Object {
                    $_.SamAccountName -notmatch $serviceAccountPattern
                } | Sort-Object SamAccountName
                if (-not $userList) {
                    Write-Log -Message "No domain users found for selected-account rotation." -Level "WARNING" -LogFile $LogFile
                } else {
                    $userOptions = $userList | ForEach-Object { $_.SamAccountName }
                    $selectedUsers = Select-ArrowMenu -Title "Select domain accounts to rotate" -Options $userOptions -MultiSelect -AllowSelectAll

                    if (-not $selectedUsers -or $selectedUsers.Count -eq 0) {
                        Write-Log -Message "No domain users selected for password rotation." -Level "WARNING" -LogFile $LogFile
                    } else {
                        $preFilterCount = $selectedUsers.Count
                        $selectedUsers = $selectedUsers | Where-Object { $_ -notmatch $serviceAccountPattern }
                        if ($selectedUsers.Count -lt $preFilterCount) {
                            Write-Log -Message "Skipping service accounts that match pattern $serviceAccountPattern." -Level "INFO" -LogFile $LogFile
                        }
                        foreach ($samAccountName in $selectedUsers) {
                            try {
                                $newPassword    = New-RandomPassword -Length 16
                                $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
                                Set-ADAccountPassword -Identity $samAccountName -NewPassword $securePassword -Reset

                                Write-Log -Message "Password changed for domain user: $samAccountName" -Level "SUCCESS" -LogFile $LogFile
                                Write-Host "$samAccountName (Domain),$newPassword"
                                "$samAccountName,Domain,$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                            } catch {
                                Write-Log -Message "Failed to set password for domain user $($samAccountName): $_" -Level "ERROR" -LogFile $LogFile
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log -Message "Failed to load ActiveDirectory module or query users for selected rotation: $_" -Level "ERROR" -LogFile $LogFile
            }
        }
        default {
            Write-Log -Message "Skipping domain user password rotation per user request." -Level "INFO" -LogFile $LogFile
        }
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# LOCAL ACCOUNT PASSWORD ROTATION  (all machines)
# ═════════════════════════════════════════════════════════════════════════════
Write-Log -Message "=== Local Account Password Rotation ===" -Level "INFO" -LogFile $LogFile

$localRotationOptions = @(
    "Rotate ALL local user passwords",
    "Rotate selected local user accounts",
    "Skip local password rotation"
)

$localChoice = Select-ArrowMenu -Title "Local account password rotation options" -Options $localRotationOptions
if (-not $localChoice) {
    $localChoice = "Skip local password rotation"
}

# Built-in accounts that should never be rotated automatically
$builtinExclusions = @("Guest", "DefaultAccount", "WDAGUtilityAccount")

switch ($localChoice) {
    "Rotate ALL local user passwords" {
        Write-Log -Message "Rotating ALL Local User Passwords..." -Level "INFO" -LogFile $LogFile
        try {
            $localUsers = Get-LocalUser | Where-Object {
                ($_.Name -notin $builtinExclusions) -and
                ($_.Name -notmatch $serviceAccountPattern)
            }

            foreach ($user in $localUsers) {
                try {
                    $newPassword    = New-RandomPassword -Length 16
                    $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
                    Set-LocalUser -Name $user.Name -Password $securePassword

                    Write-Log -Message "Password changed for local user: $($user.Name)" -Level "SUCCESS" -LogFile $LogFile
                    Write-Host "$($user.Name) (Local),$newPassword"
                    "$($user.Name),Local,$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                }
                catch {
                    Write-Log -Message "Failed to set password for local user $($user.Name): $_" -Level "ERROR" -LogFile $LogFile
                }
            }
        }
        catch {
            Write-Log -Message "Failed to enumerate local users: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    "Rotate selected local user accounts" {
        Write-Log -Message "Rotating Selected Local User Passwords..." -Level "INFO" -LogFile $LogFile
        try {
            $localUsers = Get-LocalUser | Where-Object {
                $_.Name -notin $builtinExclusions
            } | Sort-Object Name

            if (-not $localUsers) {
                Write-Log -Message "No local users found for selected-account rotation." -Level "WARNING" -LogFile $LogFile
            } else {
                $userOptions = $localUsers | ForEach-Object { $_.Name }
                $selectedLocalUsers = Select-ArrowMenu -Title "Select local accounts to rotate" -Options $userOptions -MultiSelect -AllowSelectAll

                if (-not $selectedLocalUsers -or $selectedLocalUsers.Count -eq 0) {
                    Write-Log -Message "No local users selected for password rotation." -Level "WARNING" -LogFile $LogFile
                } else {
                    foreach ($userName in $selectedLocalUsers) {
                        try {
                            $newPassword    = New-RandomPassword -Length 16
                            $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
                            Set-LocalUser -Name $userName -Password $securePassword

                            Write-Log -Message "Password changed for local user: $userName" -Level "SUCCESS" -LogFile $LogFile
                            Write-Host "$userName (Local),$newPassword"
                            "$userName,Local,$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                        } catch {
                            Write-Log -Message "Failed to set password for local user $($userName): $_" -Level "ERROR" -LogFile $LogFile
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Failed to enumerate local users for selected rotation: $_" -Level "ERROR" -LogFile $LogFile
        }
    }
    default {
        Write-Log -Message "Skipping local password rotation per user request." -Level "INFO" -LogFile $LogFile
    }
}

# ── Secrets Encryption ───────────────────────────────────────────────────────
if (-not $global:SecretsEncryptionDeferred) {
    if (-not $global:SecretsFilePassword) {
        $global:SecretsFilePassword = Read-ConfirmedPassword -Prompt "Enter secrets file password" -ConfirmPrompt "Confirm secrets file password"
    }
    if ($global:SecretsFilePassword) {
        Protect-SecretsFile -FilePath $PasswordFile -Password $global:SecretsFilePassword -LogFile $LogFile
    }
}

Write-Log -Message "Password Rotation module complete." -Level "SUCCESS" -LogFile $LogFile
