# 00_Password_Rotation.ps1
# Handles manual and bulk domain user password rotation

param(
    [string]$LogFile
)

# Import helper functions if running standalone (optional check)
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

# Setup Secrets Directory & File
$SecretsDir = "$PSScriptRoot/../../secrets"
if (-not (Test-Path $SecretsDir)) { New-Item -ItemType Directory -Path $SecretsDir -Force | Out-Null }
$PasswordFile = "$SecretsDir/rotated_passwords_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').csv"
if (-not (Test-Path $PasswordFile)) {
    "SamAccountName,Password" | Out-File -FilePath $PasswordFile -Encoding ASCII
}
Write-Log -Message "Passwords will be saved to $PasswordFile and encrypted after execution." -Level "INFO" -LogFile $LogFile
$global:RotatedPasswordFile = $PasswordFile

# ── Create Backup Domain Admin ──────────────────────────────────────────────────
# Creates a highly privileged failsafe account in case the primary admin is
# locked out. The account is added to Domain Admins, Enterprise Admins,
# Schema Admins, and the built-in Administrators group.
Write-Log -Message "=== Backup Domain Admin Creation ===" -Level "INFO" -LogFile $LogFile

$createBackupAdmin = Select-ArrowMenu -Title "Create a backup Domain Admin account?" -Options @("Yes", "No")
if ($createBackupAdmin -eq "Yes") {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $backupAdminName = Read-Host "Enter backup admin username (default: CCDCAdmin)"
        if ([string]::IsNullOrWhiteSpace($backupAdminName)) {
            $backupAdminName = "CCDCAdmin"
        }

        # Check if the account already exists
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

        # Add to all high-privilege groups
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

        # Record credentials in secrets CSV
        "$backupAdminName,$backupPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
        Write-Host "Backup admin '$backupAdminName' created/updated. Credentials saved to secrets file." -ForegroundColor Green
        Write-Log -Message "Backup admin credentials written to $PasswordFile" -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to create backup Domain Admin: $_" -Level "ERROR" -LogFile $LogFile
        Write-Warning "Backup admin creation failed. See log for details."
    }
} else {
    Write-Log -Message "Skipped backup Domain Admin creation per user request." -Level "INFO" -LogFile $LogFile
}

# ── Password Rotation ───────────────────────────────────────────────────────────
$rotationOptions = @(
    "Rotate ALL domain user passwords",
    "Rotate selected domain user accounts",
    "Skip password rotation"
)

$rotationChoice = Select-ArrowMenu -Title "Password rotation options" -Options $rotationOptions
if (-not $rotationChoice) {
    $rotationChoice = "Skip password rotation"
}

$serviceAccountPattern = '^svc'

switch ($rotationChoice) {
    "Rotate ALL domain user passwords" {
        Write-Log -Message "Rotating Domain User Passwords..." -Level "INFO" -LogFile $LogFile
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

            $GroupUserMap = @{}

            foreach ($user in $users) {
                try {
                    $newPassword    = New-RandomPassword -Length 16
                    $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
                    Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset
                    
                    Write-Log -Message "Password changed for user: $($user.SamAccountName)" -Level "SUCCESS" -LogFile $LogFile
                    Write-Host "$($user.SamAccountName),$newPassword" # Output for operator visibility
                    "$($user.SamAccountName),$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                    
                    # Track group membership for reporting
                    $usersgroups = Get-ADPrincipalGroupMembership -Identity $user | Select-Object -ExpandProperty Name
                    if ($usersgroups) {
                        foreach ($groupName in $usersgroups) {
                            if(!($GroupUserMap.ContainsKey($groupName))) {
                                $GroupUserMap[$groupName] = New-Object System.Collections.ArrayList
                            }
                            $null = $GroupUserMap[$groupName].Add([PSCustomObject]@{
                                User     = $user.SamAccountName
                                Password = $newPassword
                            })
                        }
                    }
                } 
                catch {
                    Write-Log -Message "Failed to set password for user $($user.SamAccountName): $_" -Level "ERROR" -LogFile $LogFile
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
                $selectedUsers = Select-ArrowMenu -Title "Select accounts to rotate" -Options $userOptions -MultiSelect -AllowSelectAll

                if (-not $selectedUsers -or $selectedUsers.Count -eq 0) {
                    Write-Log -Message "No users selected for password rotation." -Level "WARNING" -LogFile $LogFile
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

                            Write-Log -Message "Password changed for user: $samAccountName" -Level "SUCCESS" -LogFile $LogFile
                            Write-Host "$samAccountName,$newPassword"
                            "$samAccountName,$newPassword" | Out-File -FilePath $PasswordFile -Append -Encoding ASCII
                        } catch {
                            Write-Log -Message "Failed to set password for user $($samAccountName): $_" -Level "ERROR" -LogFile $LogFile
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

if (-not $global:SecretsEncryptionDeferred) {
    if (-not $global:SecretsFilePassword) {
        $global:SecretsFilePassword = Read-ConfirmedPassword -Prompt "Enter secrets file password" -ConfirmPrompt "Confirm secrets file password"
    }
    if ($global:SecretsFilePassword) {
        Protect-SecretsFile -FilePath $PasswordFile -Password $global:SecretsFilePassword -LogFile $LogFile
    }
}
