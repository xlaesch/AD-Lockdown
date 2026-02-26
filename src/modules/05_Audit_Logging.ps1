# 05_Audit_Logging.ps1
# Handles audit policy configuration, LSASS protection, credential hardening,
# and -- on Domain Controllers -- AD object auditing and GPO permission checks.

param(
    [string]$LogFile,
    [bool]$IsDomainController = $global:IsDomainController
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}
if (-not (Get-Command Set-RegistryValue -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Set-RegistryValue.ps1"
}

Write-Log -Message "Starting Audit Logging Configuration..." -Level "INFO" -LogFile $LogFile

# ═════════════════════════════════════════════════════════════════════════════
# ALL MACHINES
# ═════════════════════════════════════════════════════════════════════════════

# --- 1. LSASS Protection (RunAsPPL) ---
Write-Log -Message "Configuring LSA Protection (RunAsPPL)..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
    Write-Log -Message "LSASS RunAsPPL enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable RunAsPPL: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. LSASS Audit Level ---
Write-Log -Message "Configuring LSASS Audit Level..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8 -Type DWord
    Write-Log -Message "LSASS AuditLevel set to 8 (log all access)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to set LSASS AuditLevel: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. WDigest Credential Hardening ---
Write-Log -Message "Disabling WDigest credential storage..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type DWord
    Write-Log -Message "WDigest credential storage disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable WDigest: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 4. Force Advanced Audit Policy ---
Write-Log -Message "Enabling advanced audit policy override..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
    Write-Log -Message "Advanced audit policy override enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable advanced audit policy: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Comprehensive Audit Policy ---
Write-Log -Message "Configuring comprehensive audit policy..." -Level "INFO" -LogFile $LogFile
try {
    $auditRules = @(
        # Account Logon
        "Credential Validation,Success and Failure",
        "Kerberos Authentication Service,Success and Failure",
        "Kerberos Service Ticket Operations,Success and Failure",
        "Other Account Logon Events,Success and Failure",
        # Account Management
        "Computer Account Management,Success and Failure",
        "Security Group Management,Success and Failure",
        "User Account Management,Success and Failure",
        "Other Account Management Events,Success and Failure",
        # Detailed Tracking
        "DPAPI Activity,Success and Failure",
        "Process Creation,Success and Failure",
        "Process Termination,Success and Failure",
        "RPC Events,Success and Failure",
        "Plug and Play Events,Success and Failure",
        "Token Right Adjusted Events,Success and Failure",
        # Logon/Logoff
        "Logon,Success and Failure",
        "Logoff,Success and Failure",
        "Account Lockout,Success and Failure",
        "Special Logon,Success and Failure",
        "Other Logon/Logoff Events,Success and Failure",
        "Group Membership,Success and Failure",
        # Object Access
        "File System,Success and Failure",
        "Registry,Success and Failure",
        "File Share,Success and Failure",
        "Detailed File Share,Failure",
        "SAM,Success and Failure",
        "Removable Storage,Success and Failure",
        "Filtering Platform Connection,Success and Failure",
        # Policy Change
        "Audit Policy Change,Success and Failure",
        "Authentication Policy Change,Success and Failure",
        "MPSSVC Rule-Level Policy Change,Success and Failure",
        "Filtering Platform Policy Change,Success and Failure",
        # Privilege Use
        "Sensitive Privilege Use,Success and Failure",
        # System
        "Security State Change,Success and Failure",
        "Security System Extension,Success and Failure",
        "System Integrity,Success and Failure"
    )

    # DC-only: add DS Access audit categories
    if ($IsDomainController) {
        $auditRules += @(
            "Directory Service Access,Success and Failure",
            "Directory Service Changes,Success and Failure"
        )
    }

    foreach ($rule in $auditRules) {
        $parts = $rule -split ","
        $subcategory = $parts[0].Trim()
        $setting = $parts[1].Trim()

        $cmd = "auditpol /set /subcategory:`"$subcategory`" /success:enable /failure:enable"
        if ($setting -eq "Failure") { $cmd = "auditpol /set /subcategory:`"$subcategory`" /success:disable /failure:enable" }
        if ($setting -eq "Success") { $cmd = "auditpol /set /subcategory:`"$subcategory`" /success:enable /failure:disable" }

        Invoke-Expression $cmd 2>&1 | Out-Null
        Write-Log -Message "Audit: $subcategory -> $setting" -Level "SUCCESS" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Exception configuring audit policy: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 6. Enable Command Line in Process Creation Events ---
Write-Log -Message "Enabling command line logging in process creation events..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    Write-Log -Message "Command line process auditing enabled (Event 4688)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable command line auditing: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 7. PowerShell Script Block Logging ---
Write-Log -Message "Enabling PowerShell script block logging..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
    Write-Log -Message "PowerShell script block logging enabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable PowerShell logging: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 8. PowerShell Module Logging ---
Write-Log -Message "Enabling PowerShell module logging..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord
    # Log all modules
    $modulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    if (-not (Test-Path $modulePath)) { New-Item -Path $modulePath -Force | Out-Null }
    Set-ItemProperty -Path $modulePath -Name "*" -Value "*" -Force
    Write-Log -Message "PowerShell module logging enabled for all modules." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to enable PowerShell module logging: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 9. Increase Event Log Sizes ---
Write-Log -Message "Increasing event log sizes..." -Level "INFO" -LogFile $LogFile
try {
    $logSettings = @{
        "Security"    = 1048576000  # ~1GB
        "Application" = 104857600   # ~100MB
        "System"      = 104857600   # ~100MB
        "Windows PowerShell" = 104857600
    }
    foreach ($logName in $logSettings.Keys) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
            if ($log) {
                $log.MaximumSizeInBytes = $logSettings[$logName]
                $log.SaveChanges()
                Write-Log -Message "Set $logName log max size to $($logSettings[$logName] / 1MB)MB." -Level "SUCCESS" -LogFile $LogFile
            }
        } catch {
            Write-Log -Message "Failed to resize $logName log: $_" -Level "WARNING" -LogFile $LogFile
        }
    }
} catch {
    Write-Log -Message "Failed to configure event log sizes: $_" -Level "ERROR" -LogFile $LogFile
}

# ═════════════════════════════════════════════════════════════════════════════
# DOMAIN CONTROLLER ONLY
# ═════════════════════════════════════════════════════════════════════════════
if ($IsDomainController) {

    # --- 10. Advanced AD Object Auditing ---
    Write-Log -Message "Configuring Advanced AD Object Auditing..." -Level "INFO" -LogFile $LogFile

    function Set-ADObjectAudit {
        param($DistinguishedName, $AuditRules)
        try {
            $Acl = Get-Acl -Path "AD:\$DistinguishedName" -Audit
            if ($Acl) {
                foreach ($Rule in $AuditRules) {
                    $Acl.AddAuditRule($Rule)
                }
                Set-Acl -Path "AD:\$DistinguishedName" -AclObject $Acl
                return $true
            }
        } catch {
            Write-Log -Message "Failed to set audit on $DistinguishedName : $_" -Level "WARNING" -LogFile $LogFile
        }
        return $false
    }

    try {
        $DomainDN = (Get-ADDomain).DistinguishedName
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

        # 1. RID Manager Auditing
        $RidManagerDN = "CN=RID Manager$,CN=System,$DomainDN"
        $RidRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AuditFlags]::Failure, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        Set-ADObjectAudit -DistinguishedName $RidManagerDN -AuditRules @($RidRule)

        # 2. AdminSDHolder Auditing
        $AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"
        $AdminSDRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, [System.Security.AccessControl.AuditFlags]::Failure, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        Set-ADObjectAudit -DistinguishedName $AdminSDHolderDN -AuditRules @($AdminSDRule)

        # 3. Domain Controllers OU Auditing
        $DCOU_DN = "OU=Domain Controllers,$DomainDN"
        $DCRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, [System.Security.AccessControl.AuditFlags]::Success, [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        Set-ADObjectAudit -DistinguishedName $DCOU_DN -AuditRules @($DCRule)

        Write-Log -Message "Advanced AD Object Auditing configured." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to configure Advanced AD Auditing: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 11. GPO Permission Check (Reporting) ---
    Write-Log -Message "Checking for insecure GPO permissions (Authenticated Users)..." -Level "INFO" -LogFile $LogFile
    try {
        $insecureGPOs = @()
        Get-GPO -All | ForEach-Object {
            $gpoName = $_.DisplayName
            Get-GPPermissions -Guid $_.Id -All | ForEach-Object {
                if ($_.Trustee.Name -eq "Authenticated Users" -and $_.Permission -ne "GpoRead") {
                    $insecureGPOs += "$gpoName ($($_.Permission))"
                }
            }
        }

        if ($insecureGPOs.Count -gt 0) {
            Write-Log -Message "Found GPOs with potentially insecure 'Authenticated Users' permissions:" -Level "WARNING" -LogFile $LogFile
            foreach ($gpo in $insecureGPOs) {
                Write-Log -Message "  - $gpo" -Level "WARNING" -LogFile $LogFile
            }
        } else {
            Write-Log -Message "No obvious GPO permission issues found for Authenticated Users." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to check GPO permissions: $_" -Level "ERROR" -LogFile $LogFile
    }

} # end DC-only block

Write-Log -Message "Audit Logging module complete." -Level "SUCCESS" -LogFile $LogFile
