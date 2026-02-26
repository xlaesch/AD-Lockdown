# 04_Service_Hardening.ps1
# Handles disabling dangerous services, ensuring critical ones are running,
# and -- on Domain Controllers -- DSRM, NTDS, and LDAP hardening.

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

Write-Log -Message "Starting Service Hardening..." -Level "INFO" -LogFile $LogFile

# ═════════════════════════════════════════════════════════════════════════════
# ALL MACHINES
# ═════════════════════════════════════════════════════════════════════════════

# --- 1. Print Spooler (PrintNightmare) ---
Write-Log -Message "Configuring Print Spooler..." -Level "INFO" -LogFile $LogFile
if ($IsDomainController) {
    # On DCs, PrintNightmare is critical -- force disable without prompting
    try {
        Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "Spooler" -StartupType Disabled
        Write-Log -Message "Print Spooler force-disabled (DC -- PrintNightmare mitigation)." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to disable Print Spooler: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    Write-Host "IMPACT: Disabling Print Spooler prevents local and network printing." -ForegroundColor Yellow
    $disableSpooler = Read-Host "Disable Print Spooler? [y/n]"
    if ($disableSpooler -eq 'y') {
        try {
            Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "Spooler" -StartupType Disabled
            Write-Log -Message "Print Spooler disabled." -Level "SUCCESS" -LogFile $LogFile
        } catch {
            Write-Log -Message "Failed to disable Print Spooler: $_" -Level "ERROR" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "Print Spooler left enabled per user request." -Level "WARNING" -LogFile $LogFile
        # Still harden printer driver installation
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1 -Type DWord
        Write-Log -Message "Restricted printer driver installation to admins only." -Level "SUCCESS" -LogFile $LogFile
    }
}

# --- 1a. PrintNightmare & Print Spooler CVE Mitigations ---
Write-Log -Message "Applying PrintNightmare and Print Spooler CVE mitigations..." -Level "INFO" -LogFile $LogFile
try {
    $printerPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
    # CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)
    Set-RegistryValue -Path $printerPath -Name "CopyFilesPolicy" -Value 1 -Type DWord
    Set-RegistryValue -Path $printerPath -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord
    # CVE-2021-1678
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Print" -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -Type DWord
    # CVE-2022-38028 - Restrict driver installation and Point and Print
    Set-RegistryValue -Path "$printerPath\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord
    Set-RegistryValue -Path "$printerPath\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord
    Set-RegistryValue -Path "$printerPath\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -Type DWord
    # Disable HTTP print driver download and HTTP printing
    Set-RegistryValue -Path $printerPath -Name "DisableWebPnPDownload" -Value 1 -Type DWord
    Set-RegistryValue -Path $printerPath -Name "DisableHTTPPrinting" -Value 1 -Type DWord
    Write-Log -Message "PrintNightmare and Print Spooler CVE mitigations applied." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply Print Spooler CVE mitigations: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 1b. PetitPotam Mitigation (CVE-2021-36942) ---
Write-Log -Message "Applying PetitPotam mitigation (CVE-2021-36942)..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableEncryptedEfsRpc" -Value 1 -Type DWord
    Write-Log -Message "PetitPotam mitigation applied (EFSRPC disabled)." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to apply PetitPotam mitigation: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Disable Remote Registry ---
Write-Log -Message "Disabling Remote Registry service..." -Level "INFO" -LogFile $LogFile
try {
    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Log -Message "Remote Registry disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Remote Registry: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. WinRM / PSRemoting (Prompted) ---
Write-Log -Message "=== WinRM / PS Remoting Configuration ===" -Level "INFO" -LogFile $LogFile
Write-Host "IMPACT: Disabling WinRM prevents remote PowerShell management. Some scoring engines use WinRM." -ForegroundColor Yellow
Write-Host "  [1] Disable WinRM entirely" -ForegroundColor Yellow
Write-Host "  [2] Leave WinRM enabled" -ForegroundColor Yellow
$winrmChoice = Read-Host "WinRM configuration [1/2]"

if ($winrmChoice -eq '1') {
    try {
        Disable-PSRemoting -Force -ErrorAction SilentlyContinue
        Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue
        # Remove listeners
        Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse -ErrorAction SilentlyContinue
        # Disable LocalAccountTokenFilterPolicy (prevents remote admin token elevation)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Force
        Write-Log -Message "WinRM/PSRemoting disabled, listeners removed." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to fully disable WinRM: $_" -Level "ERROR" -LogFile $LogFile
    }
} else {
    # Harden WinRM if left enabled -- disallow unencrypted traffic
    try {
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord
        Write-Log -Message "WinRM left enabled but hardened (unencrypted traffic disallowed)." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to harden WinRM: $_" -Level "ERROR" -LogFile $LogFile
    }
}

# --- 4. Disable Telnet ---
Write-Log -Message "Disabling Telnet client and server features..." -Level "INFO" -LogFile $LogFile
try {
    dism /online /disable-feature /featurename:TelnetClient /NoRestart 2>&1 | Out-Null
    dism /online /disable-feature /featurename:TelnetServer /NoRestart 2>&1 | Out-Null
    Write-Log -Message "Telnet features disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable Telnet: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 5. Disable TFTP ---
Write-Log -Message "Disabling TFTP feature..." -Level "INFO" -LogFile $LogFile
try {
    dism /online /disable-feature /featurename:TFTP /NoRestart 2>&1 | Out-Null
    Write-Log -Message "TFTP feature disabled." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to disable TFTP: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 6. Remove PowerShell v2 (Downgrade Attack Prevention) ---
Write-Log -Message "Removing PowerShell v2 engine..." -Level "INFO" -LogFile $LogFile
try {
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart -ErrorAction SilentlyContinue
    Write-Log -Message "PowerShell v2 engine removed." -Level "SUCCESS" -LogFile $LogFile
} catch {
    Write-Log -Message "Failed to remove PowerShell v2: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 7. Disable Unnecessary Services ---
Write-Log -Message "Disabling unnecessary services..." -Level "INFO" -LogFile $LogFile
$servicesToDisable = @(
    @{ Name = "XblAuthManager";   Desc = "Xbox Live Auth Manager" },
    @{ Name = "XblGameSave";      Desc = "Xbox Live Game Save" },
    @{ Name = "MapsBroker";       Desc = "Downloaded Maps Manager" },
    @{ Name = "lfsvc";            Desc = "Geolocation Service" },
    @{ Name = "SharedAccess";     Desc = "Internet Connection Sharing" },
    @{ Name = "WMPNetworkSvc";    Desc = "Windows Media Player Network Sharing" },
    @{ Name = "DiagTrack";        Desc = "Connected User Experiences and Telemetry" }
)

foreach ($svc in $servicesToDisable) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log -Message "Disabled: $($svc.Desc) ($($svc.Name))" -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to disable $($svc.Name): $_" -Level "WARNING" -LogFile $LogFile
    }
}

# --- 8. Remove OpenSSH (Client & Server) ---
Write-Log -Message "Checking for OpenSSH capabilities..." -Level "INFO" -LogFile $LogFile
$opensshCapabilities = @(
    @{ Name = "OpenSSH.Server~~~~0.0.1.0";  Desc = "OpenSSH Server" },
    @{ Name = "OpenSSH.Client~~~~0.0.1.0";  Desc = "OpenSSH Client" }
)
foreach ($cap in $opensshCapabilities) {
    try {
        $installed = Get-WindowsCapability -Online -Name $cap.Name -ErrorAction SilentlyContinue
        if ($installed -and $installed.State -eq "Installed") {
            Write-Host "$($cap.Desc) is installed." -ForegroundColor Yellow
            $removeSSH = Read-Host "Remove $($cap.Desc)? [y/n]"
            if ($removeSSH -eq 'y') {
                Remove-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop
                Write-Log -Message "$($cap.Desc) removed." -Level "SUCCESS" -LogFile $LogFile
            } else {
                Write-Log -Message "$($cap.Desc) left installed." -Level "INFO" -LogFile $LogFile
            }
        } else {
            Write-Log -Message "$($cap.Desc) not installed." -Level "INFO" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to check/remove $($cap.Desc): $_" -Level "WARNING" -LogFile $LogFile
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# DOMAIN CONTROLLER ONLY
# ═════════════════════════════════════════════════════════════════════════════
if ($IsDomainController) {

    # --- 9. DSRM Admin Logon Behavior ---
    Write-Log -Message "Configuring DSRM Admin Logon Behavior..." -Level "INFO" -LogFile $LogFile
    try {
        # 1 = Only allow DSRM admin to log on when AD DS is stopped
        Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 1 -Type DWord
        Write-Log -Message "DSRM Admin Logon Behavior set to 1." -Level "SUCCESS" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Failed to set DSRM Admin Logon Behavior: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 10. NTDS File Permissions ---
    Write-Log -Message "Hardening NTDS File Permissions..." -Level "INFO" -LogFile $LogFile
    try {
        $NTDS = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
        if ($NTDS) {
            $DSA = $NTDS.'DSA Database File'
            $Logs = $NTDS.'Database log files path'

            if ($DSA -and $Logs) {
                $DSA_Folder = Split-Path -Parent $DSA
                $Logs_Folder = $Logs

                # Define Principals
                $Admins = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
                $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

                # Create Access Rules
                $FullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
                $Inheritance = @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
                $Propagation = [System.Security.AccessControl.PropagationFlags]::None
                $Allow = [System.Security.AccessControl.AccessControlType]::Allow

                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Admins, $FullControl, $Inheritance, $Propagation, $Allow)
                $SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($System, $FullControl, $Inheritance, $Propagation, $Allow)

                # Apply to DSA Folder
                if (Test-Path $DSA_Folder) {
                    $Acl = Get-Acl -Path $DSA_Folder
                    $Acl.SetAccessRuleProtection($true, $false)
                    $Acl.AddAccessRule($AdminRule)
                    $Acl.AddAccessRule($SystemRule)
                    Set-Acl -Path $DSA_Folder -AclObject $Acl
                    Write-Log -Message "Secured NTDS Database Folder: $DSA_Folder" -Level "SUCCESS" -LogFile $LogFile
                }

                # Apply to Logs Folder
                if (Test-Path $Logs_Folder) {
                    $Acl = Get-Acl -Path $Logs_Folder
                    $Acl.SetAccessRuleProtection($true, $false)
                    $Acl.AddAccessRule($AdminRule)
                    $Acl.AddAccessRule($SystemRule)
                    Set-Acl -Path $Logs_Folder -AclObject $Acl
                    Write-Log -Message "Secured NTDS Logs Folder: $Logs_Folder" -Level "SUCCESS" -LogFile $LogFile
                }
            }
        }
    }
    catch {
        Write-Log -Message "Failed to harden NTDS permissions: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 11. LDAP Connection Limits ---
    Write-Log -Message "Configuring LDAP Connection Limits (MaxConnIdleTime)..." -Level "INFO" -LogFile $LogFile
    try {
        $DomainDN = (Get-ADDomain).DistinguishedName
        $SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DomainDN"
        $Policies = Get-ADObject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties lDAPAdminLimits

        if ($Policies) {
            $AdminLimits = $Policies.lDAPAdminLimits
            $NewLimit = "MaxConnIdleTime=180"

            # Remove existing if present
            $AdminLimits = @($AdminLimits) | Where-Object { $_ -notmatch "MaxConnIdleTime=*" }
            $AdminLimits += $NewLimit

            Set-ADObject -Identity $Policies -Replace @{lDAPAdminLimits=[string[]]$AdminLimits}
            Write-Log -Message "Set MaxConnIdleTime to 180 seconds." -Level "SUCCESS" -LogFile $LogFile
        }
    } catch {
        Write-Log -Message "Failed to set LDAP limits: $_" -Level "ERROR" -LogFile $LogFile
    }

    # --- 12. Delete VSS Shadow Copies (T1003.001 - Prevent NTDS.dit Extraction) ---
    Write-Log -Message "Deleting VSS shadow copies to prevent NTDS.dit extraction..." -Level "INFO" -LogFile $LogFile
    try {
        vssadmin.exe delete shadows /all /quiet 2>&1 | Out-Null
        Write-Log -Message "VSS shadow copies deleted." -Level "SUCCESS" -LogFile $LogFile
    } catch {
        Write-Log -Message "Failed to delete VSS shadow copies: $_" -Level "ERROR" -LogFile $LogFile
    }

} # end DC-only block

# ═════════════════════════════════════════════════════════════════════════════
# ALL MACHINES -- Ensure RDP is running
# ═════════════════════════════════════════════════════════════════════════════

# --- 12. Ensure Remote Desktop Service is Running ---
Write-Log -Message "Ensuring Remote Desktop Services are running..." -Level "INFO" -LogFile $LogFile
try {
    Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord
    $termService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    if ($termService) {
        if ($termService.StartType -ne 'Automatic') {
            Set-Service -Name "TermService" -StartupType Automatic
        }
        if ($termService.Status -ne 'Running') {
            Start-Service -Name "TermService"
        }
        Write-Log -Message "RDP service ensured running (Automatic startup)." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "TermService not found." -Level "WARNING" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to configure RDP service: $_" -Level "ERROR" -LogFile $LogFile
}

Write-Log -Message "Service Hardening module complete." -Level "SUCCESS" -LogFile $LogFile
