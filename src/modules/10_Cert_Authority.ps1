# 10_Cert_Authority.ps1
# Handles Active Directory Certificate Services (ADCS) hardening.
# DC-only -- skips entirely on non-DC machines.

param(
    [string]$LogFile,
    [bool]$IsDomainController = $global:IsDomainController
)

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/../functions/Write-Log.ps1"
}

if (-not $IsDomainController) {
    Write-Log -Message "Skipping Cert Authority module (not a Domain Controller)." -Level "INFO" -LogFile $LogFile
    return
}

Write-Log -Message "Starting ADCS Hardening..." -Level "INFO" -LogFile $LogFile

# --- 1. Install/Verify ADCS Tools ---
Write-Log -Message "Verifying ADCS Management Tools..." -Level "INFO" -LogFile $LogFile
try {
    $feature = Get-WindowsFeature -Name Adcs-Cert-Authority
    if (-not $feature.Installed) {
        $installAdcs = Read-Host "ADCS Role is not installed. Do you want to install and harden ADCS? This is required for Locksmith. [y/n]"
        if ($installAdcs -ne 'y') {
            Write-Log -Message "User chose not to install ADCS. Skipping ADCS hardening and Locksmith." -Level "WARNING" -LogFile $LogFile
            $Global:SkipLocksmith = $true
            return
        }

        Write-Log -Message "Installing ADCS Management Tools..." -Level "INFO" -LogFile $LogFile
        Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
        Write-Log -Message "ADCS Management Tools installed." -Level "SUCCESS" -LogFile $LogFile
    } else {
        Write-Log -Message "ADCS Management Tools already installed." -Level "INFO" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Failed to check/install ADCS tools: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 2. Install Enterprise Root CA (Conditional) ---
Write-Log -Message "Checking Enterprise Root CA status..." -Level "INFO" -LogFile $LogFile
try {
    $caConfig = Get-Command Get-CertificationAuthority -ErrorAction SilentlyContinue
    if ($caConfig) {
        $cas = Get-CertificationAuthority -ErrorAction SilentlyContinue
        if ($cas) {
             Write-Log -Message "Certification Authority is already configured: $($cas.Name)" -Level "INFO" -LogFile $LogFile
        } else {
            Write-Log -Message "CA Tools installed but no CA found. Attempting to install Enterprise Root CA..." -Level "WARNING" -LogFile $LogFile
            Write-Host "IMPACT: Installing an Enterprise Root CA is a major infrastructure change. It introduces significant new attack surfaces (ADCS abuse) if not strictly managed." -ForegroundColor Yellow
            $installCA = Read-Host "Do you want to install Enterprise Root CA? [y/n]"
            if ($installCA -eq 'y') {
                Install-AdcsCertificationAuthority -CAtype EnterpriseRootCA -Force
                Write-Log -Message "Enterprise Root CA installed." -Level "SUCCESS" -LogFile $LogFile
            } else {
                Write-Log -Message "Skipped automatic CA installation for safety." -Level "WARNING" -LogFile $LogFile
            }
        }
    }
} catch {
    Write-Log -Message "Error checking CA status: $_" -Level "ERROR" -LogFile $LogFile
}

# --- 3. Restart NTDS (Aggressive!) ---
Write-Host "IMPACT: Restarting NTDS stops all authentication and directory services on this DC temporarily. If this is the only DC, the domain will go offline." -ForegroundColor Yellow
$restartNTDS = Read-Host "Do you want to restart NTDS service? This will cause DC downtime! [y/n]"
if ($restartNTDS -eq 'y') {
    Restart-Service -Name ntds -Force
    Write-Log -Message "NTDS service restarted." -Level "SUCCESS" -LogFile $LogFile
} else {
    Write-Log -Message "NTDS restart skipped for safety." -Level "WARNING" -LogFile $LogFile
}

# --- 4. Audit and Revoke Certificates ---
Write-Log -Message "Auditing Issued Certificates..." -Level "INFO" -LogFile $LogFile
try {
    $ca = Get-CertificationAuthority -ErrorAction SilentlyContinue
    if ($ca) {
        Write-Host "`n--- Issued Certificates on $($ca.Name) ---" -ForegroundColor Cyan

        $certs = certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,CommonName,CertificateTemplate,NotAfter" csv
        $certs | ForEach-Object {
            if ($_ -match '^\s*"?\d+"?,') { Write-Host $_ }
        }

        Write-Host "`nWARNING: Revoking certificates will break authentication for services relying on them until new ones are issued." -ForegroundColor Red
        $response = Read-Host "Do you want to REVOKE all these certificates to force re-issuance? (y/n)"

        if ($response -eq 'y') {
            Write-Log -Message "User confirmed revocation. Proceeding..." -Level "WARNING" -LogFile $LogFile

            $idList = certutil -view -restrict "Disposition=20" -out "RequestID" csv

            foreach ($line in $idList) {
                if ($line -match '^\s*"?(\d+)"?') {
                    $reqId = $matches[1]
                    Write-Log -Message "Revoking Request ID: $reqId" -Level "INFO" -LogFile $LogFile
                    certutil -revoke $reqId
                }
            }
            Write-Log -Message "All issued certificates have been revoked." -Level "SUCCESS" -LogFile $LogFile

            Write-Log -Message "Publishing new CRL..." -Level "INFO" -LogFile $LogFile
            certutil -crl
        } else {
            Write-Log -Message "User cancelled certificate revocation." -Level "INFO" -LogFile $LogFile
        }
    } else {
        Write-Log -Message "No Certification Authority found. Skipping audit." -Level "INFO" -LogFile $LogFile
    }
} catch {
    Write-Log -Message "Error during certificate audit: $_" -Level "ERROR" -LogFile $LogFile
}

Write-Log -Message "Cert Authority module complete." -Level "SUCCESS" -LogFile $LogFile
