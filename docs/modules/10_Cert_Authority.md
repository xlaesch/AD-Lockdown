# 10 Certificate Authority Module

## High-Level Summary
This DC-only module handles ADCS baseline management with safety-first prompts around major PKI-impact actions. It verifies/installs ADCS components, optionally provisions an Enterprise Root CA, optionally restarts NTDS, and provides an operator-confirmed workflow to audit and mass-revoke issued certificates with CRL publication.

## Controls

### 1. Verify/Install ADCS Role Tools (Prompted if Missing)
- What it does: Checks `Adcs-Cert-Authority`; if missing, prompts to install management tools/role components.
- Why it exists: Ensures ADCS functionality is available before CA hardening and related tooling.
- Note: If operator declines install, sets `$Global:SkipLocksmith = $true` and exits early to coordinate downstream post-analysis behavior.

### 2. Conditional Enterprise Root CA Provisioning (Prompted)
- What it does: Detects existing CA configuration; if none exists, offers `Install-AdcsCertificationAuthority -CAtype EnterpriseRootCA`.
- Why it exists: Supports environments needing internal PKI while avoiding unintentional CA deployment.
- Note: Explicit high-impact warning gate before provisioning a new enterprise root.

### 3. Optional NTDS Restart (High-Impact Prompt)
- What it does: Prompts to restart `ntds` service.
- Why it exists: Allows operator-controlled service restart when required by ADCS/domain changes.
- Note: Downtime warning emphasizes domain authentication impact, especially in single-DC environments.

### 4. Certificate Audit and Optional Mass Revocation
- What it does:
  - Enumerates issued certificates (`Disposition=20`) via `certutil`.
  - Prompts for bulk revocation.
  - If confirmed, revokes each issued request ID and publishes a new CRL.
- Why it exists: Enables rapid invalidation of potentially compromised/misissued certs and forces controlled re-issuance.
- Note: Uses request-ID-driven looped revocation with explicit operator confirmation before destructive action.
