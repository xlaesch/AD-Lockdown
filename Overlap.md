 Changes made to Windows-Lockdown:

  1. Removed Zerologon/Netlogon hardening from 01_Network_Security.ps1 - AD-Lockdown 02_Network_Security.ps1 already handles FullSecureChannelProtection, RequireSignOrSeal, etc. on the DC
  2. Removed DisableDomainCreds from LSA section - AD-Lockdown handles this on DCs
  3. Added SMB share management to 01_Network_Security.ps1 - enumerate, selectively remove, or disable SMB server entirely (non-DC machines have shares too)
  4. Added WinRM (5985/5986) and SMB inbound (445) to firewall role-specific rules - so if WinRM is scored or SMB shares are needed, the firewall won't silently block them

  What you could trim from AD-Lockdown (optional):

  Since both run on the DC, these sections in AD-Lockdown 02_Network_Security.ps1 overlap with Windows-Lockdown and could be removed to avoid double-prompting:

  ┌────────────────────────────────────────────────────────────┬──────────────────────────────────────────────┐
  │                    AD-Lockdown Section                     │                   Overlap                    │
  ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────┤
  │ Section 1: SMBv1 disable                                   │ Same as Windows-Lockdown 01 section 1        │
  ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────┤
  │ Section 2: SMB signing prompt, null sessions, admin shares │ Same prompt in Windows-Lockdown 01 section 2 │
  ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────┤
  │ LLMNR/NetBIOS/mDNS disable (in section 2)                  │ Same as Windows-Lockdown 01 sections 3-5     │
  ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────┤
  │ Section 6: NTLM minimum security prompt                    │ Same prompt in Windows-Lockdown 01 section 7 │
  ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────┤
  │ Section 8: SMB share management                            │ Now in Windows-Lockdown 01 section 10        │
  ├────────────────────────────────────────────────────────────┼──────────────────────────────────────────────┤
  │ Firewall logging, default block policy prompt              │ Same in Windows-Lockdown 05                  │
  └────────────────────────────────────────────────────────────┴──────────────────────────────────────────────┘