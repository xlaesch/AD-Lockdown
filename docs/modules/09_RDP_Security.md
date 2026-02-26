# 09 RDP Security Module

## High-Level Summary
This module hardens Remote Desktop by enforcing secure authentication/encryption settings, disabling adjacent remote-assistance and redirection risks, tightening session behavior, and optionally changing exposure characteristics (port/access review) while keeping remote administration available.

## Controls

### 1. Ensure RDP Is Enabled
- What it does: Enables RDP registry switches and enables the built-in firewall rule group for Remote Desktop.
- Why it exists: Preserves remote access channel for administration/response.

### 2. Enforce Network Level Authentication (NLA)
- What it does: Sets `UserAuthentication=1` on `RDP-Tcp`.
- Why it exists: Requires pre-session credential validation and reduces unauthenticated session abuse.

### 3. Enforce RDP Encryption and Security Layer
- What it does: Enforces encryption enabled, high encryption level, TLS security layer, and encrypted RPC traffic policy.
- Why it exists: Reduces plaintext/weak transport risk for RDP sessions.

### 4. Disable Remote Assistance
- What it does: Disables Remote Assistance help/control and enforces encrypted-only ticket behavior (including policy key enforcement).
- Why it exists: Removes a secondary remote-control pathway that can be abused.

### 4a. Disable RDP Drive Redirection
- What it does: Sets `fDisableCdm=1`.
- Why it exists: Reduces clipboard/drive pivot and data exfiltration paths through redirected local drives.

### 5. Disable Remote RPC for Terminal Services
- What it does: Sets `AllowRemoteRPC=0`.
- Why it exists: Shrinks RPC attack surface around terminal services.

### 6. Configure Session Timeouts
- What it does: Sets idle timeout (30m), disconnected timeout (15m), and broken-session reset behavior.
- Why it exists: Reduces abandoned-session exposure.

### 7. Optional RDP Port Change
- What it does: Optionally changes `RDP-Tcp` port and adds matching inbound firewall rule.
- Why it exists: Allows non-default exposure pattern if operationally needed.
- Note: Validates numeric range and logs restart requirement for `TermService` to activate new port.

### 8. Optional RDP Access Review
- What it does: Enumerates and displays current `Remote Desktop Users` membership for operator review.
- Why it exists: Supports manual least-privilege verification of who can log on via RDP.
- Note: Review-only in this module (no automatic membership changes).
