# Web3Authn Contract Limitations

This document outlines the limitations of the Web3Authn contract, their scope, and the rationale for each.

## WebAuthn Attestation Limitations

### x5c Certificate Chain Validation

**Current Support:**
- Leaf certificate parsing and validation
- P-256/ES256 signature verification
- Support for `packed` and `fido-u2f` attestation formats

**Limitations:**
- **Intermediate certificate validation**: Only the leaf certificate is validated. Full chain verification (validating signatures between certificates) is not implemented.
- **Root CA trust store**: No built-in trusted root certificate authority store.
- **Certificate revocation checking**: No support for checking if certificates have been revoked.
- **Algorithm support**: Limited to P-256/ES256 only (most common WebAuthn algorithm).

**Scope Status:**
- **In scope (future enhancement)**: Certificate expiry validation, known vendor certificate fingerprinting
- **Out of scope**: Revocation checking (no HTTP/network access)
- **Cost consideration**: Full chain verification would add 100+ TGas

**Rationale:**
On-chain contracts cannot make HTTP requests, making revocation checking and dynamic metadata service lookups impossible. Full chain validation would significantly increase gas costs (10-30x) with diminishing security returns.

### AAGUID Metadata Validation

**Current Support:**
- AAGUID extraction from authenticator data

**Limitations:**
- **FIDO Metadata Service (MDS) integration**: No validation against FIDO MDS for authenticator certification levels, known vulnerabilities, or revocation status.
- **Authenticator trust levels**: Cannot verify FIDO Alliance certification levels.
- **Vulnerability detection**: No checking for authenticators with known security issues.

**Scope Status:**
- **In scope (future enhancement)**: Embedded subset of FIDO MDS data that can be updated via contract upgrades (3-6 month cycles)
- **Out of scope**: Real-time MDS lookups, dynamic metadata updates
- **Cost consideration**: Would add 3-6.5 TGas per registration (17-32% increase)

**Rationale:**
Full MDS integration requires periodic HTTP requests to the FIDO Metadata Service, which is not possible on-chain.

## Device Linking Limitations

### Stale Key Cleanup

**Current Implementation:**
- Device linking uses temporary NEAR keys
- Automatic cleanup via yield-resume pattern (200 blocks)

**Limitations:**
- **Cross-account key deletion**: The contract cannot directly delete keys from user accounts due to NEAR's permission model.
- **Timing race conditions**: Pre-signed DeleteKey transactions on Device1 could execute before Device2 completes polling if the user closes the QR scanner prematurely.
- **Orphaned keys**: If both automatic cleanup and manual cleanup fail, stale keys may remain on the account.

**Scope Status:**
- **In scope**: Current yield-resume automatic cleanup approach
- **Partial scope**: Pre-signed DeleteKey transactions (minor race condition acceptable)
- **Out of scope**: Direct cross-account key deletion (NEAR protocol limitation)
- **Cost consideration**: Automatic cleanup adds 17-35 TGas vs 2-5 TGas for manual deletion

**Rationale:**
NEAR's security model prevents contracts from directly modifying other accounts' access keys. The yield-resume pattern provides automatic cleanup in most cases, with the understanding that edge cases may require manual intervention by the user.

## Protocol-Level Limitations

### Cryptographic Algorithm Support
- **No post-quantum cryptography**: Not yet supported in WebAuthn

## Configuration Limits

### Resource Limits
- **Maximum authenticators per account**: 10 (configurable via `VRFSettings`)
- **Maximum allowed origins**: 5000
- **Maximum origin length**: 255 characters
- **VRF challenge freshness**: 5 minutes (configurable)
- **Block age for VRF**: 200 blocks (~120 seconds, configurable)

**Rationale:**
These limits prevent resource exhaustion attacks and ensure reasonable gas costs for common operations.
