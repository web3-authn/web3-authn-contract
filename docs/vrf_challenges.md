# WebAuthn VRF Protocol for NEAR

## Overview

Serverless WebAuthn authentication system using VRF (Verifiable Random Functions) for stateless challenge generation, and stateless verification:
- Single contract view call verifies VRF proof + WebAuthn response
- NEAR block data provides freshness and replay protection, and is cryptographically bound to the VRF WebAuthn challenge.

## VRF Challenge Construction

**Input Components** (concatenated and SHA-256 hashed):
- `domain`: `"web3_authn_challenge_v3"` (protocol separation)
- `user_id`: NEAR account ID
- `rp_id`: Relying Party ID (domain)
- `session_id`: Client-generated UUID
- `block_height`: NEAR block height (freshness)
- `block_hash`: NEAR block hash (fork protection)
- `timestamp`: Current timestamp (optional)

**Security Properties:**
- Domain separation prevents cross-protocol reuse
- User and origin binding ensure challenge uniqueness
- Block data provides freshness and fork protection
- Verifiable randomness with VRF proof

See [VRF WebAuthn](https://tatchi.xyz/docs/concepts/vrf-webauthn.html)

## Authentication Flows

See [Transaction Lifecycle](https://tatchi.xyz/docs/concepts/architecture.html#transaction-lifecycle)


## Security Model

**VRF Guarantees:**
- Unpredictability: outputs indistinguishable from random
- Verifiability: anyone can verify proof validity
- Uniqueness: deterministic for same input
- Non-malleability: requires private key to generate proofs

**NEAR Integration:**
- Block height/hash provide freshness and fork protection
- VRF public keys bound to account IDs
- On-chain verification of all proofs

**WebAuthn Security:**
- Origin binding via RP ID in VRF input
- User presence/verification flags validated
- Signature verification (ECDSA/EdDSA)

