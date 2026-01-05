# WebAuthn VRF Protocol for NEAR

## Overview

Serverless WebAuthn authentication system using VRF (Verifiable Random Functions) for stateless challenge generation, and stateless verification:
- Single contract view call verifies VRF proof + WebAuthn response
- NEAR block data provides freshness and replay protection, and is cryptographically bound to the VRF WebAuthn challenge.

## VRF Challenge Construction

**Input Components** (concatenated and SHA-256 hashed):
- `domain`: `"web3_authn_challenge_v4"` (protocol separation)
- `user_id`: NEAR account ID (bytes)
- `rp_id`: Relying Party ID (domain, lowercased bytes)
- `block_height`: NEAR block height (u64 LE bytes)
- `block_hash`: NEAR block hash (32 bytes)
- `intent_digest_32`: Optional 32-byte UI intent digest (when present)
- `session_policy_digest_32`: Optional 32-byte session policy digest (when present)

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
