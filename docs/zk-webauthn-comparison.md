# High‑level idea

Today: browser → authenticator → WebAuthn response → send full clientDataJSON + attestationObject to contract → contract parses, checks challenge, origin, RP ID hash, attestation signature, etc.

ZK version: browser does the same WebAuthn registration, but instead of sending all that to the chain, it feeds it into a ZK prover (client-side? or centralized ZK prover?) which:
- Runs the same verification logic you have in verify_registration_response.rs/utils inside a circuit.
- Outputs a succinct proof: “This WebAuthn registration was valid and satisfied policy P,” plus some public values (credential pubkey, RP ID, maybe a coarse device type).

The contract replaces most of its verification logic with a single verify_proof() call and then stores just the public outputs.

## ZK registration flow (conceptually)

### 1. Inputs to the prover (private):

- Full WebAuthn registration: clientDataJSON, attestationObject (which includes AAGUID, cert chain, COSE key, flags, counters, etc.).
- VRF data / expected challenge (or just the expected challenge itself).
- Optional metadata tables (e.g., AAGUID → DeviceType or policy) as commitments.

### 2. Public inputs to the circuit / on-chain verifier:
- account_id (or user ID) you want to bind to.
- rp_id (or a hash) and maybe the VRF challenge.
- Derived credential_public_key (so the contract can later use it).
- Optional coarse outputs: DeviceType, SecurityLevel, or a boolean “this AAGUID is not in the deny list”.

### 3. Circuit logic (mirrors your current Rust):

- Parse clientDataJSON and enforce:
  - type == "webauthn.create".
  - challenge == expected_challenge (public input).
- Parse attestationObject:
  - Extract authData, fmt, attStmt.
  - Parse authData: RP ID hash, flags, AAGUID, credential ID


### Relation to the VRF challenge

The VRF in our design provides publicly verifiable randomness and binding: the challenge is unpredictable, tied to user_id/rp_id, and verifiable by the contract.

In a ZK redesign, we'd keep the VRF and feed its challenge into the zk circuit as a public input; the proof then says:
"There exists a valid WebAuthn registration/assertion whose challenge equals this VRF challenge and which meets all the policy checks."

- VRF still generates the random challenge and lets the contract verify it.
- ZK hides the WebAuthn internals (AAGUID, certs, exact origin, etc.) while proving that they were used correctly with that challenge.

## Tradeoffs

So adding ZK proofs doesn't add much more to the existing architecture. The key innovation is stateless webauthn verification enabled by VRF challenges.

ZK webauthn simply allows us to redact storing authenticators onchain (replaced with a ZK verify function, while the ZK proof is generated clientside)

### Pros
- authenticators can redact some of the WebAuthn internals (incl. AAGUID) as you wouldn't need to store them onchain in the authenticator anymore (small privacy win).
  - we could hide other stuff too: exact origin, RP ID, user handle, cert chain, etc., while still enforcing policies (“origin ∈ allowed set”, “authenticator model ∉ blocked set”).

### Cons
- Likely much more latency/lag with generating an extra ZK proof before every transaction: we'd have to generate a VRF challenge -> touchID and generate a webauthn credential -> generate a ZK proof (takes time, how long? likely 2-10 seconds on typical client hardware) -> verify ZK proof -> then unlock wallet and sign transaction
- lack of storing authenticator onchain means you can't do deterministic backup features such as "recover account" or "link device" flows, as it requires looking onchain to fetch the authenticator data to do deterministic backups
  - You would need to store a derived public key / handle on-chain so you can verify future assertions or support recovery/linking. What we would omit from onchain is the raw attestationObject + clientDataJSON (with AAGUID, cert chain, origin), not the existence of an authenticator.


## Which architecture is better product‑wise?

For a wallet/contract focused on fast UX, deterministic recovery/linking, and already minimal on‑chain WebAuthn data:
- the existing VRF + on‑chain WebAuthn verification is likely the better trade‑off today.
- A ZK architecture becomes compelling if your top priority shifts to maximal privacy (e.g. hiding AAGUID, origin, attestation details even from calldata, or building cross‑app private identity), and we are willing to pay with:
  - more complex infra and audits,
  - heavier client CPU and latency,
  - much heavier client-side bundles (5mb+), or resort to ZK-as-a-service providers, making us server dependent and less resilient.
  - and higher on-chain verification cost.
