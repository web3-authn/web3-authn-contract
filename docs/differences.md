## Differences in Web3Authn contract

This contract follows standard Webauthn flows, but with minor differences: it uses a verifiable random function (VRF) to generate and validate the WebAuthn challenge on‑chain, and treats authentication as a stateless view contract call.

### 1. Where the challenge comes from

Standard WebAuthn challenges are random bytes from the server, scoped to a single login attempt. The server stores it in memory (or a session) and later compares the value in `clientDataJSON` to the value it originally sent.

In the Web3authn contract the challenge is derived from a VRF input that cryptographically binds:

- the user/account identifier (`user_id`),
- the RP ID (domain),
- a session identifier,
- current chain state (block height and block hash),
- and a fixed domain‑separation string.

The VRF proof and output are passed into the contract, and the contract:

1. Verifies the VRF proof against a stored VRF public key for that authenticator.
2. Extracts the WebAuthn challenge string from the VRF output.
3. Uses that as the expected WebAuthn challenge when validating `clientDataJSON`.

So the web3authn contract recomputes this challenge as the unique, verifiable function of (user, RP ID, session, chain state) under a key we previously associated with this authenticator.

The contract verifies WebAuthn logins without any per‑session state or mutable storage: all the entropy and freshness come from the VRF input and the chain itself.

### 2. Stateless verification vs. counters

In this contract, instead of the counter we use stateless VRF verification:

- Replay protection is provided by the VRF input: each authentication proof is bound to a specific block height, block hash, user, RP ID, and session. You can’t replay an old VRF/WebAuthn pair against a different block or different session and have it pass, even if the WebAuthn counter never increments.

### 3. Origin and RP ID policy is contract‑configurable

This contract runs checks with a more structured configuration model:

- RP ID is stored per authenticator (`expected_rp_id`).
- Origin enforcement is modeled as an `OriginPolicy`:
  - a single strict origin (exact string match),
  - a whitelist of specific origins,
  - or “all subdomains of this RP ID”, with dot‑boundary checks so that `evil-example.com` doesn’t match `example.com`.
- The verifier enforces HTTPS, parses the origin host safely, and then applies the configured policy.

In other words, the low‑level rule (origin and RP ID must be consistent and non‑phishable), but the contract bakes in a richer notion of what 'allowed origins' means so it can support different deployment topologies (SPA frontend, API origin, wallet subdomains, etc.) without rewriting verification logic.

### 4. User presence and user verification are explicit policies

This contract follows that user verification guidance but turns it into a first‑class configuration:

- Every authenticator is stored with a `UserVerificationPolicy`:
  - `required` – UV bit must be set,
  - `preferred` – UV is nice to have, but not required,
  - `discouraged` – UV should not be relied on for this flow.
- The verifier:
  - always requires UP to be set, and
  - enforces/records UV according to that policy.

So instead of hard‑coding whether UV is required in server code, the decision becomes part of the on‑chain authenticator configuration, and the same verification logic can enforce different UX/security contracts per RP or per device.

### 5. Multi‑device / backup semantics are surfaced, not hidden

This contract explicitly reads the multi‑device / backup flags from `authenticatorData` and exposes them:

- `credential_backed_up` is derived from the BS flag.
- `credential_device_type` is derived from the BE flag (`"singleDevice"` vs `"multiDevice"`).

The goal is not just “verify the signature and move on”, but “give the application clear information about whether this credential lives on a single device or is part of a synced passkey set, and whether it’s backed up”. That’s useful for building higher‑level UX and risk signals on top of the raw WebAuthn machinery.
