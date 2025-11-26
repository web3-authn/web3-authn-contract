# Registration Griefing and Account ID Squatting

There is a limitation in the `create_account_and_register_user` function where a malicious relayer can grief a user by creating a NEAR account with an unexpected access key, effectively squatting on the `account_id`.

This issue occurs because the relayer creates named accounts (e.g. `bob.near`) for the user and associates it with the user's public key (`ed25519:abc...xyz`) for gasless onboarding.
- You have the same problem with existing name account creating services
- This isn't an issue with VRF webauthn per-se, moreso a limitation of the NEAR blockchain (and blockchains with named accounts that require gas to claim a name, e.g. Ethereum ENS).


### Impact

- The `desired_account.near` account is **successfully created**, but owned by the attacker (who controls the NEAR access key).
- The contract also stores a valid WebAuthn authenticator for `desired_account.near`, so verification of WebAuthn responses for that account still works, but from the wallet's perspective:
  - The NEAR account's on-chain key set does **not** match the expected `new_public_key`.
  - The wallet should treat this registration as **invalid/failed**.
- The user's desired `account_id` has been **squatted**. Even if the wallet refuses to use this account, the name is taken.

This is a **griefing / squatting** issue at registration time, not a cryptographic break of WebAuthn or VRF.

This is because we do not bind `new_public_key` into the VRF proof (which would prevent this issue).

## Why `new_public_key` Is Not Bound in VRF

Because of UX: to cryptographically bind `new_public_key` we would need TWO touchID prompts during registration:
- (i) one TouchID to derive the `new_public_key` deterministically from webauthn credentials, before bindiing it into the VRF challenge, then
- (ii) a second TouchID to use that VRF in creating another webauthn registration credential (VRf-bound WebAuthn challenge).


For UX reasons, the protocol explicitly aims for **one TouchID prompt** during registration. To preserve this UX:

- We **do not** bind `new_public_key` in the VRF input.
- As a result, `new_public_key` remains a parameter that is trusted from the relayer for the `create_account_and_register_user` call.


## Current Mitigation (SDK-Level Check)


Currently, the client SDK treats `new_public_key` as **trusted input from the relayer, and verifies it after registration**:

1. After `create_account_and_register_user` completes, the client:
   - Queries the NEAR RPC for the newly created account.
   - Fetches the list of access keys for `new_account_id`.
2. The SDK verifies:
   - That `expected_new_public_key` is present in the access keys.
   - Optionally, that there are no unexpected full-access keys.
3. If the key set does not match expectations:
   - The wallet **treats registration as failed**.
   - It does **not** store local secrets (e.g. encrypted NEAR keypair) for this account.
   - It may display a clear error indicating the relayer misbehaved.

This mitigates silent compromise of the wallet but **does not** prevent:

- Loss of the desired `account_id` (it remains created on-chain with someone else’s key).

Also, the relayer can be run by anyone (it's a simply stateless server from the SDK), simply deploy your own relayer, and point the client SDK to it (e.g. `your-relay.example.com`).


## Other Fixes and Tradeoffs

### 1. Double TouchID to Bind `new_public_key` (Stronger, Worse UX)

- Split registration into two WebAuthn ceremonies:
  1. **First WebAuthn/PRF call**: derive deterministic NEAR keypair (`new_public_key`).
  2. **Second WebAuthn call**: sign a VRF-based challenge that *includes* `new_public_key` in its input.

**Properties:**

- `new_public_key` becomes cryptographically bound in `VRFVerificationData`.
- The contract can validate that the NEAR key being added really matches what was bound in the VRF input.
- A relayer cannot swap out `new_public_key` without causing VRF/WebAuthn verification to fail.

**Drawbacks:**

- Requires **two TouchID prompts** during registration.
- Worse UX, especially on mobile or in flows where users expect “one tap to register”.

This is the most straightforward protocol-level fix but is currently **rejected for UX reasons**.

### 2. Create account first, then register separately

Use the simpler, safer flow:
  1. User (or a trusted funding service) creates the NEAR account out-of-band with the correct `new_public_key`.
  2. The wallet then calls `verify_and_register_user` from that account.
- In this flow, the contract uses `env::predecessor_account_id()` as the account to bind the authenticator to, rather than taking `new_account_id` and `new_public_key` as parameters.

**Properties:**

- No relayer trust for `new_public_key`: the signer of the transaction must already control the NEAR account.
- No extra TouchID prompts; uses existing VRF + WebAuthn registration.

**Drawbacks:**

- Requires separate account creation and funding step.
- Loses the “single transaction account creation + registration” ergonomics.

