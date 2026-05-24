# Apple Secure Enclave Custody POC Phase 0

> Status: Validation snapshot for a proposal planning track.
> Date: 2026-05-24.
> Purpose: Establish the shared evidence record, source references, and
> evidence-note format for Apple Secure Enclave Custody proof work before any
> prototype code is written.
> Audience: Product, security reviewers, Swift/Rust implementers, test owners,
> and AI coding tools.
> Truth sources: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md), and
> [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md).
> Evidence roots: [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Testing](TESTING.md), current Swift and Rust implementation files, Apple
> Secure Enclave documentation, RFC 9580, RFC 6637, and Sequoia 2.3
> documentation/source.
> Current-state note: This file is an evidence baseline for proposed future
> behavior. It does not describe shipped behavior, authorize production
> implementation, or change CypherAir's current security architecture.

## 1. Phase 0 Result

Phase 0 establishes the shared record that later proof phases should cite
instead of duplicating the product and security documents. It confirms:

- The shipped Secure Enclave wrapping model and the proposed Apple Secure
  Enclave Custody model are separate.
- The evidence-note format for later phases is available.
- Later phases have one shared validation-question register.
- Phase 0 is documentation-only; it does not add a macOS probe, app feature,
  Rust API, generated binding, entitlement, Xcode project change, or release
  metadata change.

Phase 1 may begin only with a separate phase-specific plan naming the disposable
harness location, exact APIs, expected artifacts, and validation commands.

## 2. Source Baseline

### Current shipped wrapping model

CypherAir currently uses Secure Enclave as an indirect device-bound wrapper for
complete OpenPGP secret certificate bytes:

- Rust key generation creates a full OpenPGP certificate with secret material
  and returns public certificate bytes, secret certificate bytes, revocation
  bytes, metadata, and profile information. See
  [pgp-mobile/src/keys/generation.rs](../pgp-mobile/src/keys/generation.rs).
- Swift wraps the secret certificate bytes with a Secure Enclave P-256 key
  agreement key through self-ECDH, HKDF, and AES-GCM. The stored bundle is the
  Secure Enclave key representation, random salt, and sealed box. See
  [Sources/Security/SecureEnclaveManager.swift](../Sources/Security/SecureEnclaveManager.swift).
- Private-key operations reconstruct the wrapping key, unwrap the full secret
  certificate bytes into application memory, pass those bytes to Rust, and
  zeroize the returned `Data` after use. See
  [Sources/Services/KeyManagement/PrivateKeyAccessService.swift](../Sources/Services/KeyManagement/PrivateKeyAccessService.swift),
  [Sources/Services/SigningService.swift](../Sources/Services/SigningService.swift),
  and [Sources/Services/DecryptionService.swift](../Sources/Services/DecryptionService.swift).
- Rust signing and decryption currently create in-memory Sequoia `KeyPair`
  values from unwrapped secret certificates. See
  [pgp-mobile/src/sign.rs](../pgp-mobile/src/sign.rs) and
  [pgp-mobile/src/decrypt.rs](../pgp-mobile/src/decrypt.rs).

This model remains the shipped behavior for Profile A and Profile B. Phase
work for Apple Secure Enclave Custody must not weaken, replace, or silently
branch this current behavior.

### Proposed custody model

Apple Secure Enclave Custody is a future private-key custody mode, not a third
OpenPGP algorithm profile:

- Secure Enclave would generate and hold a P-256 signing private key.
- Secure Enclave would generate and hold a separate P-256 key-agreement
  private key.
- CypherAir would retain public OpenPGP certificate material, custody metadata,
  and non-portable key handles.
- Software would still own OpenPGP certificate, binding, packet, digest, KDF,
  AES Key Wrap, session-key, payload decryption, signature verification, and UI
  status handling.
- The long-term P-256 private scalars would not be imported, exported,
  serialized, logged, cached, or unwrapped into Swift or Rust memory.

This proposed custody model must fail closed if a Secure Enclave key, handle,
Keychain row, access-control state, hardware capability, or required
authentication factor is unavailable. It must not fall back to a software
private key.

## 3. Research Anchors

Apple documentation to cite during later proof work:

- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)
- [SecureEnclave.P256.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
- [SecureEnclave.P256.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
- [kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [SecAccessControlCreateFlags.privateKeyUsage](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage)
- [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)

OpenPGP and Sequoia references:

- [RFC 9580: OpenPGP](https://www.rfc-editor.org/rfc/rfc9580)
- [RFC 6637: ECC in OpenPGP](https://www.rfc-editor.org/rfc/rfc6637.html)
- [Sequoia `Signer`](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/trait.Signer.html)
- [Sequoia `Decryptor`](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/trait.Decryptor.html)
- [Sequoia ECDH module](https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/crypto/ecdh/index.html)

The current local dependency baseline is Sequoia OpenPGP 2.3.0 in
[pgp-mobile/Cargo.toml](../pgp-mobile/Cargo.toml) and
[pgp-mobile/Cargo.lock](../pgp-mobile/Cargo.lock). If the dependency changes,
later phase evidence must identify the exact version used.

## 4. Non-Negotiable Invariants

Later phases must preserve the product and security invariants owned by the
truth-source documents, including:

- No network access, telemetry, update checks, sockets, or network SDKs.
- No new permissions beyond the existing biometric usage description.
- No plaintext, private-key material, session keys, shared secrets, AES Key
  Wrap keys, key handles, or stable fingerprints in logs or traces.
- AEAD/MDC authentication failure aborts without exposing partial plaintext.
- Current Profile A and Profile B software-key behavior remains unaffected.
- Secure Enclave Custody has no private-key import, private-key export,
  software fallback private key, cloud escrow, iCloud recovery, or recovery
  server path.
- P-256 signing and key-agreement custody must use separate Secure Enclave keys.
- Unsupported algorithm/profile/custody combinations must be rejected before
  key creation or UI exposure.

Do not copy this list into every later phase note. Later phase notes should
link here and add only phase-specific invariants or deviations.

## 5. Evidence Note Template

Each later phase should create or append a dated evidence note using this
format:

```text
# Apple Secure Enclave Custody POC Phase N Evidence

> Status:
> Date:
> Purpose:
> Audience:
> Truth sources:
> Evidence roots:
> Current-state note:

## Environment

- macOS/iOS/iPadOS/visionOS version:
- Hardware class:
- Xcode version:
- Swift toolchain:
- Rust toolchain:
- Sequoia version:
- Secure Enclave availability:
- Authentication/access-control setup:

## Source References

- Apple documents:
- OpenPGP/RFC references:
- Sequoia APIs/source:
- CypherAir files:

## Harness Scope

- Disposable location:
- APIs exercised:
- Inputs:
- Outputs/artifacts:
- Explicit non-goals:

## Positive Results

- Result:
- Evidence:
- Artifact path or command:

## Failure Results

- Missing handle:
- Wrong handle:
- Unavailable hardware:
- Authentication cancellation:
- Authentication failure or lockout:
- Tampering:
- Unsupported combination:

## Invariants Checked

- Current Profile A/B unchanged:
- No private-key import/export:
- No software fallback:
- No partial plaintext on auth failure:
- No secret logging:
- Separate signing/key-agreement keys:

## Residual Risks

- Open questions:
- Untested surfaces:
- Evidence limitations:

## Next-Phase Entry Condition

- Required result before proceeding:
- Required plan before touching production files:
```

## 6. Shared Validation Question Register

Later phases should answer these questions with evidence before production
planning begins:

1. Apple primitive behavior: Can macOS Secure Enclave-capable hardware generate,
   persist, reconstruct, and use distinct P-256 signing and key-agreement keys?
2. Apple failure behavior: How do missing handles, wrong handles, unavailable
   hardware, authentication cancellation, authentication failure, and lockout
   report through CryptoKit and Keychain APIs?
3. Export boundary: Which supported APIs expose public key material, key-handle
   representation, DER/raw signature bytes, and shared-secret derivation output,
   and which APIs prove that private scalar export is unavailable?
4. Public certificate feasibility: Can CypherAir construct valid OpenPGP P-256
   public certificate material around Secure Enclave public keys without storing
   private scalars?
5. Version choice: Do v4, v6, or both OpenPGP certificate shapes work for the
   proposed P-256 custody mode, and what interoperability/security tradeoff
   does each create?
6. Binding and revocation: Which certification, subkey binding, revocation,
   expiry update, selective revocation, and contact certification signatures
   are required, and can they be produced through external signing only?
7. External signing: Can Secure Enclave ECDSA output be converted into OpenPGP
   ECDSA `r` and `s` MPIs that Sequoia verifies using only public certificate
   material?
8. Signing boundary: Should validation use Sequoia's `Signer` trait, a narrow
   disposable signature bridge, or both before recommending a production seam?
9. ECDH session-key recovery: Can Secure Enclave P-256 key agreement supply the
   recipient private operation needed to recover a valid OpenPGP session key?
10. ECDH software boundary: Which code should own OpenPGP KDF parameters, AES
    Key Wrap unwrap, session-key validation, and fixed-session-key decrypt
    handoff during validation?
11. AEAD/MDC hard-fail: Does every decrypt experiment still abort without
    exposing partial plaintext on authentication failure or tampered ciphertext?
12. Capability resolution: Can unsupported platform/profile/custody
    combinations be rejected before key creation and before UI exposure?
13. Metadata and handle binding: How will public certificate material,
    fingerprints, key roles, Secure Enclave handles, and custody metadata be
    bound to prevent handle/public-certificate mismatch or role substitution?
14. Access-control policy: Which `SecAccessControl` flags provide the right
    balance between availability and private-key isolation across Standard and
    High Security modes?
15. Test ownership: Which evidence requires hardware validation, which can be
    covered by mockable contracts, and which current Rust/Swift regression
    tests must remain unchanged?

## 7. Exit Markers

Phase 0 is complete when:

- This evidence file exists and can be cited by later phase plans.
- The current wrapping model and proposed custody model are separated.
- The evidence-note template is available.
- The shared validation-question register is available.
- Documentation-only checks pass.

No production planning should start from Phase 0 alone. Production planning
requires successful evidence through the later validation phases described in
the [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md).
