# Apple Secure Enclave Custody

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC closeout; future product, architecture, and security docs will be rewritten separately.
> Successor: None yet.
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.


> Status: Proposal planning draft. This document describes proposed future
> behavior and does not describe shipped behavior.
> Purpose: Define the product model, user-visible semantics, recovery posture,
> and planning boundaries for Apple Secure Enclave-backed private-key custody.
> Audience: Product, design, security, Swift/Rust implementers, reviewers, and
> AI coding tools.
> Related: [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md),
> [PRD](../../PRD.md), [Security](../../SECURITY.md), and
> [Architecture](../../ARCHITECTURE.md).

## 1. Goal

Apple Secure Enclave Custody is a proposed hardware-backed, device-bound
private-key custody mode for CypherAir on Apple platforms. In this mode, Apple
Secure Enclave generates and holds P-256 private keys. CypherAir stores public
OpenPGP certificate material and non-portable key handles. Long-term signing
and ECDH private-key operations are delegated to Secure Enclave so the
long-term private scalar does not enter Swift or Rust plaintext memory.

This is a private-key custody model, not a third OpenPGP algorithm profile.
Profile A and Profile B remain the current software-key OpenPGP profiles:

- Profile A: v4 Ed25519/X25519 for broad GnuPG compatibility.
- Profile B: v6 Ed448/X448 for current RFC 9580 behavior.
- Apple Secure Enclave Custody: proposed hardware-backed custody for supported
  P-256 OpenPGP configurations on Apple platforms.

The security improvement is private-key isolation and device binding. It should
not be described as stronger overall cryptography than Profile B: P-256 does
not provide a higher algorithm security level than Ed448/X448.

## 2. Model Boundary

Future design must separate two dimensions:

- Algorithm/profile dimension: OpenPGP key version, public-key algorithms,
  message-format preferences, S2K/export semantics, and interoperability scope.
- Custody dimension: where long-term private-key operations live, such as
  software secret certificate, Apple Secure Enclave, or future external
  hardware custody.

The UI must not become a fixed list of every possible combination. Instead, key
creation should ask for intent through a constrained product entry point and use
a capability resolver to produce only valid configurations. The resolver must
consider platform support, Secure Enclave availability, OpenPGP rules, Sequoia
support, CypherAir implementation readiness, and product policy.

For this proposal, Apple Secure Enclave Custody is a custody kind. The concrete
Swift/Rust type names and whether existing `PGPKeyProfile` remains only the
algorithm/profile vocabulary are deferred to implementation design.

## 3. Product Shape And UI Semantics

Apple Secure Enclave Custody must be an explicit opt-in at key generation time.
It must not silently replace existing Profile A or Profile B software keys, and
it must not be presented as an upgrade path that converts existing keys. Apple
documentation states that preexisting keys cannot be imported into Secure
Enclave, so existing OpenPGP private keys cannot be migrated into this custody
mode.

The key-generation flow should communicate these facts before creation:

- The long-term private keys are generated on this device and are not
  exportable.
- The mode uses separate Secure Enclave P-256 signing and key-agreement keys.
- Losing the device, erasing Secure Enclave state, losing Keychain handles, or
  losing required biometric/passcode access can make the key permanently
  unusable.
- Existing encrypted messages addressed only to that key may become
  undecryptable after such a loss.
- This mode is intended for users who prefer device-bound private-key isolation
  over full portability.

Key detail UI should distinguish at least these states:

- Algorithm/profile: the OpenPGP profile, key version, and algorithm family.
- Custody: software private key, Apple Secure Enclave Custody, or future custody
  kinds.
- Secure Enclave handle state: available, requires authentication, unavailable,
  missing, or not checked.
- Backup/recovery state: revocation artifact exported, recovery note saved, and
  private key not exportable.

Backup and recovery UI must not show this custody mode as "private key backed
up" or "backup complete". Hardware unavailable, authentication canceled,
Keychain handle missing, or Secure Enclave unavailable states should be shown as
fail-closed private-key operation failures, not as prompts to fall back to a
software private key.

## 4. Expected Capabilities

The proposed mode should preserve CypherAir's OpenPGP product surface as much
as the standards and Apple platform allow:

- Public key sharing through existing public-certificate export, QR, file,
  paste, and contact-import paths if the generated OpenPGP certificate is valid
  and interoperable.
- Signing through a Secure Enclave P-256 signing key, with OpenPGP signature
  packet assembly performed by software.
- Decryption of OpenPGP ECDH PKESK packets through a separate Secure Enclave
  P-256 key-agreement key, with software performing the OpenPGP KDF, AES Key
  Wrap, session-key validation, message decryption, and signature verification.
- Existing plaintext lifecycle, AEAD/MDC hard-fail behavior, no-secret-logging
  rules, zero-network model, and minimal-permission model remain unchanged.

The mode should be available across iOS, iPadOS, macOS, and visionOS only when
the platform and capability resolver report support. Initial feasibility
validation can start on macOS because local development, hardware inspection,
and failure testing are easier there.

## 5. Non-Goals

This planning effort does not introduce a custom encryption format and does not
change CypherAir's zero-network or minimal-permission requirements.

The following are explicitly out of scope for the initial feature concept:

- Importing existing OpenPGP private keys into Secure Enclave.
- Exporting a complete Secure Enclave private key backup.
- Storing a second software private key as recovery for Secure Enclave Custody.
- Cloud escrow, iCloud Keychain sync, recovery servers, or network recovery.
- Replacing Profile A or Profile B software keys.
- Promising decryptability after device loss, Keychain loss, Secure Enclave
  reset, or unavailable authentication factors.

## 6. Recovery Model

Apple Secure Enclave Custody has weaker recoverability than current software-key
custody. A future product flow must say this plainly.

At key creation, the app should generate and prompt the user to export a
revocation artifact when technically feasible. That artifact must be created
while the Secure Enclave keys are still available. The app must not imply that a
revocation artifact can be generated later after device loss, Secure Enclave
loss, key-handle loss, or authentication-factor loss.

The app should also provide a recovery note explaining that the private key
itself cannot be exported and that new keys must be distributed to contacts if
the device-bound key becomes unusable.

A safer status model is:

- "Revocation artifact exported" for key invalidation readiness.
- "Recovery instructions saved" for user education.
- "Private key not exportable" as the persistent custody fact.

## 7. Deferred Lifecycle Questions

The following decisions are deferred until the validation track produces
evidence:

- Whether the production OpenPGP certificate should be v4 or v6.
- Which certificate creation, expiry modification, selective revocation, contact
  certification, and binding refresh operations are supported in v1.
- How much of the OpenPGP packet construction should stay in Rust versus Swift.
- Whether all required certification, binding, revocation, and expiry update
  operations can be performed without ever materializing private key scalars.
- Which product entry points should expose Apple Secure Enclave Custody after
  capability resolution.

## 8. References

- [Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)
- [Apple: SecureEnclave.P256](https://developer.apple.com/documentation/cryptokit/secureenclave/p256)
- [Apple: SecureEnclave.P256.Signing.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
- [Apple: SecureEnclave.P256.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
- [Apple: kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [RFC 9580: OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html)
- [RFC 6637: ECC in OpenPGP](https://www.rfc-editor.org/rfc/rfc6637.html)
