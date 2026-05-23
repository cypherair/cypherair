# Apple Secure Enclave Profile

> Status: Planning draft. This document describes a proposed future key custody
> mode and does not describe shipped behavior.
> Companion documents:
> [Security](APPLE_SECURE_ENCLAVE_PROFILE_SECURITY.md) and
> [POC Plan](APPLE_SECURE_ENCLAVE_PROFILE_POC.md).

## 1. Goal

Apple Secure Enclave Profile is a proposed high-security, device-bound key mode
for CypherAir on Apple platforms. In this mode, Apple Secure Enclave generates
and holds P-256 private keys. CypherAir stores only public OpenPGP certificate
material and non-portable key handles. Signing and ECDH private-key operations
are delegated to Secure Enclave so the long-term private key does not enter
Swift or Rust plaintext memory.

This is a key custody model, not a replacement for the current OpenPGP profiles.
Profile A and Profile B remain the interoperable software-key profiles:

- Profile A: v4 Ed25519/X25519 for broad GnuPG compatibility.
- Profile B: v6 Ed448/X448 for current RFC 9580 behavior.
- Apple Secure Enclave Profile: proposed P-256 device-bound custody for users
  who accept weaker portability in exchange for stronger private-key isolation.

The exact product model remains open. A future implementation may make this a
new `PGPKeyProfile` case, or may split "algorithm profile" from "private-key
custody kind". This document intentionally does not decide that interface.

## 2. Product Shape

Apple Secure Enclave Profile must be an explicit opt-in at key generation time.
It must not silently replace existing Profile A or Profile B keys, and it must
not be presented as an upgrade path that converts existing keys. Apple
documentation states that preexisting keys cannot be imported into Secure
Enclave, so existing OpenPGP private keys cannot be migrated into this mode.

The key-generation UI should communicate the tradeoff before creating the key:

- The long-term private key is generated on this device and is not exportable.
- Losing the device, erasing Secure Enclave state, losing the Keychain handle,
  or losing required biometric/passcode access can make the key permanently
  unusable.
- Existing encrypted messages addressed only to that key may become
  undecryptable after such a loss.
- This mode is intended for users who prefer device-bound protection over
  complete portability.

Keys in this mode should have a distinct visual/status label such as
"Device-bound Secure Enclave key". They must not be marked as having a normal
private-key backup, because no complete private-key backup exists. The app may
instead track whether the user exported recovery artifacts such as a revocation
certificate and recovery instructions.

## 3. Expected Capabilities

The proposed mode should preserve CypherAir's OpenPGP product surface as much as
the standards and Apple platform allow:

- Public key sharing through existing public-certificate export, QR, file, paste,
  and contact-import paths if the generated OpenPGP certificate is valid and
  interoperable.
- Signing through Secure Enclave P-256 ECDSA, with OpenPGP signature packet
  assembly performed by software.
- Decryption of OpenPGP ECDH PKESK packets by using Secure Enclave for the
  private ECDH operation and software for the OpenPGP KDF, AES Key Wrap,
  session-key validation, message decryption, and signature verification.
- Existing plaintext lifecycle, AEAD/MDC hard-fail behavior, no-secret-logging
  rules, zero-network model, and minimal-permission model remain unchanged.

The mode should be available across iOS, iPadOS, macOS, and visionOS when the
platform reports Secure Enclave availability. Initial feasibility validation can
start on macOS because local development, hardware inspection, and failure
testing are easier there.

## 4. Non-Goals

This planning effort does not introduce a custom encryption format and does not
change CypherAir's zero-network or minimal-permission requirements.

The following are explicitly out of scope for the initial feature concept:

- Importing existing OpenPGP private keys into Secure Enclave.
- Exporting a complete Secure Enclave private key backup.
- Cloud escrow, iCloud Keychain sync, recovery servers, or network recovery.
- Replacing Profile A or Profile B software keys.
- Promising decryptability after device loss, Keychain loss, Secure Enclave
  reset, or unavailable authentication factors.

## 5. Recovery Model

Apple Secure Enclave Profile has weaker recoverability than current software-key
profiles. A future product flow must say this plainly.

At key creation, the app should still generate and prompt the user to export a
revocation certificate when technically feasible. It should also provide a
recovery note explaining that the private key itself cannot be exported and that
new keys must be distributed to contacts if the device-bound key becomes
unusable.

The app must avoid language like "backup complete" for this mode. A safer status
model is:

- "Revocation exported" for key invalidation readiness.
- "Recovery instructions saved" for user education.
- "Private key not exportable" as the persistent security fact.

## 6. Open Questions

The following decisions are deferred until the POC produces evidence:

- Whether the production OpenPGP certificate should be v4 or v6.
- Whether one P-256 Secure Enclave key can serve multiple roles safely, or
  whether the mode should use separate signing and key-agreement keys.
- Whether the product should expose this as a third profile or as a custody
  option under a P-256 algorithm profile.
- How much of the OpenPGP packet construction should stay in Rust versus Swift.
- Whether all required certification, binding, revocation, and expiry update
  operations can be performed without ever materializing private key scalars.

## 7. References

- [Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)
- [Apple: kSecAttrTokenIDSecureEnclave](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [Apple: SecureEnclave.P256.KeyAgreement.PrivateKey](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
- [RFC 9580: OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html)
- [RFC 6637: ECC in OpenPGP](https://www.rfc-editor.org/rfc/rfc6637.html)
