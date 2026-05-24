# Apple Secure Enclave Custody Security Model

> Status: Proposal planning draft. This document records intended security
> goals and feasibility questions for a proposed future custody mode.
> Purpose: Define the security boundary between Secure Enclave private-key
> operations and software-owned OpenPGP processing.
> Audience: Security reviewers, Swift/Rust implementers, product engineers,
> and AI coding tools.
> Related: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md), and
> current [Security](SECURITY.md).

## 1. Security Goal

The goal of Apple Secure Enclave Custody is to keep long-term OpenPGP P-256
private keys inside Apple Secure Enclave for their entire lifecycle. CypherAir
should retain public OpenPGP certificate material and key handles, but should
not receive, serialize, export, log, or cache the long-term private scalar.

This differs from the current shipped Secure Enclave wrapping model. Today,
CypherAir stores a Secure Enclave-protected AES-GCM bundle, then unwraps the
complete OpenPGP secret certificate into memory when signing, decrypting,
exporting, or mutating key material. The proposed custody mode moves long-term
P-256 signing and ECDH private-key operations to Secure Enclave instead of
unwrapping the OpenPGP secret key into application memory.

## 2. Operation Boundary

Secure Enclave should perform only the long-term private-key operations that it
supports:

- P-256 ECDSA signing through a Secure Enclave signing key.
- P-256 ECDH key agreement through a separate Secure Enclave key-agreement key.

Software still owns the surrounding OpenPGP work:

- OpenPGP certificate, binding, and packet construction.
- Hashing and digest preparation before signing.
- Encoding Secure Enclave ECDSA output into OpenPGP `r` and `s` MPIs.
- Parsing PKESK packets and identifying the matching key.
- Running the OpenPGP ECDH KDF and AES Key Wrap / unwrap steps.
- Holding the decrypted session key for message decryption.
- Decrypting the message payload and enforcing AEAD/MDC authentication.
- Verifying signatures and mapping detailed verification status.

This mode reduces exposure of the long-term private key, but it does not remove
all sensitive memory from the app. Session keys, decrypted plaintext, and
transient derived OpenPGP values still require the existing zeroization,
temporary-file, and hard-fail protections.

## 3. Key Separation Requirement

Production design must use separate Secure Enclave keys for signing and key
agreement. A single P-256 Secure Enclave key must not be used for both ECDSA
signing and ECDH.

This is a design requirement because:

- Apple CryptoKit exposes `SecureEnclave.P256.Signing.PrivateKey` and
  `SecureEnclave.P256.KeyAgreement.PrivateKey` as separate API families.
- OpenPGP key flags distinguish certification/signing usage from encryption
  usage.
- Sequoia's certificate builder rejects ECC keys that are simultaneously marked
  for signing and encryption with `Can't use key for encryption and signing`.
- Separating roles avoids cross-purpose key reuse and keeps future external
  hardware custody designs aligned with OpenPGP usage semantics.

## 4. Hard Requirements

The production design must preserve these requirements:

- Secure Enclave private keys are generated on device. Preexisting private keys
  are never imported into Secure Enclave.
- No complete private-key export path exists for this custody mode.
- No software fallback private key exists alongside the Secure Enclave keys.
- If either Secure Enclave key, key handle, Keychain row, access-control state,
  or required authentication factor is unavailable, the corresponding
  private-key operation fails closed.
- Device-bound keys are never marked as ordinary backed-up keys.
- Authentication cancellation, lockout, or unavailable hardware must not trigger
  a degraded software path.
- Existing AEAD/MDC hard-fail behavior remains mandatory: authentication failure
  aborts without exposing partial plaintext.
- Logs and traces must not contain plaintext, private-key material, session
  keys, ECDH shared secrets, AES Key Wrap keys, key handles, or stable
  fingerprints.
- Capability resolution must prevent unsupported algorithm/profile/custody
  combinations from being created or displayed as selectable configurations.

## 5. Standards And Library Fit

RFC 9580 supports NIST P-256 for ECDSA and ECDH. It defines ECDSA signatures as
two MPIs (`r`, `s`) and ECDH PKESK processing as an ephemeral public point plus
an encoded wrapped session key. RFC 6637 describes OpenPGP ECDH as a combination
of ECC Diffie-Hellman, a KDF, and a key-wrapping method. For P-256 ECDH,
software must use the OpenPGP KDF parameters and AES Key Wrap behavior required
by the standard.

Sequoia 2.3 exposes `Signer` and `Decryptor` traits for external private-key
storage mechanisms. That is the likely architectural seam for a production
design, because it allows Sequoia to keep owning OpenPGP packet semantics while
private-key operations can be delegated. The current CypherAir Rust code still
uses in-memory `KeyPair` values created from unwrapped secret certificates in
`pgp-mobile/src/sign.rs` and `pgp-mobile/src/decrypt.rs`.

Validation evidence must distinguish cryptographic compatibility from
production-candidate custody boundary evidence. A prototype that proves packet
or signature compatibility through a shortcut path is useful, but it must not
be accepted as evidence that the custody boundary is feasible unless it also
uses a representative Secure Enclave key lifecycle and private-operation call
path. The no-software-fallback and no secret-certificate-unwrap fallback
requirements apply to POC acceptance criteria, not only to later production
code.

The existing `decrypt_with_fixed_session_key_detailed` helper may be useful for
validation work after a Secure Enclave path recovers an OpenPGP session key. It
should not be treated as a required production design until validation results
show where the cleanest boundary belongs.

## 6. Recovery And Availability Risks

This mode intentionally trades portability for stronger private-key isolation.
The product and implementation must treat availability loss as a first-class
risk:

- A lost, erased, or replaced device means the private key is not recoverable.
- A deleted or corrupt key handle may make a Secure Enclave key inaccessible.
- Biometric enrollment changes, passcode changes, hardware repair, lockout, or
  platform policy changes may affect availability depending on the final
  `SecAccessControl` policy.
- Existing ciphertext addressed only to that key may be permanently
  undecryptable.

The app may offer revocation artifact export and recovery instructions, but
must not claim to restore the private key. A revocation artifact should be
created while the key is available; the product must not imply that it can be
created after the device-bound private keys are lost.

## 7. Validation Security Questions

The validation track must answer these questions before production planning
proceeds:

- Can CypherAir construct valid OpenPGP P-256 public certificates without
  storing private scalars?
- Can Secure Enclave ECDSA output be encoded into OpenPGP signatures accepted by
  Sequoia verification?
- Can Secure Enclave ECDH output be integrated with OpenPGP P-256 ECDH KDF and
  AES Key Wrap handling without exposing the long-term private scalar?
- Can certificate binding, revocation artifact creation, expiry update,
  selective revocation, and contact certification workflows be supported using
  external signers only?
- Does the v4 or v6 packet/certificate shape produce the best compatibility and
  security tradeoff for this custody mode?
- What access-control flags provide the right balance between availability and
  private-key isolation across Apple platforms?

## 8. Red Lines

Do not implement any of the following:

- Generating a software P-256 private key and importing it into Secure Enclave.
- Reusing one Secure Enclave P-256 key for both signing and ECDH.
- Storing a second software private key as recovery for a Secure Enclave key.
- Exporting Secure Enclave private-key material or presenting a key handle as a
  full private-key backup.
- Falling back to current secret-certificate unwrap when a Secure Enclave
  Custody operation fails.
- Mutating existing Profile A/B behavior while experimenting with this mode.
- Treating proof-only packet construction or test hooks as production-ready
  security architecture.
