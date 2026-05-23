# Apple Secure Enclave Profile Security Model

> Status: Planning draft. This document records intended security goals and
> feasibility questions for a proposed future mode. Current shipped private-key
> protection remains the Secure Enclave wrapping scheme in [Security](SECURITY.md).

## 1. Security Goal

The goal of Apple Secure Enclave Profile is to keep long-term OpenPGP P-256
private keys inside Apple Secure Enclave for their entire lifecycle. CypherAir
should retain public OpenPGP certificate material and key handles, but should
not receive, serialize, export, log, or cache the long-term private scalar.

This differs from the current shipped Secure Enclave wrapping model. Today,
CypherAir stores a Secure Enclave-protected AES-GCM bundle, then unwraps the
complete OpenPGP secret certificate into memory when signing, decrypting,
exporting, or mutating key material. The proposed mode moves the long-term
signing and ECDH private-key operations to Secure Enclave instead of unwrapping
the OpenPGP secret key into application memory.

## 2. Operation Boundary

Secure Enclave should perform only the long-term private-key operations that it
supports:

- P-256 ECDSA signing for OpenPGP signatures.
- P-256 ECDH key agreement for OpenPGP ECDH PKESK decryption.

Software still owns the surrounding OpenPGP work:

- OpenPGP certificate, binding, and packet construction.
- Hashing and digest preparation before signing.
- Encoding Secure Enclave ECDSA output into OpenPGP `r` and `s` MPIs.
- Parsing PKESK packets and identifying the matching key.
- Running the OpenPGP ECDH KDF and AES Key Wrap / unwrap steps.
- Holding the decrypted session key for message decryption.
- Decrypting the message payload and enforcing AEAD/MDC authentication.
- Verifying signatures and mapping detailed verification status.

This means the mode reduces exposure of the long-term private key, but it does
not remove all sensitive memory from the app. Session keys, decrypted plaintext,
and transient derived OpenPGP values still require the existing zeroization,
temporary-file, and hard-fail protections.

## 3. Hard Requirements

The production design must preserve these requirements:

- Secure Enclave private keys are generated on device. Preexisting private keys
  are never imported into Secure Enclave.
- No complete private-key export path exists for this mode.
- No software fallback private key exists alongside the Secure Enclave key.
- If the Secure Enclave key, key handle, Keychain row, access-control state, or
  required authentication factor is unavailable, private-key operations fail
  closed.
- Device-bound keys are never marked as ordinary backed-up keys.
- Authentication cancellation, lockout, or unavailable hardware must not trigger
  a degraded software path.
- Existing AEAD/MDC hard-fail behavior remains mandatory: authentication failure
  aborts without exposing partial plaintext.
- Logs and traces must not contain plaintext, private-key material, session keys,
  ECDH shared secrets, AES Key Wrap keys, key handles, or stable fingerprints.

## 4. Standards And Library Fit

RFC 9580 supports NIST P-256 for ECDSA and ECDH. It defines ECDSA signatures as
two MPIs (`r`, `s`) and ECDH PKESK processing as an ephemeral public point plus
an encoded wrapped session key. For P-256 ECDH, software must use the OpenPGP
KDF parameters and AES Key Wrap behavior required by the standard.

Sequoia 2.3 exposes `Signer` and `Decryptor` traits for external private-key
storage mechanisms. That is the likely architectural seam for a production
design, because it allows Sequoia to keep owning OpenPGP packet semantics while
private-key operations can be delegated. The current CypherAir Rust code still
uses in-memory `KeyPair` values created from unwrapped secret certificates in
`pgp-mobile/src/sign.rs` and `pgp-mobile/src/decrypt.rs`.

The existing `decrypt_with_fixed_session_key_detailed` helper may be useful for
POC work after a Secure Enclave path recovers an OpenPGP session key. It should
not be treated as a required production design until POC results show where the
cleanest boundary belongs.

## 5. Recovery And Availability Risks

This mode intentionally trades portability for stronger private-key isolation.
The product and implementation must treat availability loss as a first-class
risk:

- A lost, erased, or replaced device means the private key is not recoverable.
- A deleted or corrupt key handle may make the Secure Enclave key inaccessible.
- Biometric enrollment changes, passcode changes, hardware repair, lockout, or
  platform policy changes may affect availability depending on the final
  `SecAccessControl` policy.
- Existing ciphertext addressed only to that key may be permanently
  undecryptable.

The app may offer revocation export and recovery instructions, but must not
claim to restore the private key. Any future migration or backup feature for
this mode requires a separate design and security review.

## 6. POC Security Questions

The POC must answer these questions before production planning proceeds:

- Can CypherAir construct valid OpenPGP P-256 public certificates without
  storing private scalars?
- Can Secure Enclave ECDSA output be encoded into OpenPGP signatures accepted by
  Sequoia verification?
- Can Secure Enclave ECDH output be integrated with OpenPGP P-256 ECDH KDF and
  AES Key Wrap handling without exposing the long-term private scalar?
- Can certificate binding, revocation, expiry update, and certification
  workflows be supported using external signers only?
- Does the v4 or v6 packet/certificate shape produce the best compatibility and
  security tradeoff for this mode?
- What access-control flags provide the right balance between standard
  availability and high-security behavior across Apple platforms?

## 7. Red Lines

Do not implement any of the following:

- Generating a software P-256 private key and importing it into Secure Enclave.
- Storing a second software private key as recovery for a Secure Enclave key.
- Exporting Secure Enclave private-key material or presenting a key handle as a
  full private-key backup.
- Falling back to current secret-certificate unwrap when a Secure Enclave
  Profile operation fails.
- Mutating existing Profile A/B behavior while experimenting with this mode.
- Treating POC-only packet construction or test hooks as production-ready
  security architecture.
