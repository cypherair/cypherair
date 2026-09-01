# Key Custody

*Custody promises for the Device-Bound key families, the split-custody design and its red lines, the interop position, and the evidence rules. Family taxonomy is owned by `Sources/Models/Keys/PGPKeyFamily.swift`; app-wide fail-closed and sanitization rules by [SECURITY.md](SECURITY.md).*

## 1. The custody model

Secure Enclave custody is a **custody model, not an algorithm suite**: long-term private operations stay bound to the current device's Secure Enclave — P-256 for the classical device-bound families, RFC 9980 split custody for the post-quantum ones. It sits alongside, and never replaces, the portable software-key model. The design separates OpenPGP **configuration** (version/algorithms/format), private-key **custody** (software secret certificate vs enclave operations), and **operation capability** (what a key can do right now, or an explicit unsupported state) — validity is decided by *family*, never by suite alone. All four device-bound families are exposed wherever Secure Enclave hardware is present, gated on `SecureEnclave.isAvailable` alone, with no per-platform guard (accepted risks: §7).

## 2. Custody promises

- **Private material is never exportable in any operable form.** The export boundary refuses anything but software custody before touching any secret, and the UI never offers a backup flow for device-bound keys.
- **Import into the enclave is not an operation**, and **existing private keys are never converted into Secure Enclave custody**; the product must not imply otherwise.
- **A Keychain handle, public key, or locator is never a recoverable private-key backup** — treating one as such is a stop-and-review condition.
- **Never weaken portable software-key behavior to make custody integration easier** — the second stop-and-review condition.
- **Rust owns all OpenPGP semantics**; the enclave performs only the private primitive through narrow callbacks that never carry secret certificate material (§5).
- **Device-bound keys always require biometrics**, fixed at creation, with no passcode fallback and never the mode-dependent app policy. Keys survive a change of the enrolled biometric set, and biometric-set invalidation must **never** be offered as a user option — for a non-exportable key it is permanent key loss.
- **A Standard ↔ High Security mode switch never re-wraps device-bound custody state.**

## 3. Operation routing

- **Locate before authentication.** Handle lookup by the certificate's public-key bindings is non-prompting; a missing or mismatched handle blocks the operation **without ever showing a biometric sheet**.
- **One approval per operation.** A single authenticated window covers the enclave-handle load and, for split custody, the classical-component unwrap.
- **Roles are distinct handles.** Signing and key agreement route by required role; wrong-role or wrong-public-binding requests fail closed. A Secure Enclave route never falls back to software material.

## 4. Split custody

CryptoKit's Secure Enclave implements ML-KEM and ML-DSA but none of the classical curves, so a whole RFC 9980 composite key cannot be enclave-resident. Device-Bound Post-Quantum therefore splits custody: the PQ components are generated in and never leave the enclave; the classical components are sealed under a fixed-access envelope in their own Keychain namespace with their own payload kind, so a software-custody consumer handed one fails closed rather than opening it. **The custody invariant:** every composite signature and decryption requires an in-enclave ML-DSA/ML-KEM operation; the classical component alone can neither sign nor decrypt, and is never independently reachable through any export or backup path. Split custody needs both halves: an intact enclave handle pair says nothing about the sealed component.

## 5. Structural red lines

- **No OpenPGP wire-format cryptography in Swift.** Swift custody providers perform *exactly* the enclave-resident primitive; all OpenPGP-standardized derivation — the RFC 9980 KEM combiner, AES-256 key unwrap, packet assembly, composite self-verification before any signature is released — stays in the Rust engine. The FFI is not a trust boundary (same process); the rule keeps wire-format cryptography single-sourced and vector-testable in Rust.
- **Never construct Sequoia's native composite secret-key material for device-bound keys** — the native representation requires both components at once. Split custody pairs the public key with custom decryptor/signer implementations.
- **One OpenSSL.** The `crypto-openssl` backend must continue to link through the vendored CypherAir OpenSSL fork — no second OpenSSL build may enter the dependency graph. Nothing mechanical checks this; the next dependency addition is where it would break.

## 6. Interop position

- **The PQ families make no GnuPG claim, and product copy must never imply one.** GnuPG follows LibrePGP, whose post-quantum wire format is different and encryption-only. Portable Legacy remains the GnuPG-compatibility story ([PRODUCT.md](PRODUCT.md)).
- **The interop target for PQ artifacts is the Sequoia lineage** (`sq` at RFC 9980-capable releases). Device-Bound Modern (v6) likewise makes no GnuPG claim; Device-Bound Legacy (v4) is the GnuPG-oriented device-bound family.
- **QR surfaces show an explicit unavailable state, never a silent omission** — PQ certificates exceed single-QR capacity, and multi-part QR is rejected by decision.

## 7. Evidence rules

- **Evidence and diagnostic output never carry** plaintext, private-key material, shared secrets, session keys, KEKs, Keychain locators or handle-set identifiers, stable fingerprints, or temporary capability paths — only pass/fail, scenario labels, sanitized failure categories, algorithm/curve identifiers, packet versions and tags, counts, and the gpg version string.
- **Coverage honesty.** v6 third-party AEAD interop is verified by composition only — no non-Sequoia RFC 9580 implementation is exercised. The software-backed CI lanes drive the production seams with a software-P256 stand-in and **never substitute for real-hardware evidence**. Interactive authentication-cancellation and biometric-lockout evidence is deliberately out of scope; fail-closed behavior is covered by the automated interaction-not-allowed proxy.
- **A platform-specific custody claim requires that platform's own capture**; the shared CryptoKit substrate justifies exposure, not claims.
- **Accepted risks:** visionOS is exposed without dedicated evidence — no Vision Pro hardware; based on the shared substrate, the visionOS build probe, and macOS capture. iPad capture is deferred and not required for release.
