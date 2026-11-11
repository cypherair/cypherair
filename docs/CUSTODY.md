# Key Custody

## 1. The custody model

Secure Enclave custody is a **custody model, not an algorithm suite**: long-term private operations stay bound to the current device's Secure Enclave — P-256 for the classical device-bound families, RFC 9980 split custody for the post-quantum ones. It sits alongside, and never replaces, the portable software-key model.

## 2. Custody promises

- **Private material is never exportable in any operable form.**
- **Import into the enclave is not an operation**, and **existing private keys are never converted into Secure Enclave custody**.
- **An enclave key blob, a public key, or a copy of the sealed key list is never a recoverable private-key backup.**
- **Rust owns all OpenPGP semantics**; the enclave performs only the private primitive through narrow callbacks that never carry secret-key material (§5).
- **Device-bound keys always require biometrics**, fixed at creation, with no passcode fallback. Keys survive a change of the enrolled biometric set, and biometric-set invalidation must **never** be offered as a user option — for a non-exportable key it is permanent key loss.
- **Device-bound keys also require the passphrase.** Every enclave custody key is created with the identity credential as its application password, so a borrowed biometric alone cannot use one — with the single exception of the ML-KEM half (§4), which the enclave cannot decapsulate under the option. A passphrase change never touches custody keys, and there is no mode or policy switch that could.

## 3. Operation routing

- **Check before authentication.** Checking a key's stored material never prompts, because it is part of the key list. A blob that does not match its certificate fails closed when it is loaded.
- **One approval per operation.** A single authenticated window covers the enclave-handle load and, for split custody, the classical-component unwrap; the operation context carries the identity credential silently.
- **Roles are distinct handles.** Signing and key agreement route by required role; wrong-role or wrong-public-binding requests fail closed. A Secure Enclave route never falls back to software material.

## 4. Split custody

CryptoKit's Secure Enclave implements ML-KEM and ML-DSA but none of the curves that RFC 9980 pairs them with, so a whole composite key cannot be enclave-resident. Device-Bound Post-Quantum therefore splits custody: the PQ components are generated in and never leave the enclave; the classical components are sealed against the identity wrapping key with their own payload kind and stored with the key inside the sealed key list, so a software-custody consumer handed one fails closed rather than opening it. **The custody invariant:** every composite signature and decryption requires an in-enclave ML-DSA/ML-KEM operation; the classical component alone can neither sign nor decrypt, and is never independently reachable through any export or backup path. Split custody needs both halves: an intact enclave handle pair says nothing about the sealed component.

**The ML-KEM exception.** The enclave cannot decapsulate with an ML-KEM key created under the application-password option ([SECURITY.md](SECURITY.md) §9), so the ML-KEM half is the one enclave key created without it, under the biometric constraint alone. The passphrase still gates every composite decryption, because the classical half is sealed against the identity wrapping key, which demands it. The ML-DSA half carries the password like every other enclave key.

## 5. Structural red lines

- **No OpenPGP wire-format cryptography in Swift.** Swift custody providers perform *exactly* the enclave-resident primitive; all OpenPGP-standardized derivation — the RFC 9980 KEM combiner, AES-256 key unwrap, packet assembly, composite self-verification before any signature is released — stays in the Rust engine. The FFI is not a trust boundary (same process); the rule keeps wire-format cryptography single-sourced and vector-testable in Rust.
- **Never construct Sequoia's native composite secret-key material for device-bound keys** — the native representation requires both components at once. Split custody pairs the public key with custom decryptor/signer implementations.
- **One OpenSSL.** The `crypto-openssl` backend must continue to link through the vendored CypherAir OpenSSL fork — no second OpenSSL build may enter the dependency graph. Nothing mechanical checks this; the next dependency addition is where it would break.

## 6. Interop position

- **The PQ families make no GnuPG claim.** GnuPG follows LibrePGP, whose post-quantum wire format is different and encryption-only. Portable Legacy remains the GnuPG-compatibility story.
- **The interop target for PQ artifacts is the Sequoia lineage** (`sq` at RFC 9980-capable releases). Device-Bound Modern (v6) likewise makes no GnuPG claim; Device-Bound Legacy (v4) is the GnuPG-oriented device-bound family.
- **v6 interop is tested only against `sq`**, which is built on Sequoia like the engine: no RFC 9580 implementation outside Sequoia is exercised.

## 7. Not built yet

Rules for pieces that are not built yet. Each names the piece that builds it: a piece of [ARCHITECTURE.md](ARCHITECTURE.md) §9, or a screens piece by its issue.

- **#1049, #1063.** The export boundary must refuse anything but software custody before touching any secret.
- **#1063, #1053.** All four device-bound families must be offered wherever Secure Enclave hardware is present, gated on `SecureEnclave.isAvailable` alone, with no per-platform guard.
- **#1063.** Material that is missing or has the wrong form must block the operation **without ever showing a biometric sheet**.
- **#1053.** The UI must never offer a backup flow for device-bound keys.
- **#1053, #1059.** No text may imply that a key can be imported into the enclave or converted into Secure Enclave custody, or that the PQ families are GnuPG-compatible.
