# Key Custody

*Custody promises for the Device-Bound key families, the split-custody design and its red lines, the interop position, and the evidence rules. What ships is stated as shipped; decided-but-unshipped work is explicitly marked **roadmap**. Family taxonomy is owned by `Sources/Models/Keys/PGPKeyFamily.swift`; app-wide fail-closed and sanitization rules by [SECURITY.md](SECURITY.md).*

## 1. The custody model

Secure Enclave custody is a **custody model, not an algorithm suite**: long-term private operations stay bound to the current device's Secure Enclave — P-256 for the classical device-bound families, RFC 9980 split custody for the post-quantum ones. It sits alongside, and never replaces, the portable software-key model. The design separates three concepts: OpenPGP **configuration** (version/algorithms/format — the certificate's own facts, read from the engine's parse), private-key **custody** (portable software key vs enclave operations), and **operation capability** (what a key can do right now, or an explicit unsupported state). Custody is a *property of the family*, derived wherever it is needed and never persisted beside it — an identity cannot state a custody its family does not have.

All four device-bound families are production-exposed wherever Secure Enclave hardware is present — the generation surface and capability resolution gate on `SecureEnclave.isAvailable` alone; there is no per-platform guard (accepted risks: §9).

## 2. Custody promises

- **Private material is never exportable in any operable form.** The enforcement is the custody guard at the export service boundary, which refuses anything but portable (software) custody before touching any secret, backed by the UI never offering a backup flow for device-bound keys.
- **Import into the enclave is not an operation.**
- **Existing private keys are never converted into Secure Enclave custody**, and the product must not imply otherwise.
- **A Keychain handle, public key, or locator is never a recoverable private-key backup** — treating one as such is a stop-and-review condition.
- **Never weaken portable software-key behavior to make custody integration easier** — the second stop-and-review condition.
- Rust owns all OpenPGP semantics; the enclave performs only the private primitive through narrow callbacks that never carry secret certificate material (§6).

## 3. Access control

Every device-bound tier persists role-separated Secure Enclave keys as sealed blobs in tier/role-namespaced Keychain rows (row promises: [STORAGE.md](STORAGE.md) §3), with access control **fixed at creation**: `WhenUnlockedThisDeviceOnly` + `[.privateKeyUsage, .biometryAny]` — no passcode fallback, never the mode-dependent app policy. The split-custody classical wrapping key (§7) fixes the same shape at its own creation site.

Two product rules ride on the flag choice: `biometryAny` keeps the key usable when the enrolled biometric set changes, and `biometryCurrentSet` must **never** be exposed as a user-selectable option — for a non-exportable key, biometric-set invalidation is permanent key loss.

## 4. The mode-switch exemption — invariant and mechanism

**Invariant:** a Standard ↔ High Security mode switch never re-wraps device-bound custody state.

**Mechanism:** two layers; the caller-side custody-kind filter is the enforcement.

1. **Caller-side custody-kind filtering** decides what is enumerated: the mode-switch caller and interrupted-rewrap recovery walk only software-custody identities. This keeps device-bound identities out of the workflow entirely — which matters because a fingerprint with no software envelope classifies as unrecoverable and poisons the whole mode-switch recovery.
2. **The envelope's payload kind is what makes a mis-enumeration fail closed.** The re-wrap opens and re-seals only software-secret-certificate envelopes. The split-custody classical component (§7) is sealed as a different kind in a namespace the workflow never reads, so it is rejected by contract validation before any Secure Enclave call, and would fail the AEAD even if that check were bypassed. There is no input to this workflow that produces a silent custody downgrade.

The fixed access policy (§3) enforces neither: it constrains how the wrapping key may be used, not which envelopes a re-wrap may open. The filter is the difference between a clean switch and a poisoned recovery.

## 5. Operation routing

- **Locate before authentication.** Handle lookup by the certificate's public-key bindings is non-prompting; a missing or mismatched handle blocks the operation **without ever showing a biometric sheet**.
- **One approval per operation.** A single authenticated window covers the enclave-handle load and — for split custody — the classical-component unwrap in the same breath.
- **Roles are distinct handles.** Signing and key agreement route by required role; wrong-role or wrong-public-binding requests fail closed. A Secure Enclave route never falls back to software material ([SECURITY.md](SECURITY.md) §3).

## 6. Split custody

CryptoKit's Secure Enclave implements ML-KEM and ML-DSA but none of the classical curves, so a whole RFC 9980 composite key cannot be enclave-resident. Device-Bound Post-Quantum therefore splits custody: the PQ components are generated in and never leave the enclave; the classical components are sealed under a fixed-access envelope (§7).

**The custody invariant:** every composite signature and decryption requires an in-enclave ML-DSA/ML-KEM operation; the classical component alone can neither sign nor decrypt; the key is never exportable in any operable form, and the classical component is never independently reachable through any export or backup path.

Structural red lines:

- **Seam invariant — no OpenPGP wire-format cryptography in Swift.** Swift custody providers perform *exactly* the enclave-resident primitive; all OpenPGP-standardized derivation — the RFC 9980 KEM combiner, AES-256 key unwrap, packet assembly, composite self-verification before any signature is released — stays in the Rust engine. The FFI is **not** a trust boundary (same process); the rule exists to keep wire-format cryptography single-sourced and vector-testable in Rust.
- **Never construct Sequoia's native composite secret-key material for device-bound keys** — the native representation requires both components at once. Split custody pairs the public key with custom decryptor/signer implementations (the proven external-P-256 architecture).
- **One OpenSSL.** The `crypto-openssl` backend must continue to link through the vendored CypherAir OpenSSL fork — no second OpenSSL build may enter the dependency graph. Nothing mechanical checks this; the next dependency addition is where it would break.

## 7. Classical-component storage

The classical component secrets (Ed25519+X25519, or Ed448+X448 for · High) are concatenated and sealed as one `CAPKEV6` envelope under a fixed-access Secure Enclave wrapping key, stored per fingerprint in the **`split-custody-classical.<fingerprint>`** row family — its own Keychain namespace, distinct from every software-custody row ([STORAGE.md](STORAGE.md) §3).

Two properties hold the boundary, and they are independent:

- **Location.** A single component store is the only writer and only reader of that namespace. No software-custody path resolves a service name that reaches it.
- **Payload kind.** The envelope binding names what it seals (`split-custody-classical-component`), authenticated by both the HKDF `sharedInfo` and the AES-GCM AAD (version map: [STORAGE.md](STORAGE.md) §5). Moving a row does not change what it is: a component handed to a software-certificate consumer is rejected before any Secure Enclave call, and fails the AEAD even if that check is bypassed.

The custody health check reports the component's presence as its own availability value: split custody needs both halves, and an intact enclave handle pair says nothing about the sealed component (§5 routing depends on both).

## 8. Interop position

- **The PQ families make no GnuPG claim, and product copy must never imply one.** GnuPG follows LibrePGP, whose post-quantum wire format is different and encryption-only; the two do not interoperate. Portable Legacy remains the GnuPG-compatibility story ([PRODUCT.md](PRODUCT.md) §6).
- **The interop target for PQ artifacts is the Sequoia lineage** (`sq` at RFC 9980-capable releases). Device-Bound Modern (v6) likewise makes no GnuPG claim (GnuPG has no v6 support); Device-Bound Legacy (v4) is the GnuPG-oriented device-bound family.
- **QR surfaces show an explicit unavailable state, never a silent omission** — PQ certificates are an order of magnitude beyond single-QR capacity (the size classification is Rust-side), and multi-part QR is rejected by decision.

## 9. Evidence rules

- **Sanitizer vocabulary for all evidence and diagnostic output** (console summaries, committed entries, attachments). Must exclude: plaintext, private-key material, ECDH shared secrets, session keys, KEKs, Keychain locators / handle-set identifiers, stable fingerprints, and temporary capability paths. Allowed: pass/fail, scenario labels, sanitized failure-category values, algorithm/curve identifiers, packet versions/tags, counts, and the gpg version string. Enforcement: the evidence summary types are sanitized by construction and test-pinned.
- **Coverage honesty.** v6 third-party AEAD interop is verified **by composition only** (production seam + packet-shape assertions; no non-Sequoia RFC 9580 implementation is exercised — a committed fixture would upgrade this to direct interop). The software-backed CI lanes drive the production seams with a software-P256 stand-in and validate seams, formats, and gpg interop — they **never substitute for real-hardware evidence**. Interactive authentication-cancellation and biometric-lockout evidence is deliberately out of scope (a low-value attended edge case); fail-closed behavior is covered by the automated interaction-not-allowed proxy.
- **The platform-claim rule.** A platform-specific custody claim requires that platform's own capture; the shared CryptoKit substrate justifies exposure, not claims.
- **Accepted risks:** visionOS is exposed without dedicated evidence (maintainer-accepted 2026-06-14 — no Vision Pro hardware; based on the shared substrate, the visionOS build probe, and macOS capture). iPad capture is deferred (shares the iPhone iOS Secure Enclave substrate) and not required for release.
