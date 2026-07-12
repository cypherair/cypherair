# Technical Design Document (TDD)

> Status: Canonical current-state.
> Purpose: Exact technical values and project-specific contracts — profiles, format selection, FFI rules, key wrapping values, storage contracts.
> Audience: Developers, security auditors, and AI coding tools.
> Update triggers: Library/backend selection, profile configuration, FFI contract rules, SE wrapping, storage contracts, or MIE enablement change.
> Last reviewed: 2026-07-05.

## 1. OpenPGP Engine

### 1.1 Library

`sequoia-openpgp` (version pinned in `pgp-mobile/Cargo.toml`, currently `=2.4.0`; LGPL-2.0-or-later) — the only Rust OpenPGP implementation with complete RFC 9580 support plus production RFC 9980 (post-quantum) support. Release ordering and the compliance-asset contract: [RELEASE.md](RELEASE.md).

### 1.2 Backend: crypto-openssl (vendored)

`crypto-openssl`, vendored via `openssl-src`: battle-tested, constant-time, no experimental opt-in flags, PQC-capable. The `openssl-src` override for the arm64e chain must stay explicit — the checked-in fork branch plus `Cargo.lock`, never a machine-local `path` dependency ([ARM64E_STATUS.md](ARM64E_STATUS.md)). Feature set: `compression-deflate` is enabled for **reading** compressed messages only; outgoing messages are never compressed; bzip2 is excluded. Release-profile gotcha: LTO and strip stay **disabled** (`lto = false`, `strip = "none"`) — enabling either causes linker failures with vendored OpenSSL; binary size is managed via `codegen-units = 1` and Xcode dead-code elimination instead.

### 1.3 Software Profile Configuration

The two composite Post-Quantum suites each back two families: the ML-DSA-65/ML-KEM-768 suite backs the **Portable Post-Quantum** software key below and **Device-Bound Post-Quantum** split custody, and the ML-DSA-87/ML-KEM-1024 suite backs **Portable Post-Quantum · High** and **Device-Bound Post-Quantum · High** ([SECURE_ENCLAVE_CUSTODY.md](SECURE_ENCLAVE_CUSTODY.md) §4.1). The table below shows the base Post-Quantum tier; the · High tier uses the same RFC 9580/9980 configuration with ML-DSA-87+Ed448 (composite, algo 31) / ML-KEM-1024+X448 (composite, algo 36). Family taxonomy and product exposure: [PRD.md](PRD.md) §3.

| Setting | Legacy (Universal) | Modern | Modern · High (Advanced) | Post-Quantum |
|---------|--------------------|--------|--------------------------|--------------|
| `Profile` | `Profile::RFC4880` | `Profile::RFC9580` | `Profile::RFC9580` | `Profile::RFC9580` |
| `CipherSuite` | `CipherSuite::Cv25519` | `CipherSuite::Cv25519` | `CipherSuite::Cv448` | `CipherSuite::MLDSA65_Ed25519` |
| Key version | v4 | v6 | v6 | v6 |
| Signing algo | Ed25519 (legacy EdDSA) | Ed25519 | Ed448 | ML-DSA-65+Ed25519 (composite, algo 30) |
| Encryption algo | X25519 (legacy ECDH) | X25519 | X448 | ML-KEM-768+X25519 (composite, algo 35) |
| Hash | SHA-512 (accepts SHA-256 for legacy verification) | SHA-512 | SHA-512 | SHA-512 |
| Symmetric | AES-256 | AES-256 | AES-256 | AES-256 (RFC 9980 floor) |
| Message format | SEIPDv1 (MDC) | SEIPDv2 (AEAD OCB) | SEIPDv2 (AEAD OCB) | SEIPDv2 (AEAD OCB) |
| S2K (export) | Iterated+Salted (mode 3) | Argon2id (512 MB / p=4 / ~3s) | Argon2id (512 MB / p=4 / ~3s) | Argon2id (512 MB / p=4 / ~3s) |
| Compression | DEFLATE (read-only) | DEFLATE (read-only) | DEFLATE (read-only) | DEFLATE (read-only) |
| Security level | ~128 bit | ~128 bit | ~224 bit | ~192 bit, quantum-resistant |

Legacy (Universal) and Modern share `CipherSuite::Cv25519` (Ed25519+X25519); they differ only by `Profile` — RFC 4880 yields a v4 key, RFC 9580 a v6 key. Modern · High (Advanced) is the Ed448+X448 v6 tier (`CipherSuite::Cv448`).

**Classification is algorithm-aware, not version-only:** an RFC 9980 composite primary (ML-DSA-65+Ed25519 or ML-DSA-87+Ed448) classifies as Post-Quantum; an Ed25519 v6 primary classifies as Modern; an Ed448 v6 primary classifies as Advanced; v4 classifies as Universal. Any other v6 primary hits the defensive Advanced catch-all (`_ if version >= 6 => Advanced`), so SLH-DSA primaries fall back to Advanced (an under-claim, never an over-claim). The rule lives in one shared function (`classify_profile`) used by `detect_profile`, `parse_key_info`, and the export profile-mismatch guard.

**Legacy (Universal) Features subpacket:** Sequoia defaults to advertising SEIPDv2 support. Legacy generation explicitly sets `Features::empty().set_seipdv1()` so other implementations send SEIPDv1 to this key — otherwise a GnuPG sender would see SEIPDv2 advertised and produce a message it cannot construct correctly. `set_profile(Profile::RFC4880)` is likewise explicit.

### 1.4 Encryption Format Auto-Selection

The message format is determined by the **recipient key versions**, never the sender's profile:

- All recipients v4 → SEIPDv1 (MDC).
- All recipients v6 → SEIPDv2 (AEAD OCB, GCM secondary preference).
- Mixed v4 + v6 → SEIPDv1 (lowest common denominator).
- Encrypt-to-self adds the sender's own key and participates in the same rule (v6 sender + v4 recipient → mixed → SEIPDv1).

Sequoia applies the rule automatically from the recipient certificates; the wrapper implements no manual format selection. Decrypt accepts SEIPDv1 and SEIPDv2 (OCB/GCM) regardless of the user's own profile; legacy SEIPD without MDC is hard-rejected.

Post-quantum recipients ride the same version-driven rule (they are v6): PQ-only → SEIPDv2; mixed PQ + v4 → SEIPDv1, in which case the RFC 9980 **AES-256 floor** still holds inside the SEIPDv1 container (decrypt-time cipher assertions in `portable_pq_message_tests.rs`). The engine also classifies every produced message's quantum safety from its PKESK algorithms (`message_quantum_safety`: fully post-quantum / mixed / none) — the compose surface derives its quantum-safe badge from that artifact-level classification, never from the live recipient selection.

## 2. Rust-to-Swift FFI: UniFFI

Three-layer bridge: the `pgp-mobile` wrapper crate (UniFFI proc-macros, `Vec<u8>`/`String` API, Sequoia internals never exposed) → generated C scaffolding → generated Swift bindings (`Sources/PgpMobile/pgp_mobile.swift`). The real API surface is `pgp-mobile/src/lib.rs`; the adapter layer and its conventions are described in [ARCHITECTURE.md](ARCHITECTURE.md) §2 ("FFI Adapters"). Build/sync mechanics: [TESTING.md](TESTING.md) §2.4.

### Durable Rust / FFI Contract Rules

- **API evolution is additive during migration.** New semantics land first as parallel methods, result records, or enums; superseded surfaces are deleted intentionally once migration gates pass, not kept as permanent compatibility APIs.
- **Payload input classes stay explicit.** Byte-oriented OpenPGP payload inputs are classified `binary-only`, `armored-only`, or `dual-format`; new APIs document which class they accept instead of relying on implicit parser behavior.
- **Cryptographic selectors use bytes, not display strings.** Selector-bearing User ID operations use raw `userIdData + occurrenceIndex`; cryptographically significant payloads stay `Vec<u8>` / `Data`.
- **Discovery helpers are part of the contract when needed.** If a Swift service cannot safely discover required selectors or metadata from the exported surface, the Rust/FFI boundary grows a bounded helper rather than pushing string inference into Swift.
- **Parse/setup failure stays distinct from cryptographic invalidity.** Parse, type, and precondition failures return `Err(PgpError)`; successful parsing followed by crypto failure stays in family-specific result or graded-status types.
- **`PgpError` remains the cross-family fatal boundary.** UniFFI-visible error changes preserve the Rust/Swift 1:1 mapping and are reserved for fatal semantics that cannot be modeled as a family-local result.
- **Signer fingerprint means the primary, not the subkey.** Detailed verify/decrypt summaries expose the signer certificate's primary fingerprint; new APIs either preserve that meaning or add a separate explicit subkey field.
- **Any UniFFI-visible surface change is a multi-layer change** — run the sync-and-validate workflow in [TESTING.md](TESTING.md) §2.4.
- **Plaintext-bearing results inherit Swift-side zeroization expectations** (CLAUDE.md hard constraint 5).

## 3. Secure Enclave Key Wrapping

### 3.1 Constraint

The Secure Enclave natively holds only some key types (P-256, and on current OS versions ML-KEM/ML-DSA) — not the classical curves the software profiles use, which therefore require indirect wrapping. The scheme is identical for all software profiles: the SE protects raw private key bytes regardless of algorithm. Device-bound families are different — their private operations run inside the enclave ([SECURE_ENCLAVE_CUSTODY.md](SECURE_ENCLAVE_CUSTODY.md)). Authoritative wrapping/unwrapping flows, binding details, and ordering rationale: [SECURITY.md](SECURITY.md) §3; mode-switch procedure and recovery invariant: [SECURITY.md](SECURITY.md) §4.

### 3.2 Access Control (dual mode)

| Mode | Flags | Behavior |
|------|-------|----------|
| Standard (default) | `[.privateKeyUsage, .biometryAny, .or, .devicePasscode]` | Biometrics with passcode fallback (≈ `deviceOwnerAuthentication`) |
| High Security | `[.privateKeyUsage, .biometryAny]` | Biometrics only; key inaccessible while biometrics are unavailable |

### 3.3 Keychain Layout

One self-contained `CAPKEV1` envelope row per identity (fingerprint = lowercase hex, no separators), plus a transient pending row during mode-switch / modify-expiry recovery:

```
com.cypherair.v1.privkey-envelope.<fingerprint>
com.cypherair.v1.pending-privkey-envelope.<fingerprint>
```

Rows are `kSecClassGenericPassword` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and **no per-row access control** — the auth-mode policy is baked into the folded SE key at creation, and device authentication triggers when the Secure Enclave reconstructs and uses that key during unseal. (The ProtectedData root-secret and wrapped-DMK rows are a separate model — [SECURITY.md](SECURITY.md) §3 "ProtectedData Device-Binding Note" — and the full row inventory is [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).)

### 3.4 Key Loss & Recovery

SE keys are destroyed by device erase, iCloud restore, or backup restore. The app detects the unusable envelope, prompts restore-from-backup, generates a new SE wrapping key, and re-wraps.

## 4. Argon2id Configuration

Applies to the four v6 portable software families that use Argon2id S2K — Portable Modern, Portable Modern · High, Portable Post-Quantum, and Portable Post-Quantum · High; Portable Legacy uses Iterated+Salted (mode 3). Canonical scope, guard procedure, and refusal message: [SECURITY.md](SECURITY.md) §7.

| Parameter | Value | RFC 9580 encoding | Rationale |
|-----------|-------|-------------------|-----------|
| Memory | 512 MB | `encoded_m = 19` | ~6% of the 8 GB minimum-device RAM |
| Parallelism | 4 | `p = 4` | 128 MB per lane |
| Time | 3 passes (~3s target) | `t = 3` | Stable, explicit export profile |

## 5. QR Code

Format: `cypherair://import/v1/<base64url binary key, no padding>` — self-describing binary OpenPGP, works for v4 and v6 keys. Classical certificates: ~250–350 bytes binary → <600 chars, single QR at Level M. Generate with `CIQRCodeGenerator`; decode from photo with PHPicker + `CIDetector`. Post-quantum certificates are too large for QR (~30 KB armored) and exchange via file/share/clipboard instead; QR surfaces show an explicit unavailable state ([POST_QUANTUM.md](POST_QUANTUM.md) §4).

## 6. Storage Architecture

Row-level storage locations, target classes, current status, and migration readiness live in [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md). This TDD owns the technical contracts for ProtectedData behavior, migration safety, relock, and recovery. Permanent exceptions stay limited to documented boot-authentication, private-key-material, framework-bootstrap, test-only, temporary, and out-of-app-custody surfaces as classified in the inventory.

### 6.1 ProtectedData Current Contract

ProtectedData is the shared framework for app-owned local state that opens only after app privacy authentication. It is separate from the private-key material domain and stores no OpenPGP secret key bytes.

- `ProtectedDataRegistry` is the plaintext bootstrap authority for committed domain membership, shared-resource lifecycle state, and a single pending create/delete mutation.
- Pre-auth startup may classify the registry and per-domain bootstrap metadata, but must not load the root secret, unwrap any domain master key, or open protected payload generations.
- The shared root secret is a single self-contained `CAPDSEV3` Keychain envelope loaded with an authenticated `LAContext` handoff; the ProtectedData-only SE device-binding key is folded into it (no separate row) and reconstructed to silently unwrap it under the same app-session gate.
- `ProtectedDomainKeyManager` derives a wrapping root key from the raw root secret (which is then zeroized) and unwraps per-domain 256-bit master keys from Keychain-backed `CADMKV2` wrapped-DMK records (`com.cypherair.v1.protected-data.domain-key.*`, staged/committed rows).
- Registry, bootstrap metadata, scratch writes, and domain payload generations verify explicit file protection where available.
- Every production domain opens through the post-auth handoff, decodes strictly, enters recovery instead of silently resetting unreadable committed state, and clears decrypted domain-local state on relock. Relock clears the wrapping root key, unwrapped DMKs, and registered domain-local state; a relock-participant failure latches runtime-only `restartRequired`.

### 6.2 Contacts Domain Contract

The protected Contacts payload is schema v2 `ContactsDomainSnapshot` with `ContactIdentity`, `ContactKeyRecord`, `ContactTag`, and `ContactCertificationArtifactReference` records, persisted via SQLCipher at `Application Support/ProtectedData/contacts/contacts.sqlite`. `ContactService` is the app/UI facade; `ContactsDomainStore` opens the domain post-auth and keys SQLCipher with the unwrapped `contacts` domain master key through raw-key syntax — no separate database-key record. Missing database authority, wrong key, corrupt DB, `application_id` mismatch, unsupported `user_version`, or integrity failure routes to recovery.

Key-usage rules:

- At most one encryptable key per contact is **preferred**; only preferred keys participate in encryption recipient resolution.
- **Additional** active keys remain usable contact-owned material but are not selected for encryption unless made preferred.
- **Historical** keys are excluded from encryption but remain available for signer recognition and audit context.
- Merge operations preserve per-key manual verification and certification state, union tags, and keep certification artifacts attached to their original key records.
- Tags normalize display text for case-insensitive uniqueness. In Encrypt, applying a tag is a one-way batch selection: it adds the tag's currently encryptable contacts to `selectedRecipients` (reporting skipped contacts that lack a preferred encryptable key) and leaves the final target as explicit selected contact IDs the user may edit or clear.
- Search indexes, screen filters, pending route state, recipient selections, and signer caches are runtime-only — cleared on relock or content clear, never persisted outside the protected payload.

Migration and exception rules:

- `private-key-control` settings and recovery-journal state mutate only inside the protected payload; key metadata persists only in `key-metadata`; private-key envelope rows stay in the Keychain/Secure Enclave private-key domain.
- Self-test reports are in-memory export-only data. Temporary/export/tutorial artifacts run through `AppTemporaryArtifactStore` with the ephemeral-with-cleanup behavior classified in the inventory.
- Legacy flat Contacts files under `Documents/contacts` are outside supported app state — not read, migrated, quarantined, or reset-cleaned — and must never become fallback sources of truth. Unsupported Contacts schema versions fail closed to recovery.
- Future protected-domain migrations preserve readable source state until the protected destination is created, opened, and verified through the normal post-auth path.
- Protected-after-unlock settings must not add pre-unlock shadow copies; `appSessionAuthenticationPolicy` is the only ordinary-settings boot-authentication exception.
- Contacts package exchange is not implemented; any future complete Contacts backup must be designed separately as mandatory encrypted export/import.

## 7. Memory Integrity Enforcement (MIE)

MIE is required because vendored OpenSSL is C code. Enablement is the Enhanced Security capability (`ENABLE_ENHANCED_SECURITY = YES`); the canonical entitlement-key list, device support, and validation workflow live in [SECURITY.md](SECURITY.md) §8.
