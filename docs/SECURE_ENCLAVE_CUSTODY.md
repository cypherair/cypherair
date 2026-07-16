# Secure Enclave Custody

> Status: Canonical current-state.
> Purpose: The durable reference for Apple Secure Enclave-backed OpenPGP private-key custody (the Device-Bound key families): architecture, security contract, operation surface, and the captured hardware/interop evidence.
> Audience: Security reviewers, release owners, Swift/Rust implementers, test owners, and AI coding tools.
> Source of truth: This document, the code under `Sources/Security/SecureEnclaveCustody*` / `Sources/Security/SecureEnclaveComposite*` / `Sources/Services/KeyManagement/` / `pgp-mobile/src/`, and the companion canonical docs cited below.
> Update triggers: Any change to the custody model, access-control policy, red lines, operation surface, persisted-state classification, Rust/UniFFI boundary, or evidence matrix.
> Last reviewed: 2026-07-16.

## 1. Overview

Secure Enclave custody is a device-bound private-key custody model: long-term signing and key-agreement private operations stay bound to the current device's Secure Enclave — P-256 for the classical device-bound families, RFC 9980 split custody for Device-Bound Post-Quantum (§4.1). It sits alongside, and does not replace, the portable software-key model. It is a custody model, not a third OpenPGP profile.

The product presents it as four of the nine key families ([PRD.md](PRD.md) §3 owns the full taxonomy, generation UX, commitment sheet, and compatibility copy):

- **Device-Bound Legacy** — P-256, v4 certificate.
- **Device-Bound Modern** — P-256, v6 (RFC 9580) certificate.
- **Device-Bound Post-Quantum** — RFC 9980 composite split custody (ML-DSA-65/ML-KEM-768), v6 certificate (§4.1).
- **Device-Bound Post-Quantum · High** — RFC 9980 composite split custody (ML-DSA-87/ML-KEM-1024), v6 certificate (§4.1).

All four are implemented, production-exposed wherever Secure Enclave hardware is present (capability-resolver-gated), and ship through the tag-first stable releases — Device-Bound Post-Quantum since `cypherair-v1.5.0-build15000`.

## 2. Architecture and ownership

The integration separates three concepts the software-key model partly compressed — OpenPGP **configuration** (version/algorithm/format/interop target), private-key **custody** (software secret certificate vs Secure Enclave private operations), and **operation capability** (what a key can do now, or an explicit unsupported state). The durable boundary:

- **Service layer** owns user workflows; it asks `PGPKeyCapabilityResolver` for availability and `PrivateKeyOperationRouter` for a private-operation route, and never touches Keychain rows or Secure Enclave access-control flags directly.
- **Security layer** (`Sources/Security/SecureEnclaveCustody*`, `SecureEnclaveComposite*`) owns the Apple primitives through one CryptoKit custody stack: every device-bound tier (classical P-256, ML-DSA/ML-KEM components) persists its enclave keys as `dataRepresentation` blobs in tier/role-namespaced generic-password rows, behind one handle store per tier for role-separated creation/loading, non-prompting locate by public binding, access-control enforcement, and cleanup / local-reset participation.
- **Rust/OpenPGP layer** (`pgp-mobile/src/`, Sequoia) owns OpenPGP semantics: certificate construction/parsing, packet construction, ECDH KDF, AES Key Wrap, session-key validation, streaming payload decrypt, and MDC/AEAD hard-fail.

Secure Enclave private operations cross the Rust boundary through the **external signer / key-agreement seams** (P-256) and the **external composite signer / decryptor seams** (ML-DSA/ML-KEM): Rust delegates only the private primitive and never receives private scalars or a complete secret certificate. The software-custody route is unchanged and is the only route that unwraps and zeroizes a secret certificate.

Persisted state: protected `key-metadata` schema v2 stores only the non-secret `PGPKeyIdentity` projection (configuration identity, custody kind, public certificate association, operation availability, revocation presence, non-exportability) — never access-control policy, handle locators, or secret material. The handles live in the data-protection Keychain / Secure Enclave boundary. Row-level classification: [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).

## 3. Security contract

The authoritative custody red lines — handles and access control, the external operation boundary, dispatch and fail-closed (including no software fallback on a Secure Enclave route, with failures surfacing only as sanitized `PGPKeyOperationFailureCategory` values), sanitized failure mapping, storage/export/hard-fail, reset and recovery — live in [SECURITY.md](SECURITY.md) §3 and are enforced in code and test-pinned.

### 3.1 Access-control policy

The fixed creation policy (`privateKeyUsage` + `biometryAny`, no passcode fallback — [SECURITY.md](SECURITY.md) §3) carries two custody-specific product rules: `biometryAny` keeps the key usable when the enrolled biometric set changes, and `biometryCurrentSet` must **not** be exposed as a user-selectable option (for a non-exportable key it creates a high permanent-loss risk). Secure Enclave custody must **not** use the Standard/High-Security in-place rewrap to change access policy — that rewrap model remains software-custody only.

### 3.2 Custody-specific stop conditions

Beyond the SECURITY.md §3 red lines, return to security review before either of the following:

- treating a Keychain handle, public key, or locator as a recoverable private-key backup;
- weakening current portable software-key behavior to make custody integration easier.

### 3.3 Payload hard-fail

The private-operation route may recover a session key, but final plaintext release stays gated by Sequoia payload authentication and the read-to-completion contract (the MDC/AEAD hard-fail and `.tmp`-then-rename rules are SECURITY.md §3 red lines).

## 4. Supported operation surface

Resolved by `PGPKeyCapabilityResolver` and routed by `PrivateKeyOperationRouter` (`Sources/Services/KeyManagement/`):

| Operation | Secure Enclave custody | Route |
| --- | --- | --- |
| Generate | Supported | builds the public-only v4/v6 cert + revocation artifact bound to distinct signing/key-agreement public keys |
| Sign / certify / revoke / modify-expiry | Supported (signing role) | external signer seam |
| Decrypt (message + streaming file) | Supported (key-agreement role) | external ECDH / composite decapsulation seam |
| Export public material | Supported when present | uses stored public artifact |
| Export revocation artifact | Supported when present | uses stored revocation artifact |
| Export / back up private material | **Unsupported (red line)** | `.operationUnsupportedForCustody` |
| Import existing private key into Secure Enclave | **Unsupported (red line)** | not an operation |

Signing and key agreement route to **distinct** handles by required role; wrong-role or wrong-public-binding requests fail closed.

### 4.1 Device-Bound Post-Quantum (split custody)

Device-Bound Post-Quantum applies the same custody model to RFC 9980 composite keys (ML-DSA-65+Ed25519 signing, ML-KEM-768+X25519 encryption) with the same operation surface. Because CryptoKit's Secure Enclave offers ML-DSA/ML-KEM but no Ed25519/X25519, custody is **split**:

- **Post-quantum components** are generated and held in the Secure Enclave through the shared custody handle store (their tiers of the same blob-row model every device-bound tier uses; the blob is useless off-device), gated by the same fixed `privateKeyUsage` + `biometryAny` access control baked in at creation.
- **Classical components** (one 32-byte Ed25519 seed + one 32-byte X25519 scalar, generated inside Rust) are sealed as a single payload under a dedicated fixed-access Secure Enclave `CAPKEV1` envelope, stored per fingerprint. The fixed policy — never the mode-dependent app wrapping policy — keeps every device-bound key exempt from Standard/High Security mode-switch re-wrap.

Invariants ([POST_QUANTUM.md](POST_QUANTUM.md) §2–§3): every composite signature or decryption requires an in-enclave ML-DSA/ML-KEM operation; the classical component alone can neither sign nor decrypt; the key is never exportable in any operable form. The Rust engine owns all OpenPGP derivation — the RFC 9980 KEM combiner, AES-256 key unwrap, packet assembly, and composite self-verification before any signature is released — while Swift performs exactly the enclave primitive through the external composite provider seams, mirroring the external P-256 seams.

Routing mirrors the P-256 flow: non-prompting handle lookup by the certificate's component public keys, then one authenticated biometric window covering the enclave-handle load and the classical-component unwrap. Deletion removes the enclave blobs and the classical envelope; Reset All Local Data cleans all composite rows. Real-hardware evidence: `DeviceSecureEnclaveCompositeCustodyTests` (generation, decrypt through the vendored RFC 9980 combiner, cleartext sign/verify, wrong-classical-component fail-closed) — one biometric approval per run.

## 5. Compatibility language

- **Device-Bound Legacy (v4)** — described as GnuPG-oriented; entitled by the v4 GnuPG interop evidence (§8).
- **Device-Bound Modern (v6)** — described as RFC 9580 / AEAD-oriented OpenPGP; it makes **no** GnuPG interoperability claim (GnuPG does not support v6 keys).
- **Device-Bound Post-Quantum** — makes no GnuPG claim ([POST_QUANTUM.md](POST_QUANTUM.md) §1).
- **Device-Bound Post-Quantum · High** — RFC 9980 ML-DSA-87+Ed448 / ML-KEM-1024+X448; makes no GnuPG claim ([POST_QUANTUM.md](POST_QUANTUM.md) §1).
- Existing private keys are never converted into Secure Enclave custody; the product must not imply otherwise.

## 6. Validation

Test lanes, suites, and CI jobs are owned by [TESTING.md](TESTING.md): the custody unit suites run in `CypherAir-UnitTests` (mocks + software P-256), real-hardware evidence runs in `CypherAir-DeviceTests` / `CypherAir-DangerousDeviceTests`, and the GnuPG interop lanes are TESTING.md §5. This document keeps only the captured evidence (§8).

## 7. Release posture

The device-bound families are shipped, user-reachable product surface; stable releases follow [RELEASE.md](RELEASE.md). Custody changes remain security-critical ([SECURITY.md](SECURITY.md) §10) with the hardware-evidence expectations of §8.

## 8. Evidence record

Evidence is captured by the device test plans (real Secure Enclave, biometric) and the Rust/interop lanes, emitting sanitized one-line summaries. The sanitizer expectations (§8.4) apply to all evidence output.

### 8.1 Real-hardware Secure Enclave evidence

Real SE private operations via `CypherAir-DeviceTests` (and the destructive `CypherAir-DangerousDeviceTests`), one biometric approval per run.

> **Recapture pending (issue #683).** The P-256 rows below were captured against the retired SecKey custody implementation; the CryptoKit consolidation requires re-attestation. macOS recapture runs before the consolidation PR merges; the iPhone rows are recaptured or explicitly re-deferred at that point.

| Scenario | macOS | iPhone | iPad | visionOS |
| --- | --- | --- | --- | --- |
| handle-pair generation + persistence | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| signing (real ECDSA) | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| ECDH decrypt v4 (SEIPDv1/MDC) | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| ECDH decrypt v6 (SEIPDv2/AEAD) | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| hidden generation (v4 cert via real signing handle) | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| missing handle fails closed | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| wrong public binding fails closed | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| wrong role fails closed (signer/KA guards) | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| payload tamper hard-fail (no partial plaintext) | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| local-reset cleanup (dangerous plan) | ✅ captured | deferred | deferred | exposed, no evidence |
| interaction-not-allowed proxy (fail-closed) | ✅ captured | ✅ captured | deferred | exposed, no evidence |
| split-custody composite, both tiers (generate / combiner decrypt / sign / wrong-classical fail-closed) | ✅ captured (`DeviceSecureEnclaveCompositeCustodyTests` — base ML-DSA-65/ML-KEM-768 and · High ML-DSA-87/ML-KEM-1024, 2026-07) | deferred | deferred | exposed, no evidence |

Capture notes:

- **macOS** (arm64e, real Secure Enclave, gpg 2.5.19, 2026-06-13): all eleven P-256 rows captured — non-interactive scenarios, biometric scenarios (Touch ID approved at the sensor), and the destructive local-reset proof.
- **iPhone** (iOS 27.0 developer beta, real Secure Enclave, 2026-06-14): the ten non-destructive P-256 rows captured; the local-reset row is covered on macOS.
- **iPad** — deferred. iPad runs the same iOS Secure Enclave substrate and LocalAuthentication stack as iPhone; dedicated capture is recommended before any iPad-specific custody claim.
- **visionOS** — exposed without dedicated evidence (accepted risk, §9).

Authentication-cancellation and biometric-lockout positive *interactive* evidence is intentionally out of scope (a low-value attended edge case); the fail-closed behavior is covered by the automated `interaction-not-allowed` proxy and the `LAError`→category normalizer.

### 8.2 Software-backed interop evidence (CI)

These lanes drive the **production** Secure Enclave seams with a software-P256 stand-in (`pgp-mobile/tests/common/secure_enclave.rs`), validating the seam and packet shapes — and full v4 gpg interoperability — without hardware. Lane/CI mechanics: [TESTING.md](TESTING.md) §5.

| Scenario | Lane | Acceptance criteria | Status |
| --- | --- | --- | --- |
| v4: gpg imports SE public cert | CI (mandatory) | ECDSA P-256 primary (algo 19) + ECDH subkey (algo 18), `nistp256`, fingerprint listed | ✅ macOS, gpg 2.5.19 |
| v4: gpg verifies SE signature | CI (mandatory) | `gpg --verify` → "Good signature" | ✅ macOS, gpg 2.5.19 |
| v4: gpg→SE encrypt, production seam decrypts | CI (mandatory) | plaintext recovered; **PKESK v3 + SEIPDv1/MDC, not AEAD** | ✅ macOS, gpg 2.5.19 |
| v4: gpg signed+encrypted, production decrypt+verify | CI (mandatory) | plaintext recovered; signature `Verified` | ✅ macOS, gpg 2.5.19 |
| v4: bidirectional sign+encrypt | CI (mandatory) | both directions recover plaintext + verify | ✅ macOS, gpg 2.5.19 |
| v4: tampered gpg ciphertext fails closed | CI (mandatory) | production seam errors, no plaintext | ✅ macOS, gpg 2.5.19 |
| v6: SEIPDv2/AEAD-OCB round-trip | CI (default) | plaintext recovered; **PKESK v6 + SEIPDv2** | ✅ macOS |
| v6: AEAD tamper fails closed | CI (default) | production seam errors, no plaintext | ✅ macOS |
| v6: signed+encrypted decrypt+verify | CI (default) | plaintext recovered; signature `Verified` | ✅ macOS |
| v6: gpg rejects v6 public key | CI (default) | `gpg --import` non-zero (v6 unsupported) | ✅ (`gnupg_binary_tests`) |
| Portable Legacy (software): gpg bidirectional | CI (mandatory) | import / decrypt / verify / reject-v6 | ✅ macOS, gpg 2.5.19 |

### 8.3 Real-SE ↔ gpg bidirectional interop (manual lane)

`CypherAir-InteropEvidenceTests` → `DeviceSecureEnclaveGnuPGInteropEvidenceTests` generates a real device-bound SE v4 key and drives the local `gpg` binary bidirectionally. macOS-only (gpg cannot run on iOS/iPadOS), operator-run.

| Direction | macOS | iPhone / iPad |
| --- | --- | --- |
| SE signs → gpg verifies | ✅ captured (manual plan) | documented manual cross-device |
| gpg encrypts → production seam decrypts (real SE ECDH) | ✅ captured (manual plan) | documented manual cross-device |

Captured on real Secure Enclave + gpg 2.5.19 (macOS arm64e, 2026-06-13): both directions passed. The iPhone/iPad cross-device procedure (produce SE artifacts on device, transfer to the Mac for gpg, transfer ciphertext back, decrypt through the production path) is a documented manual step because gpg runs only on the Mac.

### 8.4 Sanitizer expectations

All evidence output (console summaries, committed matrix entries, attachments) **must exclude**: plaintext, private-key material, ECDH shared secrets, session keys, KEKs, Keychain locators / application tags / handle-set identifiers, stable fingerprints, and temporary capability paths. Allowed: pass/fail, scenario labels, sanitized `PGPKeyOperationFailureCategory` values, algorithm/curve identifiers, packet versions/tags, counts, and the gpg version string. Enforcement: `SecureEnclaveCustodyEvidenceSummary` is sanitized by construction (enums + integer counts only) and pinned by `SecureEnclaveCustodyEvidenceLogTests`; the device tests assert trace/error sanitization; the Rust lanes print only scenario labels.

### 8.5 GnuPG version policy

The v4 interop contract (ECDSA/ECDH P-256, PKESK v3, SEIPDv1/MDC, v6 rejection) is stable across GnuPG ≥ 2.4, so the mandatory lane asserts a `>= 2.4.0` floor rather than pinning a release; the runner's version is echoed into the job log. Fixtures were generated with GnuPG 2.5.18; local capture used 2.5.19.

### 8.6 Known limitations

- **v6 third-party AEAD interop is verified by composition.** RFC 9580 / SEIPDv2 AEAD correctness is validated through the production seam plus packet-shape assertions; interop against a non-Sequoia RFC 9580 implementation is deferred (a committed fixture under `pgp-mobile/tests/fixtures/` would upgrade this to direct interop). v6 carries no GnuPG interop gate.
- The software-backed CI lanes (§8.2) validate the seam, formats, and gpg interoperability without hardware; they do not substitute for the real-hardware evidence (§8.1) or the manual real-SE↔gpg lane (§8.3).
- The RFC 9980 `sq` cross-implementation interop pack is the remaining post-quantum evidence scope ([POST_QUANTUM.md](POST_QUANTUM.md) §5).

## 9. Accepted-risk register

- **visionOS exposed without dedicated evidence (maintainer-accepted, 2026-06-14).** Device-bound generation is gated only by `SecureEnclave.isAvailable`, with no visionOS-specific guard, so Apple Vision Pro offers the device-bound families. No dedicated visionOS hardware evidence exists (no Vision Pro hardware available). Accepted on the basis of the shared CryptoKit `SecureEnclave` substrate, the visionOS build probe, and the captured macOS + iPhone evidence; visionOS capture remains recommended if hardware becomes available.
- **iPad evidence deferred.** iPad shares the iPhone iOS Secure Enclave substrate; dedicated capture was not run and is not required for the shipped releases.
