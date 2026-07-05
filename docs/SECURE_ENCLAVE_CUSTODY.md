# Secure Enclave Custody

> Status: Canonical current-state.
> Purpose: Single durable reference for Apple Secure Enclave-backed OpenPGP
> private-key custody (the Device-Bound key families): the product/architecture
> model, the security contract, the supported operation surface, the release-gate
> closeout, and the captured hardware/interop evidence.
> Audience: Security reviewers, release owners, Swift/Rust implementers, test
> owners, product owners, and AI coding tools.
> Source of truth: This document, the code under `Sources/Security/SecureEnclaveCustody*`,
> `Sources/Services/KeyManagement/`, and `pgp-mobile/src/`, and the companion
> canonical docs cited below.
> Last reviewed: 2026-06-14.
> Update triggers: any change to the Secure Enclave custody model, access-control
> policy, red lines, operation surface, persisted-state classification,
> Rust/UniFFI boundary, evidence matrix, or release posture.
> Supersedes: the Apple Secure Enclave custody planning series (product design,
> architecture plan, security requirements, feasibility summary, implementation
> reference, implementation roadmap, and Phase 8 evidence record), removed in the
> Phase 9 closeout. Their phase-by-phase history is preserved in git.
> Companion current-state docs: [Architecture](ARCHITECTURE.md),
> [Security](SECURITY.md), [PRD](PRD.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md),
> [Testing](TESTING.md), [Code Review](WORKFLOW.md).

## 1. Overview

Secure Enclave custody is a device-bound private-key custody model in which
long-term signing and key-agreement private operations stay bound to the
current device's Secure Enclave — P-256 for the classical device-bound families,
and RFC 9980 split custody for Device-Bound Post-Quantum (§4.1). It sits
alongside — and does not replace — the portable software-key model. It is
presented in the product as three of the six
key families:

- **Device-Bound Compatible** — Secure Enclave custody, P-256, v4 certificate.
- **Device-Bound Modern** — Secure Enclave custody, P-256, v6 (RFC 9580)
  certificate.
- **Device-Bound Post-Quantum** — RFC 9980 composite split custody, v6
  certificate (campaign #567 Phase 3; §4.1).

(The portable software families are **Portable Compatible** = Profile A,
**Portable Modern** = Profile B, and **Portable Post-Quantum** = the RFC 9980
software configuration; Profile A/B remain the technical vocabulary for the
classical software configurations.)

Secure Enclave custody is **implemented and production-exposed since issue #501
Phase 7D** (PR #509): the production capability-resolver policy supports
device-bound generation, signing-class, and key-agreement operations, and the
production container wires the generation service where Secure Enclave hardware
is present. The **release gate is satisfied (Phase 9 closeout, 2026-06-14, §7)**;
the families ship to users with the next tag-first stable release
([App Release Process](RELEASE.md)).

Product semantics (families, generation UX, commitment sheet, key-detail
surfaces, compatibility copy) are owned by [PRD](PRD.md) §3.

## 2. Architecture and ownership

The integration separates three concepts the software-key model partly
compressed — OpenPGP **configuration** (version/algorithm/format/interop
target), private-key **custody** (software secret certificate vs Secure Enclave
private-operation handles), and **operation capability** (what a key can do now,
or an explicit unsupported state). Full ownership detail is in
[Architecture](ARCHITECTURE.md). The durable boundary:

- **Service layer** owns user workflows; it asks `PGPKeyCapabilityResolver` for
  availability and `PrivateKeyOperationRouter` for a private-operation route, and
  never touches Keychain rows or Secure Enclave access-control flags directly.
- **Security layer** (`Sources/Security/SecureEnclaveCustody*`) owns the Apple
  primitives: distinct role-tagged P-256 handle creation/loading, Keychain
  handle storage and deletion, access-control enforcement, role + public-key
  binding checks, and cleanup / local-reset participation.
- **Rust/OpenPGP layer** (`pgp-mobile/src/`, Sequoia) owns OpenPGP semantics:
  certificate construction/parsing, packet construction, ECDH KDF, AES Key Wrap,
  session-key validation, streaming payload decrypt, and MDC/AEAD hard-fail.

Secure Enclave private operations cross the Rust boundary through **external
signer / key-agreement seams** (`ExternalP256SigningProvider` /
`ExternalP256KeyAgreementProvider` callback bridges): Rust delegates only the
private ECDSA or P-256 ECDH operation and never receives private scalars or a
complete secret certificate. The software-custody route is unchanged and is the
only route that unwraps and zeroizes a secret certificate.

Persisted state: protected `key-metadata` schema v2 stores only the non-secret
`PGPKeyIdentity` projection (configuration identity, custody kind, public
certificate/handle association, operation-availability projection, revocation
presence, non-exportability) and never the access-control policy, handle
locators, or secret material. The signing and key-agreement handles live in the
data-protection Keychain/Secure Enclave boundary, separate from the retired
multi-row software-custody wrapping scheme. Classification is owned by
[Persisted State Inventory](PERSISTED_STATE_INVENTORY.md).

## 3. Security contract

The authoritative security model is [Security](SECURITY.md) §3; this section is
the consolidated custody-specific contract.

### 3.1 Access-control policy

Secure Enclave private-operation keys are created with:

- `privateKeyUsage`;
- `biometryAny`;
- **no** device-passcode fallback.

`biometryAny` keeps the key usable when the enrolled biometric set changes while
still requiring biometric authentication for every private-key use.
`biometryCurrentSet` must **not** be exposed as a user-selectable option (for a
non-exportable key it creates a high permanent-loss risk). Secure Enclave custody
must **not** use the Standard/High-Security in-place rewrap to change access
policy — that rewrap model remains software-custody only.

### 3.2 Red lines and program-level stop conditions

Return to security review before doing any of the following. Each is enforced in
code and test-pinned (see [Security](SECURITY.md) §3, §10):

- exporting Secure Enclave private-key material;
- importing an existing OpenPGP private key into Secure Enclave custody;
- storing a software fallback or complete secret certificate for a Secure Enclave
  custody key;
- treating a Keychain handle, public key, or locator as a recoverable
  private-key backup;
- using one Secure Enclave private key for both signing and key agreement, or
  accepting a signing handle for ECDH (or vice versa);
- accepting a handle whose public key does not match the stored OpenPGP public
  certificate association;
- exposing partial plaintext after MDC or AEAD authentication failure;
- logging plaintext, private-key material, session keys, ECDH shared secrets,
  KEKs, Keychain locators, stable fingerprints, or temporary capability paths;
- weakening current portable software-key behavior to make integration easier;
- adding network, telemetry, new permissions, or release-metadata churn as part
  of the feature.

A failure to load, authenticate, validate, or bind the required handle must fail
closed through a sanitized `PGPKeyOperationFailureCategory`; there is no software
fallback on a Secure Enclave route.

### 3.3 Payload hard-fail

Secure Enclave custody preserves the OpenPGP authentication contract: v4
SEIPDv1/MDC and v6 SEIPDv2/AEAD tampering fail closed; file decrypt writes only
through the success-only `.tmp`-then-rename output contract; cancellation and
authentication errors never expose partial plaintext. The private-operation route
may recover a session key, but final plaintext release stays gated by Sequoia
payload authentication and the read-to-completion contract.

## 4. Supported operation surface

Resolved by `PGPKeyCapabilityResolver` and routed by `PrivateKeyOperationRouter`
(`Sources/Services/KeyManagement/`):

| Operation | Secure Enclave custody | Route |
| --- | --- | --- |
| Generate | Supported | hidden→exposed generation builds the public-only v4/v6 cert + revocation artifact bound to distinct signing/key-agreement public keys |
| Sign / certify / revoke / modify-expiry | Supported (signing role) | external P-256 signer seam |
| Decrypt (message + streaming file) | Supported (key-agreement role) | external P-256 ECDH/session-key seam |
| Export public material | Supported when present | uses stored public artifact |
| Export revocation artifact | Supported when present | uses stored revocation artifact |
| Refresh binding (standalone) | Not implemented | `.operationNotImplementedForCustody` (no service implements this route) |
| Export / back up private material | **Unsupported (red line)** | `.operationUnsupportedForCustody` |
| Import existing private key into Secure Enclave | **Unsupported (red line)** | not an operation |

Signing and key agreement are routed to **distinct** Secure Enclave handles by
the operation's required role; a wrong-role or wrong-public-binding request fails
closed.

### 4.1 Device-Bound Post-Quantum (split custody)

Device-Bound Post-Quantum applies the same custody model to RFC 9980 composite
keys (ML-DSA-65+Ed25519 signing, ML-KEM-768+X25519 encryption), with the same
operation surface as the P-256 families. Because CryptoKit's Secure Enclave
offers ML-DSA/ML-KEM but no Ed25519/X25519, custody is **split**:

- **Post-quantum components** are generated and held in the Secure Enclave as
  CryptoKit `dataRepresentation` blobs (`kSecClassGenericPassword` rows in the
  data-protection keychain, this-device-only; the blob is useless off-device).
  Use is gated by the same fixed `privateKeyUsage` + `biometryAny` access
  control baked into the key at creation.
- **Classical components** (one 32-byte Ed25519 seed + one 32-byte X25519
  scalar, generated inside Rust) are sealed as a single payload under a
  dedicated fixed-access Secure Enclave envelope (the CAPKEV1 construction),
  stored per fingerprint. The fixed policy — never the mode-dependent app
  wrapping policy — keeps every device-bound key exempt from Standard/High
  Security mode-switch re-wrap.

Invariants (docs/POST_QUANTUM.md §3): every composite signature or decryption
requires an in-enclave ML-DSA/ML-KEM operation; the classical component alone
can neither sign nor decrypt; the private key is never exportable (the same
red lines as the P-256 families apply). The Rust engine owns all OpenPGP
derivation — the RFC 9980 KEM combiner, AES-256 key unwrap, packet assembly,
and composite self-verification before any signature is released — while Swift
performs exactly the enclave primitive (an ML-DSA-65 digest signature or an
ML-KEM-768 decapsulation) through the external provider seam, mirroring the
external P-256 seam.

Routing mirrors the P-256 flow: non-prompting handle lookup by the
certificate's component public keys, then one authenticated biometric window
covering the enclave-handle load and the classical-component unwrap. Deletion
removes the enclave blobs (by composite binding inspection) and the classical
envelope (via the shared fingerprint-keyed keychain-material path); Reset All
Local Data cleans all composite rows. Real-hardware evidence:
`DeviceSecureEnclaveCompositeCustodyTests` (generation, decrypt through the
vendored RFC 9980 combiner, cleartext sign/verify, wrong-classical-component
fail-closed) — one biometric approval per run.

## 5. Compatibility language

- **Device-Bound Compatible (v4)** — described as GnuPG-oriented; entitled by the
  v4 GnuPG interop evidence (§8).
- **Device-Bound Modern (v6)** — described as RFC 9580 / AEAD-oriented OpenPGP;
  it makes **no** GnuPG interoperability claim (GnuPG does not support v6 keys).
- Portable Compatible / Portable Modern keep the current Profile A/B
  cryptographic behavior.

Existing private keys are never converted into Secure Enclave custody; the
product must not imply otherwise.

## 6. Validation and tests

Coverage and lanes are owned by [Testing](TESTING.md). In summary:

- **Mockable unit + FFI** (`CypherAir-UnitTests`, default lane): legal/illegal
  configuration+custody pairs, Profile A/B→software migration, metadata
  corruption/recovery, resolver output, router dispatch with no workflow-local
  custody switches, no-fallback/no-secret-cert-unwrap, wrong-role / wrong-public /
  missing-handle / mismatch, no-partial-plaintext, and no-secret-in-logs; plus
  the Rust external signer / ECDH proofs and runtime API matrices.
- **Real-hardware device** (`CypherAir-DeviceTests`, manual): generation,
  persistence, signing, ECDH decrypt, and the fail-closed guards on real Secure
  Enclave hardware. Destructive local-reset cleanup is `CypherAir-DangerousDeviceTests`.
- **Interop** (`pgp-mobile/tests/`, plus the manual macOS-only
  `CypherAir-InteropEvidenceTests`): v4 GnuPG interoperability and v6 RFC 9580 /
  AEAD correctness.

## 7. Release-gate closeout

**Decision (2026-06-14): the Secure Enclave custody release gate is SATISFIED.**
Secure Enclave custody is cleared to ship to users with the next tag-first stable
release. Every gate condition is met:

| Gate condition | Status | Evidence |
| --- | --- | --- |
| Configuration and custody migration behavior | MET | metadata v2 migration + tests (§6) |
| Persisted-state classification and migration | MET | [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md) rows for the SE-custody handle + metadata state |
| Private-operation router and Rust/UniFFI boundary | MET | external signer/decryptor seams (§2), router tests (§6) |
| Mockable security tests | MET | `CypherAir-UnitTests` SE-custody suite (§6) |
| Hardware evidence | MET | §8.1 matrix: macOS + iPhone captured (iPad deferred, visionOS accepted-risk §9) |
| v4 GnuPG interop evidence | MET | §8.2 software-interop lanes (mandatory CI) + §8.3 real-SE↔gpg manual lane |
| User-facing recovery and non-exportability language | MET | [PRD](PRD.md) §3 commitment sheet + key-detail copy (en + zh-Hans) |

The six SECURITY.md §3 red lines are implemented and test-pinned; unsupported
operations (private export/backup, import-into-SE) remain explicit and fail
closed.

**Sign-off:** maintainer, acting as security reviewer and release owner,
2026-06-14.

The formal stable release and App Store candidate work is a separate,
maintainer-initiated step that follows [App Release Process](RELEASE.md).

## 8. Evidence record

Evidence is captured by the device test plans (real Secure Enclave, biometric)
and the Rust/interop lanes, emitting sanitized one-line summaries. The sanitizer
expectations (§8.4) apply to all evidence output.

### 8.1 Real-hardware Secure Enclave evidence

Real SE private operations via `CypherAir-DeviceTests` (and the destructive
`CypherAir-DangerousDeviceTests`), one biometric approval per run.

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

Capture notes:

- **macOS** (arm64e, real Secure Enclave, gpg 2.5.19, 2026-06-13): all eleven
  rows captured — the non-interactive scenarios, the biometric scenarios (signing,
  ECDH decrypt v4/v6, hidden generation, payload tamper, Touch ID approved at the
  sensor), and the destructive local-reset proof (`CypherAir-DangerousDeviceTests`,
  which deleted app-owned custody rows).
- **iPhone** (iOS 27.0 developer beta, real Secure Enclave, 2026-06-14): the ten
  non-destructive rows captured via `CypherAir-UnitTests` + `CypherAir-DeviceTests`
  (biometric scenarios approved at the sensor). The local-reset row was **not**
  run on iPhone (`CypherAir-DangerousDeviceTests` not executed there); it is
  covered on macOS.
- **iPad** — deferred. iPad runs the same iOS Secure Enclave substrate and the
  same LocalAuthentication stack as iPhone; dedicated iPad capture is not required
  for this release. Capture is recommended before any iPad-specific custody claim.
- **visionOS** — exposed without dedicated evidence (accepted risk, §9). No
  Apple Vision Pro hardware is available to capture evidence; the code exposes
  device-bound families wherever `SecureEnclave.isAvailable` is true.

Authentication-cancellation and biometric-lockout positive *interactive* evidence
is intentionally out of scope (a low-value attended edge case); the fail-closed
behavior is covered by the automated `interaction-not-allowed` proxy and the
`LAError`→category normalizer.

### 8.2 Software-backed interop evidence (CI)

These lanes drive the **production** Secure Enclave seams with a software-P256
stand-in (`pgp-mobile/tests/common/secure_enclave.rs`), validating the seam and
packet shapes (and full v4 gpg interoperability) without hardware.

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
| Profile A (software): gpg bidirectional | CI (mandatory) | import / decrypt / verify / reject-v6 | ✅ macOS, gpg 2.5.19 |

Tests: `pgp-mobile/tests/secure_enclave_gnupg_interop_tests.rs` (v4, 6/6),
`secure_enclave_v6_aead_evidence_tests.rs` (v6, 3/3), `gnupg_binary_tests.rs`
(Profile A, 6/6), `secure_enclave_support_tests.rs` (TSK-export smoke, 1/1). The
mandatory lanes run under `CYPHERAIR_REQUIRE_GPG=1` in the `rust-gnupg-interop`
job, which installs gpg and asserts a `>= 2.4.0` floor
(`scripts/assert_min_gpg_version.sh`); a missing/old gpg fails the lane rather
than skipping. The v6 lanes need no gpg.

### 8.3 Real-SE ↔ gpg bidirectional interop (manual lane)

`CypherAir-InteropEvidenceTests` → `DeviceSecureEnclaveGnuPGInteropEvidenceTests`
generates a real device-bound SE v4 key and drives the local `gpg` binary
bidirectionally. It is **macOS-only** (gpg cannot run on iOS/iPadOS) and
operator-run.

| Direction | macOS | iPhone / iPad |
| --- | --- | --- |
| SE signs → gpg verifies | ✅ captured (manual plan) | documented manual cross-device |
| gpg encrypts → production seam decrypts (real SE ECDH) | ✅ captured (manual plan) | documented manual cross-device |

Captured on real Secure Enclave + gpg 2.5.19 (macOS arm64e, 2026-06-13): both
directions passed. The iPhone/iPad cross-device procedure (produce SE artifacts
on device, transfer to the Mac for gpg, transfer ciphertext back, decrypt through
the production path) is a documented manual step because gpg runs only on the Mac.

### 8.4 Sanitizer expectations

All evidence output (console summaries, committed matrix entries, attachments)
**must exclude**: plaintext, private-key material, ECDH shared secrets, session
keys, KEKs, Keychain locators / application tags / handle-set identifiers, stable
fingerprints, and temporary capability paths. Allowed: pass/fail, scenario
labels, sanitized `PGPKeyOperationFailureCategory` values, algorithm/curve
identifiers, packet versions/tags, counts, and the gpg version string.
Enforcement: `SecureEnclaveCustodyEvidenceSummary` is sanitized by construction
(only enums + integer counts) and pinned by `SecureEnclaveCustodyEvidenceLogTests`;
the device tests assert trace/error sanitization; the Rust lanes print only
scenario labels.

### 8.5 GnuPG version policy

The v4 interop contract (ECDSA/ECDH P-256, PKESK v3, SEIPDv1/MDC, v6 rejection)
is stable across GnuPG ≥ 2.4, so the mandatory lane asserts a `>= 2.4.0` floor
rather than pinning a release; the runner's version is echoed into the job log.
Fixtures were generated with GnuPG 2.5.18; local capture used 2.5.19.

### 8.6 Known limitations

- **v6 third-party AEAD interop is verified by composition.** RFC 9580 / SEIPDv2
  AEAD correctness is validated through the production seam (Sequoia encode →
  production decrypt) plus packet-shape assertions; interop against a non-Sequoia
  RFC 9580 implementation is deferred (a future committed fixture under
  `pgp-mobile/tests/fixtures/` would upgrade this to direct interop). v6 carries
  no GnuPG interop release gate.
- The software-backed CI lanes (§8.2) validate the seam, formats, and gpg
  interoperability without hardware; they do not substitute for the real-hardware
  evidence (§8.1) or the real-SE↔gpg manual lane (§8.3).

## 9. Accepted-risk register

- **visionOS exposed without dedicated evidence (maintainer-accepted, 2026-06-14).**
  Device-bound generation is gated only by `SecureEnclave.isAvailable`, with no
  visionOS-specific guard, so on Apple Vision Pro the device-bound families are
  offered. No dedicated visionOS hardware evidence exists (no Vision Pro hardware
  is available to test). The risk is accepted on the basis of the shared CryptoKit
  `SecureEnclave` substrate, the visionOS build probe, and the captured macOS +
  iPhone evidence. visionOS custody evidence remains recommended if hardware
  becomes available.
- **iPad evidence deferred.** iPad shares the iPhone iOS Secure Enclave substrate;
  dedicated iPad capture was not run and is not required for this release.
- **Exposure preceded the formal gate by design (Phase 7D).** The production
  exposure flip landed in Phase 7D ahead of this closeout, by maintainer decision,
  because tag-first releases are the user-exposure boundary. The accepted risk —
  that an emergency release mid-series could have shipped Device-Bound without
  Phase 8 evidence — is retired now that Phase 8 is merged and this gate is closed.

## 10. History

The Secure Enclave custody work ran as issue #501, Phases 0–9. Phase 7D exposed
the model in production (PR #509); Phase 8 captured hardware + interop evidence
(PR #516); Phase 9 (this closeout, 2026-06-14) satisfied the release gate,
consolidated the durable content into the canonical current-state docs and this
document, and removed the completed planning series and the archived POC docs.
Their full phase-by-phase history is preserved in git.
