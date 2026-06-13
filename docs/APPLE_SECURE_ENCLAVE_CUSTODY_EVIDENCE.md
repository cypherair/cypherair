# Apple Secure Enclave Custody Evidence

> Status: Active Phase 8 evidence record (issue #501). Captures the hardware and
> OpenPGP-interop evidence that gates Secure Enclave custody user exposure. Some
> rows are operator/maintainer-run (real biometrics, on-device, cross-device gpg)
> and are marked pending until captured.
> Last reviewed: 2026-06-13.
> Purpose: Name the platform-family matrix, evidence acceptance criteria,
> sanitizer expectations, and reviewer ownership for Apple Secure Enclave-backed
> OpenPGP private-key custody, and record captured results.
> Audience: Security reviewers, release owners, Swift/Rust implementers, test
> owners, and AI coding tools.
> Source authorities: [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md)
> (§"Hardware Evidence Requirements", §"Interop Evidence Requirements"),
> [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md#compatibility-language),
> and [Implementation Roadmap](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_ROADMAP.md) §"Phase 8".
> Related: [Testing](TESTING.md), [Implementation Reference](APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md).
> Update triggers: any captured evidence run, changed evidence acceptance
> criteria, changed sanitizer expectations, changed platform matrix, or a release
> decision.

## 1. Scope and Lanes

Phase 8 evidence has two parts:

- **Hardware evidence (roadmap 8A):** real Secure Enclave private operations on
  supported Apple platform families. Run via the device test plans, never in
  mandatory default CI.
- **Interop evidence (roadmap 8B/8C):** GnuPG v4 interoperability for the
  device-bound *compatible* family, and RFC 9580 / AEAD correctness for the
  device-bound *modern* family.

Lane legend:

- **CI (mandatory)** — runs in `pr-checks.yml` / `nightly-full.yml`, fails the
  build if it cannot run.
- **CI (default)** — runs in the standard `rust-full-tests` / unit lanes.
- **Operator-automated** — an automated test that requires a real device +
  biometric approval (and, for the interop harness, a local `gpg`); run by hand
  from the relevant manual plan. Cannot run headless in CI.
- **Documented manual** — a written cross-device procedure (no single automated
  lane is possible).
- **N/A** — explicitly excluded.

Platforms: macOS, iPhone, iPad now; **visionOS is excluded** (build-probe only,
no dedicated XCTest plan). visionOS custody evidence is required before any
visionOS custody release.

## 2. Software-backed interop evidence (CI)

The v4 GnuPG interop and v6 AEAD lanes drive the **production** Secure Enclave
seams (`generate_secure_enclave_public_certificate`, the external P-256 signer,
`decrypt_detailed_with_external_p256_key_agreement`) with a software-P256
stand-in (`pgp-mobile/tests/common/secure_enclave.rs`). Because the software lane
holds both secret halves, it imports a gpg-importable TSK whose fingerprints
match the SE-shaped certificate, giving full bidirectional v4 interop with no
hardware. This validates the seam and packet shapes; real-hardware bidirectional
interop is §4.

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
| v6: gpg rejects v6 public key | CI (default) | `gpg --import` non-zero (v6 unsupported) | ✅ (generic v6, `gnupg_binary_tests`) |
| Profile A (software): gpg bidirectional | CI (mandatory) | import / decrypt / verify / reject-v6 | ✅ macOS, gpg 2.5.19 |

Tests: `pgp-mobile/tests/secure_enclave_gnupg_interop_tests.rs` (v4, 6/6),
`pgp-mobile/tests/secure_enclave_v6_aead_evidence_tests.rs` (v6, 3/3),
`pgp-mobile/tests/gnupg_binary_tests.rs` (Profile A, 6/6),
`pgp-mobile/tests/secure_enclave_support_tests.rs` (TSK-export smoke, 1/1).

The mandatory lanes run under `CYPHERAIR_REQUIRE_GPG=1` in the `rust-gnupg-interop`
job, which installs gpg (`brew install gnupg`) and asserts a `>= 2.4.0` floor
(`scripts/assert_min_gpg_version.sh`); a missing/old gpg fails the lane rather
than skipping. The v6 lanes need no gpg.

## 3. Real-hardware Secure Enclave evidence (8A)

Real SE private operations via `CypherAir-DeviceTests` (and the destructive
`CypherAir-DangerousDeviceTests`). These require a real Secure Enclave plus
enrolled biometrics and are operator-run (one biometric approval per run); they
emit sanitized `SE-CUSTODY-EVIDENCE` summary lines for this matrix.

| Scenario | macOS | iPhone | iPad | visionOS |
| --- | --- | --- | --- | --- |
| handle-pair generation + persistence | ✅ captured (non-interactive) | pending (maintainer) | pending (maintainer) | N/A |
| signing (real ECDSA) | ✅ captured (biometric) | pending | pending | N/A |
| ECDH decrypt v4 (SEIPDv1/MDC) | ✅ captured (biometric) | pending | pending | N/A |
| ECDH decrypt v6 (SEIPDv2/AEAD) | ✅ captured (biometric) | pending | pending | N/A |
| hidden generation (v4 public cert via real signing handle) | ✅ captured (biometric) | pending | pending | N/A |
| missing handle fails closed | ✅ captured (non-interactive) | pending | pending | N/A |
| wrong public binding fails closed | ✅ captured (non-interactive) | pending | pending | N/A |
| wrong role fails closed (signer/KA guards) | ✅ captured (non-interactive) | pending | pending | N/A |
| payload tamper hard-fail (no partial plaintext) | ✅ captured (biometric) | pending | pending | N/A |
| local-reset cleanup (dangerous plan) | pending (dangerous plan) | pending | pending | N/A |
| interaction-not-allowed proxy (fail-closed) | ✅ captured (non-interactive) | pending | pending | N/A |

Tests: `Tests/DeviceSecurityTests/DeviceSecureEnclaveCustody*Tests.swift` +
`DeviceDangerousSecureEnclaveCustodyResetCleanupTests.swift`. Captured on macOS
arm64e (real Secure Enclave, 2026-06-13): the five non-interactive scenarios and
the four biometric scenarios (signing, ECDH decrypt v4/v6, hidden generation,
payload tamper — Touch ID approved at the sensor) all passed and emitted
sanitized `SE-CUSTODY-EVIDENCE` lines. The local-reset proof lives in the
destructive `CypherAir-DangerousDeviceTests` plan (not yet run); all iPhone/iPad
rows are pending the maintainer's interactive runs.

**Authentication-cancellation and biometric-lockout** positive *interactive*
evidence is intentionally out of scope: it is a low-value attended edge case that
cannot run daily. The fail-closed behavior is covered by the automated
`interaction-not-allowed` proxy and the `LAError`→category normalizer.

## 4. Real-SE ↔ gpg bidirectional interop (manual lane)

`CypherAir-InteropEvidenceTests` →
`DeviceSecureEnclaveGnuPGInteropEvidenceTests` is the production successor to the
POC `gnupg-interop --request` mode (no raw shared-secret response file). It
generates a **real** device-bound SE v4 key and drives the local `gpg` binary
bidirectionally (SE→gpg verify; gpg→SE production-seam decrypt). It is
**macOS-only** (gpg cannot run on iOS/iPadOS) and operator-run (real biometrics +
local gpg); it is out of default CI.

| Direction | macOS | iPhone / iPad |
| --- | --- | --- |
| SE signs → gpg verifies | ✅ captured (manual plan) | documented manual cross-device |
| gpg encrypts → production seam decrypts (real SE ECDH) | ✅ captured (manual plan) | documented manual cross-device |

Run: `xcodebuild test -scheme CypherAir -testPlan CypherAir-InteropEvidenceTests -destination 'platform=macOS,arch=arm64e'`. Captured on real Secure Enclave + gpg 2.5.19 (macOS arm64e, 2026-06-13): both directions passed (`SE-CUSTODY-EVIDENCE scenario=gnupgInteropV4 outcome=passed`).

**iPhone/iPad documented manual cross-device procedure** (gpg runs only on the
Mac):

1. On the device, run the SE custody flow to produce: the exported public
   certificate, an SE-signed message, and an SE-decrypted result. Transfer them
   to the Mac via the Share Sheet.
2. On the Mac, `gpg --import` the certificate, `gpg --verify` the SE signature,
   and `gpg --encrypt` a message to it. Transfer the ciphertext back.
3. On the device, decrypt the gpg ciphertext through the production decryption
   path (real SE ECDH) and sign+encrypt a reply; the Mac's gpg verifies/decrypts
   it.
4. Record the sanitized outcome of each step in this matrix.

## 5. Sanitizer expectations

All evidence output (console summaries, committed matrix entries, attachments)
**must exclude**: plaintext, private-key material, ECDH shared secrets, session
keys, KEKs, Keychain locators / application tags / handle-set identifiers, stable
fingerprints, and temporary capability paths (per Security Requirements §"Hardware
Evidence Requirements"). Allowed: pass/fail, scenario labels, sanitized
`PGPKeyOperationFailureCategory` values, algorithm/curve identifiers, packet
versions/tags, counts, and the gpg version string.

Enforcement: the Swift `SecureEnclaveCustodyEvidenceSummary` is sanitized by
construction (only enums + integer counts) and pinned by
`SecureEnclaveCustodyEvidenceLogTests`; the device tests assert trace/error
sanitization (`assertSanitizedText` / `assertTraceIsSanitized`); the Rust lanes
print only scenario labels.

## 6. GnuPG version policy

The interop contract (v4 ECDSA/ECDH P-256, PKESK v3, SEIPDv1/MDC, v6 rejection)
is stable across GnuPG ≥ 2.4, so the mandatory lane asserts a `>= 2.4.0` floor
rather than pinning an exact release; the runner's actual version is echoed into
the job log as evidence-of-record. Fixtures were generated with GnuPG 2.5.18
(`pgp-mobile/tests/fixtures/gpg_version.txt`); local capture above used 2.5.19.

## 7. Known limitations

- **v6 third-party AEAD interop is verified by composition.** RFC 9580 / SEIPDv2
  AEAD correctness is validated through the production seam (Sequoia encode →
  production decrypt) and packet-shape assertions; interop against a non-Sequoia
  RFC 9580 implementation (OpenPGP.js / GopenPGP / PGPainless) is deferred. A
  future committed fixture from such an implementation under
  `pgp-mobile/tests/fixtures/` would upgrade this to direct interop. v6 carries
  no GnuPG interop release gate (GnuPG does not support v6 keys).
- The software-backed CI lanes (§2) validate the seam, formats, and gpg
  interoperability without hardware; they do not substitute for the real-hardware
  evidence (§3) or the real-SE↔gpg manual lane (§4).

## 8. Reviewer ownership

The release gate requires a security reviewer and a release owner to review the
captured sanitized evidence in §2–§4 before Secure Enclave custody becomes
product-selectable (Security Requirements §"Release Gate", roadmap Phase 9). The
matrix above must show captured (not pending) rows for every required platform
family, or an explicit, documented exclusion.
