# Apple Secure Enclave Custody POC Phase 1

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC closeout; future product, architecture, and security docs will be rewritten separately.
> Successor: None yet.
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.


> Status: macOS primitive validation evidence for a proposal planning track.
> Date: 2026-05-24.
> Purpose: Record Phase 1 Apple Secure Enclave primitive validation results
> before OpenPGP certificate, signing, or decrypt integration work begins.
> Truth sources: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md), [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md),
> and [Phase 0 Baseline](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE0.md).
> Current-state note: This is POC evidence only. It does not describe shipped
> behavior, authorize production integration, or change CypherAir's current
> Secure Enclave wrapping architecture.

## 1. Phase 1 Role

Phase 1 validates Apple platform primitives only. It does not build OpenPGP
certificates, implement Sequoia external signers/decryptors, add app UI, or
change current Profile A / Profile B behavior.

The disposable probe lives at:

- `poc/apple-secure-enclave-custody-phase1/`
- executable: `Phase1SecureEnclaveProbe`
- dependencies: SwiftPM standard library plus Apple frameworks only

The probe writes only dedicated POC Keychain rows with the
`com.cypherair.poc.secure-enclave-custody.phase1` service prefix and deletes
them after each run. It reports only booleans, byte lengths, algorithm names,
and sanitized error classes. It does not print private material, shared
secrets, stable fingerprints, or key handles.

## 2. Tested Environment

- Host OS: macOS Version 26.5 (Build 25F71)
- Architecture: arm64
- Swift toolchain: Apple Swift version 6.3.2
- Secure Enclave availability: `SecureEnclave.isAvailable == true`
- Probe date: 2026-05-24

SwiftPM commands needed to run outside the repository sandbox because Xcode /
Swift writes user-level module caches. The probe itself is repository-local and
does not require network access.

## 3. Results

| Probe mode | Result | Evidence |
|------------|--------|----------|
| `noninteractive` | Passed | Generated distinct Secure Enclave P-256 signing and key-agreement keys, persisted and reconstructed both handles, signed and verified message and digest inputs, performed P-256 ECDH with a software ephemeral key, derived matching 32-byte HKDF output, and cleaned up two probe Keychain rows. |
| `failure` | Passed with observed role-substitution risk | Missing handle and corrupted handle failed closed; deleted Keychain row failed closed. Wrong-role reconstruction and operation were accepted by CryptoKit, so production must bind stored handles to expected custody role and public certificate material instead of relying on CryptoKit type reconstruction to enforce role separation. |
| `negative-export-check` | Passed | Swift typecheck fixture confirmed `dataRepresentation` is available while `rawRepresentation` is not available on Secure Enclave private-key types. |
| `manual-auth --policy standard` | Passed | Standard-style access control was evaluable; authenticated signing and ECDH operations succeeded. |
| `manual-auth --policy highSecurity` | Passed | Biometrics-only-style access control was evaluable; authenticated signing and ECDH operations succeeded. |
| `cleanup` | Passed | Final cleanup found zero remaining standard probe Keychain rows. |

Observed primitive details:

- Secure Enclave P-256 signing key handle length: 324 bytes.
- Secure Enclave P-256 key-agreement handle length: 324 bytes.
- Signing public key and key-agreement public key X9.63 lengths: 65 bytes.
- Secure Enclave ECDSA raw signature length: 64 bytes.
- HKDF validation output length: 32 bytes.
- Reverse ECDH agreement between the Secure Enclave key and a software
  ephemeral key matched.

## 4. Security Findings

- Separate key generation works: the probe generated distinct Secure Enclave
  P-256 signing and key-agreement keys and confirmed the public keys and handle
  blobs differed.
- Private scalar export remains unavailable through the supported CryptoKit API
  surface checked by the negative typecheck fixture.
- CryptoKit `dataRepresentation` is a key handle, not an OpenPGP role binding.
  On this host, a signing-key handle could be reconstructed as a key-agreement
  wrapper and used for ECDH, and a key-agreement handle could be reconstructed
  as a signing wrapper and used for ECDSA. This reinforces the existing product
  requirement to generate separate keys and adds a later validation requirement:
  custody metadata must bind handle role, expected public key, and OpenPGP
  certificate material before any private operation is attempted.
- The command-line POC uses standard macOS Keychain queries with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. An earlier data-protection
  Keychain attempt was not reliable from this unsigned SwiftPM CLI environment,
  so production app Keychain behavior must still be validated in app or
  app-test contexts.

## 5. Residual Questions

- User cancellation was not observed in this run because both manual
  authentication prompts succeeded. The probe can record cancellation as an
  observed result, but a future manual run should intentionally cancel the
  prompt to capture the exact sanitized error class.
- Biometric lockout was not induced and must not be deliberately forced by the
  POC. If a device is already locked out, the probe can record that state.
- Unavailable-hardware behavior was not directly observed because the host
  reported Secure Enclave availability. The probe records a no-fallback skip on
  available hardware and a no-fallback result on unavailable hardware.
- This phase does not decide v4 versus v6 OpenPGP certificate shape, Sequoia
  `Signer` / `Decryptor` integration, ECDH OpenPGP KDF/AES Key Wrap handling,
  or final app access-control policy.

## 6. Commands Run

```bash
xcrun swift build --package-path poc/apple-secure-enclave-custody-phase1
xcrun swift run --package-path poc/apple-secure-enclave-custody-phase1 Phase1SecureEnclaveProbe -- --mode noninteractive
xcrun swift run --package-path poc/apple-secure-enclave-custody-phase1 Phase1SecureEnclaveProbe -- --mode failure
xcrun swift run --package-path poc/apple-secure-enclave-custody-phase1 Phase1SecureEnclaveProbe -- --mode negative-export-check
xcrun swift run --package-path poc/apple-secure-enclave-custody-phase1 Phase1SecureEnclaveProbe -- --mode manual-auth --policy standard
xcrun swift run --package-path poc/apple-secure-enclave-custody-phase1 Phase1SecureEnclaveProbe -- --mode manual-auth --policy highSecurity
xcrun swift run --package-path poc/apple-secure-enclave-custody-phase1 Phase1SecureEnclaveProbe -- --mode cleanup
```

## 7. Next Phase Entry Condition

Phase 1 provides enough macOS primitive evidence to plan Phase 2 OpenPGP public
certificate feasibility in an isolated prototype. Phase 2 must carry forward
the role-substitution finding and explicitly validate that stored Secure
Enclave handles, expected public keys, and generated OpenPGP certificate
material cannot be mismatched or substituted.

> Status: Archived historical Secure Enclave Custody POC material.
> Archived: 2026-05-25.
> Archive reason: Secure Enclave Custody POC closeout; future product, architecture, and security docs will be rewritten separately.
> Successor: None yet.
> Current-state note: Current code and active docs outrank this archived file; use it only as historical evidence and context.

