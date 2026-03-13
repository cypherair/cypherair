---
paths:
  - "Sources/Security/**"
  - "Sources/*/KeychainManager*"
  - "Sources/*/SecureEnclave*"
  - "Sources/*/Authentication*"
  - "Sources/Services/DecryptionService*"
  - "Sources/Services/QRService*"
---

# Security Module Rules

This code protects private keys with Secure Enclave hardware and biometric authentication.
Mistakes here can make keys permanently inaccessible or silently insecure.

DecryptionService and QRService are included in this scope because they enforce
authentication boundaries (Phase 1/Phase 2) and parse untrusted external input
(cypherair:// URLs), respectively.

## Before Any Edit

1. Read the current implementation completely. Do not guess behavior from names alone.
2. Describe the proposed change and its security implications to the user.
3. Wait for explicit approval before writing code.

## Never Do

- Never log key material, passphrases, decrypted content, Keychain data, or SE key representations. Not even in DEBUG.
- Never remove or weaken `zeroize()` / `resetBytes(in:)` calls on sensitive buffers.
- Never change `SecAccessControlCreateFlags` without understanding both Standard and High Security mode implications.
- Never remove `.privateKeyUsage` from any SE key access control — it is mandatory for SE key operations.
- Never use `.biometryCurrentSet` where `.biometryAny` is specified or vice versa without explicit approval.
- Never store unencrypted private key material in UserDefaults, files, or any location outside the Keychain.
- Never use `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAfterFirstUnlock` — always use `WhenUnlockedThisDeviceOnly`.
- Never catch and silently discard Keychain or CryptoKit errors. All failures must propagate.
- Never skip the `os_proc_available_memory()` guard before Argon2id derivation on key import.
- Never pass raw private key bytes to Swift via UniFFI return value without ensuring the Rust side has zeroized its copy. UniFFI `Vec<u8>` transfer uses copy semantics — the Rust-side buffer persists after the call returns and must be explicitly zeroed.
- Never delete old Keychain items during mode switch before confirming all new items are stored. See docs/SECURITY.md Section 4 for the correct atomic procedure.
- Never skip or bypass the Phase 1 → Phase 2 authentication boundary in DecryptionService. Phase 1 (header parsing, key matching) must complete before Phase 2 (biometric auth, decryption) begins.
- Never send SEIPDv2 (AEAD) to a v4 key recipient. Format must match recipient key version.
- Never generate v6 keys from Profile A or v4 keys from Profile B.

## Always Do

- Use `SecRandomCopyBytes` or CryptoKit for all random generation.
- Zero sensitive `Data` buffers immediately after use with `data.resetBytes(in: data.startIndex..<data.endIndex)`.
- Generate a fresh random salt for every SE wrapping operation. Never reuse salts.
- Include the key's hex fingerprint in the HKDF info string for domain separation: `"CypherAir-SE-Wrap-v1:" + hexFingerprint`.
- Store Keychain items before zeroizing the source key material. If storage fails, the key bytes must still be available for retry.
- Make SE key operations atomic: if any step of wrap/unwrap/re-wrap fails, the original state must be preserved.
- On app launch, check for the `rewrapInProgress` flag and run crash recovery if present.
- Validate all data received via `cypherair://` URL scheme as untrusted input before passing to Sequoia parser.
- Verify encryption format matches recipient key version before sending.
- Include both positive tests (correct auth succeeds) and negative tests (wrong auth fails, tampered data rejected) for every change.
- Guard SE-dependent code with `SecureEnclave.isAvailable` for simulator compatibility.

## Definition of Done

- `cargo test --manifest-path pgp-mobile/Cargo.toml` passes
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests` passes
- Both positive tests (correct inputs succeed) and negative tests (wrong inputs fail gracefully) included
- Diff reviewed against SECURITY.md invariants (§3 SE wrapping, §4 auth modes, §7 red lines)
- No `print()` / `os_log()` / `NSLog()` of sensitive data added
