# Security Model

> Purpose: Complete description of the encryption scheme, key lifecycle, authentication flows,
> security invariants, and AI coding boundaries for Cypher Air.
> Audience: Human developers, security auditors, and AI coding tools.

## 1. Encryption Scheme

All cryptographic operations use Sequoia PGP 2.2.0. Two profiles with different algorithm suites:

### Profile A (Universal Compatible)

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Primary key (sign/certify) | Ed25519 (legacy EdDSA) | v4 key format |
| Encryption subkey | X25519 (legacy ECDH) | v4 key format |
| Symmetric encryption | AES-256 | 256-bit key |
| Message format | SEIPDv1 (MDC) | Non-AEAD; GnuPG compatible |
| Hash | SHA-512 | Accepts SHA-256 for legacy verification |
| S2K (key export) | Iterated+Salted (mode 3) | GnuPG compatible |
| Compression | DEFLATE (read-only) | Enabled for reading compatibility; outgoing messages must not use compression |
| Random | SecRandomCopyBytes | Via `getrandom` crate on iOS |

### Profile B (Advanced Security)

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Primary key (sign/certify) | Ed448 | v6 key format; ~224-bit security |
| Encryption subkey | X448 | v6 key format; inherent AES-256 key wrap |
| Symmetric encryption | AES-256 | 256-bit key |
| AEAD | OCB (primary), GCM (secondary) | SEIPDv2; OCB mandatory per RFC 9580 |
| Hash | SHA-512 | |
| S2K (key export) | Argon2id (512 MB / p=4 / ~3s) | Memory-hard |
| Compression | DEFLATE (read-only) | Enabled for reading compatibility; outgoing messages must not use compression |
| Random | SecRandomCopyBytes | Via `getrandom` crate on iOS |

**Interoperability:** Profile A output compatible with GnuPG 2.1+ and all PGP tools. Profile B output compatible with Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+, Bouncy Castle 1.82+. The App reads v4 keys, v6 keys, SEIPDv1, SEIPDv2 (OCB/GCM), Iterated+Salted S2K, and Argon2id S2K. Compression (`deflate`) read-only for compatibility; outgoing messages never compressed. Bzip2 excluded (extra C dependency).

## 2. Key Lifecycle

```
Generate (Profile A: Ed25519+X25519 v4 / Profile B: Ed448+X448 v6)
    │
    ├──→ SE Wrap (P-256 self-ECDH + HKDF + AES-GCM)
    │       │
    │       └──→ Store in Keychain (3 items per identity)
    │
    ├──→ Auto-generate revocation certificate
    │       └──→ Prompt user to export separately
    │
    └──→ Prompt user to back up private key + share public key

Use (decrypt / sign):
    Keychain retrieve → SE reconstruct (biometric auth) → HKDF → AES-GCM unseal
    → Perform PGP operation → Zeroize private key from memory

Export (backup):
    Authenticate → User enters strong passphrase
    → Profile A: Iterated+Salted S2K protect → .asc file via Share Sheet
    → Profile B: Argon2id protect → .asc file via Share Sheet

Import (restore):
    .asc file → User enters passphrase → S2K derive (detect mode automatically) → Recover key
    → Generate new SE wrapping key → SE wrap → Store in Keychain

Revocation:
    Export revocation cert → Distribute to contacts → They import → Key marked revoked

Deletion:
    Double-confirm → Delete SE key from Keychain → Delete salt + sealed box
    → Key permanently inaccessible
```

**Profile-specific behavior:**
- **Generation:** Profile A → `CipherSuite::Cv25519` + `Profile::RFC4880`. Profile B → `CipherSuite::Cv448` + `Profile::RFC9580`.
- **Export:** Profile A → Iterated+Salted S2K. Profile B → Argon2id S2K.
- **Encryption format:** Determined by recipient key version, not sender profile. See [TDD](TDD.md) Section 1.4.

## 3. Secure Enclave Wrapping Scheme

The Secure Enclave supports only P-256. Private keys (Ed25519, X25519, Ed448, or X448) are protected via an indirect wrapping scheme. The wrapping scheme is identical for all key algorithms — the SE wraps raw private key bytes regardless of algorithm.

### Wrapping (on key generation or import)

1. Generate `SecureEnclave.P256.KeyAgreement.PrivateKey()` with access control flags matching the current auth mode.
2. Self-ECDH: compute shared secret between SE private key and its own public key. This computation happens inside the SE hardware.
3. Derive AES-256 key: `HKDF<SHA256>.deriveKey(inputKeyMaterial: sharedSecret, salt: randomSalt, info: infoString, outputByteCount: 32)` where `infoString = "CypherAir-SE-Wrap-v1:" + hexFingerprint`.
4. Seal: `AES.GCM.seal(privateKeyBytes, using: symmetricKey)`.
5. Store three Keychain items: SE key `dataRepresentation`, random salt, AES-GCM sealed box. **Confirm all three writes succeed.**
6. Only after successful storage: zeroize the raw private key bytes and symmetric key from memory.

**HKDF info string:** The info parameter includes a version prefix (`v1`) and the key's hex fingerprint to provide domain separation across different keys and future wrapping scheme versions. **This exact string must be constructed identically in `SecureEnclaveManager.swift`. Any mismatch will produce a different derived key and make existing wrapped keys permanently inaccessible.**

**Ordering rationale (steps 5–6):** Storage is performed before zeroization. If storage fails or the process crashes before step 5 completes, the raw key bytes are still in memory and the operation can be retried. If zeroization happened first and storage then failed, the key would be permanently lost.

### Unwrapping (on decrypt or sign)

1. Retrieve SE key blob, salt, and sealed box from Keychain.
2. Reconstruct SE key from `dataRepresentation` — this triggers device authentication (Face ID / Touch ID, with or without passcode fallback depending on auth mode).
3. Re-derive symmetric key: self-ECDH (inside SE) + HKDF with stored salt and same info string (`"CypherAir-SE-Wrap-v1:" + hexFingerprint`).
4. Open sealed box → raw private key bytes in application memory.
5. Perform the PGP operation.
6. Zeroize the private key bytes and symmetric key immediately.

### Security Properties

- Keychain data extraction without the SE hardware yields an encrypted blob that cannot be decrypted.
- The SE key's `dataRepresentation` is bound to the SoC UID (fused at manufacturing, never exposed to software).
- The raw private key exists in application memory briefly during use. This is an inherent tradeoff of the P-256-only SE constraint.
- SE ECDH latency: ~2–5ms. Imperceptible to users.

## 4. Authentication Modes

### Standard Mode (default)

```swift
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryAny, .or, .devicePasscode],
    &error
)
```

Face ID / Touch ID with device passcode fallback. Equivalent to `LAPolicy.deviceOwnerAuthentication`. Suitable for most users.

### High Security Mode

```swift
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryAny],
    &error
)
```

Face ID / Touch ID only. No passcode fallback. If biometrics are unavailable (sensor damaged, face obscured, biometry locked out after 5 failures), all private-key operations (decrypt, sign, export) are blocked until biometric auth is restored.

Inspired by Apple's Stolen Device Protection: prevents a thief who has both the device and the passcode from accessing encrypted data.

### Mode Switching Procedure

When the user changes mode in Settings:

1. Display warning. If switching to High Security and no backup exists, show a stronger warning requiring explicit acknowledgment.
2. Set an in-progress flag in UserDefaults (`com.cypherair.internal.rewrapInProgress = true`).
3. Authenticate under the **current** mode (proves the user has authority to change).
4. For each private key:
   a. Unwrap using the current SE key.
   b. Generate a new SE key with the **new** access control flags.
   c. Re-wrap the private key with the new SE key.
   d. Store the new Keychain items under **temporary key names** (e.g., `com.cypherair.v1.pending-se-key.<fingerprint>`).
   e. Zeroize the raw key bytes from memory.
5. **Verify all new items are successfully stored.**
6. Delete the **old** Keychain items (original `com.cypherair.v1.se-key.<fingerprint>` etc.).
7. Rename the temporary items to their permanent key names.
8. Persist the mode preference to UserDefaults (`com.cypherair.preference.authMode`).
9. Clear the in-progress flag (`com.cypherair.internal.rewrapInProgress = false`).

**Atomicity:** Old Keychain items are kept intact until ALL new items are confirmed stored (step 5). If any step fails before step 6, the original keys are unaffected — delete the temporary items and report the error.

**Crash recovery:** On app launch, check for the in-progress flag. If present:
- Check whether temporary items exist → if yes, the re-wrap was partially completed. Delete temporary items and clear the flag. The user's original keys are still intact under the old mode.
- Check whether old items are missing but temporary items exist → promote temporary items to permanent names and clear the flag.
- This ensures the app never enters an inconsistent state, regardless of when the crash occurred.

### LAPolicy Selection

| Mode | LAPolicy | Fallback Button |
|------|----------|-----------------|
| Standard | `.deviceOwnerAuthentication` | Passcode shown |
| High Security | `.deviceOwnerAuthenticationWithBiometrics` | `context.localizedFallbackTitle = ""` (hidden) |

## 5. Argon2id Parameters (Profile B Only)

Used only for private key export (backup) and for importing/unlocking passphrase-protected private key files. **Not used for routine message decryption or signing** — those operations use the SE-unwrapped private key directly.

**Not used by Profile A.** Profile A uses Iterated+Salted S2K (mode 3).

| Parameter | Value | RFC 9580 Encoding |
|-----------|-------|-------------------|
| Memory | 512 MB (524,288 KiB) | `encoded_m = 19` (2^19 KiB) |
| Parallelism | 4 lanes | `p = 4` |
| Time | Calibrated (~3s) | `t = calibrated on first export` |

### iOS Memory Safety Guard

Before Argon2id derivation **when importing or unlocking a passphrase-protected private key file** (this guard does NOT apply to routine message decryption):

1. Parse the S2K specifier from the key file.
2. Calculate required memory: `2^encoded_m` KiB.
3. Query `os_proc_available_memory()`.
4. If required > 75% of available memory: **refuse** with error message: _"This key uses memory-intensive protection that exceeds this device's capacity."_
5. Log the refused parameters (never the key material) for diagnostics.

This prevents iOS Jetsam from killing the app. The 75% threshold provides a safety margin.

## 6. Memory Integrity Enforcement (MIE)

### What It Protects

MIE is built right into Apple hardware and software in all models of iPhone 17 and iPhone Air (A19/A19 Pro). It provides hardware-level defense against buffer overflows and use-after-free in all C/C++ code, including vendored OpenSSL. The system allocator assigns 4-bit tags to heap allocations. Every memory access is checked by hardware in real time. Tag mismatch = immediate process termination.

### Enablement

In Xcode 26, Enhanced Security is managed via the `ENABLE_ENHANCED_SECURITY = YES` build setting. The `CypherAir.entitlements` file should contain an empty `<dict/>` — Xcode automatically injects the correct entitlements at build time. **Do not manually add entitlement keys to the `.entitlements` file**; doing so causes a build error ("Entitlements file was modified during the build").

To enable: Signing & Capabilities → Add Capability → Enhanced Security → enable Hardware Memory Tagging.

To verify: check `ENABLE_ENHANCED_SECURITY = YES` in both Debug and Release build settings in `project.pbxproj`.

### Testing Workflow

1. **Xcode diagnostics:** Enable Hardware Memory Tagging in Scheme → Run → Diagnostics. Run full test suite on A19 device. Any tag mismatch surfaces as a crash with exact location.
2. **Production:** Tag mismatches terminate the process immediately. This is the desired behavior — it converts silent corruption into a detectable, non-exploitable crash.

### Impact on Vendored OpenSSL

The `openssl-src` crate compiles OpenSSL from C source. Any undiscovered buffer overflow or use-after-free in OpenSSL will cause an immediate crash under MIE. This is the desired behavior — it converts silent corruption into a detectable, non-exploitable crash. Test all Sequoia + OpenSSL code paths (AES-256, SHA-512, Ed25519, X25519, Ed448, X448, Argon2id) under Hardware Memory Tagging diagnostics.

### Compatibility

| Device | MIE Behavior |
|--------|-------------|
| All models of iPhone 17 and iPhone Air (A19/A19 Pro) | Full hardware memory tagging active |
| Older devices (A15–A18) | Software-only typed allocator. No hardware tagging. |

The Enhanced Security capability is additive. It never breaks compatibility with older devices.

## 7. AI Coding Red Lines

The following files and functions are security-critical. Claude Code must **stop and describe proposed changes** before editing them. Do not make autonomous modifications.

### Files Requiring Human Review

| File | Reason |
|------|--------|
| `Sources/Security/SecureEnclaveManager.swift` | SE wrapping/unwrapping logic. Error = keys lost or insecure. |
| `Sources/Security/KeychainManager.swift` | Access control flags. Wrong flags = wrong auth behavior. |
| `Sources/Security/AuthenticationManager.swift` | Mode switching re-wrap. Error = keys permanently lost. |
| `Sources/Security/MemoryZeroingUtility.swift` | Removing a zeroize call = key material leaks. |
| `Sources/Services/DecryptionService.swift` | Phase 1/Phase 2 auth boundary. Skipping Phase 2 auth check = biometric bypass. |
| `Sources/Services/QRService.swift` | Parses untrusted external input (`cypherair://` URLs). Bugs here may trigger Sequoia parser on malicious data. |
| `pgp-mobile/src/decrypt.rs` | AEAD hard-fail enforcement. Weakening = plaintext leaks. |
| `pgp-mobile/src/error.rs` | PgpError enum. Must stay 1:1 with Swift. |
| `CypherAir.entitlements` | MIE, Enhanced Security entitlements. |
| `Info.plist` | Only `NSFaceIDUsageDescription` permitted. No other usage descriptions. |

### Functions Requiring Human Review

- Any function that calls `SecAccessControlCreateWithFlags`
- Any function that calls `SecureEnclave.P256.KeyAgreement.PrivateKey()`
- Any function that calls `AES.GCM.seal()` or `AES.GCM.open()` on key material
- Any function that calls `HKDF<SHA256>.deriveKey()`
- Any function that writes to or deletes from Keychain
- The `os_proc_available_memory()` guard in Argon2id handling
- Any Rust function marked `pub` in `pgp-mobile/src/lib.rs`
- URL parsing logic in `QRService` that handles `cypherair://` scheme input
- Profile/CipherSuite selection in key generation

### Testing Requirements for Security Changes

Every change to a file listed above must include:

1. **Positive test:** The operation succeeds with correct inputs and proper authentication.
2. **Negative test:** The operation fails gracefully with wrong inputs (wrong key, wrong passphrase, tampered data, unavailable biometrics).
3. **Round-trip test:** For crypto operations — encrypt then decrypt, sign then verify, wrap then unwrap.
4. **No-leak test:** For memory-sensitive changes — verify that sensitive data is zeroized after use (inspect with Xcode Memory Graph Debugger or Instruments).
