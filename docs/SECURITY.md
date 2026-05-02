# Security Model

> Purpose: Complete description of the encryption scheme, key lifecycle, authentication flows,
> security invariants, and AI coding boundaries for CypherAir.
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
| Random | SecRandomCopyBytes | Via `getrandom` crate on Apple platforms |

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
| Random | SecRandomCopyBytes | Via `getrandom` crate on Apple platforms |

**Interoperability:** Profile A output compatible with GnuPG 2.1+ and all PGP tools. Profile B output compatible with Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+, Bouncy Castle 1.82+. The App reads v4 keys, v6 keys, SEIPDv1, SEIPDv2 (OCB/GCM), Iterated+Salted S2K, and Argon2id S2K. Compression (`deflate`) read-only for compatibility; outgoing messages never compressed. Bzip2 excluded (extra C dependency).

## 2. Key Lifecycle

```
Generate (Profile A: Ed25519+X25519 v4 / Profile B: Ed448+X448 v6)
    │
    ├──→ SE Wrap (P-256 self-ECDH + HKDF + AES-GCM)
    │       │
    │       └──→ Store private-key material in Keychain (3 protected items per identity)
    │
    ├──→ Store PGPKeyIdentity metadata in ProtectedData `key-metadata`
    │       └──→ Opened after app-session authentication; no private-key material
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
    → Generate key-level revocation signature for imported key
    → Generate new SE wrapping key → SE wrap → Store in Keychain

Revocation:
    Export ASCII-armored revocation signature → Distribute to contacts → They import → Key marked revoked

Deletion:
    Double-confirm → Delete SE key from Keychain → Delete salt + sealed box
    → Delete protected key-metadata entry
    → Key permanently inaccessible
```

**Metadata storage note:** `PGPKeyIdentity` metadata is non-sensitive indexing data, but it now lives in the ProtectedData `key-metadata` domain so key-list loading happens only after app-session authentication opens protected app data. Legacy metadata rows may still exist in the dedicated metadata Keychain account (`KeychainConstants.metadataAccount`) or older default-account locations; those rows are migration/cleanup sources only and are read after app-session authentication, using the authenticated `LAContext` handoff when the default account requires it. Private-key blobs, salts, and sealed boxes remain in the protected private-key namespace.

**Revocation storage/export note:** CypherAir stores revocation signatures internally as binary OpenPGP signature packets. Export converts those bytes to ASCII armor on demand. Imported keys now receive key-level revocation export capability as part of import. Older imported keys that predate this support lazily backfill the binary revocation at export time, then immediately zeroize the temporarily unwrapped secret certificate bytes after use.

**Selective revocation note:** Subkey and User ID selective revocations are generated and exported on demand. They do not write back into `PGPKeyIdentity.revocationCert`, and they do not introduce an implicit persisted selective-revocation history alongside the key-level revocation slot.

**Certificate-signature workflow note:** Generated User ID certification signatures are exported artifacts. The workflow does not automatically insert them into a stored contact certificate, change `Contact.isVerified`, or introduce trust / web-of-trust policy semantics.

**Profile-specific behavior:**
- **Generation:** Profile A → `CipherSuite::Cv25519` + `Profile::RFC4880`. Profile B → `CipherSuite::Cv448` + `Profile::RFC9580`.
- **Export:** Profile A → Iterated+Salted S2K. Profile B → Argon2id S2K.
- **Encryption format:** Determined by recipient key version, not sender profile. See [TDD](TDD.md) Section 1.4.

## 3. Secure Enclave Wrapping Scheme

The Secure Enclave supports only P-256. Private keys (Ed25519, X25519, Ed448, or X448) are protected via an indirect wrapping scheme. The wrapping scheme is identical for all key algorithms — the SE wraps raw private key bytes regardless of algorithm.

### ProtectedData Device-Binding Note

ProtectedData uses a separate app-data root-secret model and must not be
conflated with private-key bundle wrapping. The current ProtectedData v2 model
keeps the Keychain / `SecAccessControl` / authenticated `LAContext` gate, but
stores the root-secret Keychain payload as a Secure Enclave device-bound
envelope instead of raw root-secret bytes.

The device-binding key is a ProtectedData-only P-256 Secure Enclave key with
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and `.privateKeyUsage`. It
must not include `.userPresence`, `.biometryAny`, or `.devicePasscode`, because
the user authentication prompt remains the existing app-session Keychain gate.
The SE layer is a silent second factor that makes copied Keychain payloads and
ProtectedData files unusable away from the original device. If the SE
device-binding key is missing or unusable, ProtectedData must fail closed and
require framework recovery/reset; there is no production fallback that opens v2
ProtectedData without the SE factor.

The v2 root-secret envelope is a binary-plist `CAPDSEV2` payload with
`algorithmID = p256-ecdh-hkdf-sha256-aes-gcm-v1`. It uses a normal
software-ephemeral P-256 ECDH exchange with the persistent ProtectedData SE
public key; it must not reuse the existing private-key self-ECDH wrapping
scheme as its security design. Its HKDF sharedInfo and AES-GCM AAD bind the
AAD version plus hashes of both persistent SE and ephemeral public keys. After
v2 migration succeeds, registry state plus
a ThisDeviceOnly Keychain `format-floor` marker must make later v1 raw
root-secret payloads fail closed as downgrade/corruption.

ProtectedData domain payloads must open only after the app privacy gate has
produced an authenticated `LAContext` or an already-authorized ProtectedData
session. The post-unlock domain coordinator may reuse that context for
registered committed domains, but it must skip pending-mutation, missing
context, and no-domain states without fetching the root secret or starting a
second interactive prompt.

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
2. Record the rewrap target and phase in the post-unlock `private-key-control.recoveryJournal`.
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
8. Persist the new mode to `private-key-control.settings.authMode`.
9. Clear the `private-key-control.recoveryJournal` rewrap entry.

**Atomicity:** Old Keychain items are kept intact until ALL new items are confirmed stored (step 5). If any step fails before step 6, the original keys are unaffected — delete the temporary items and report the error.

**Crash recovery:** After app-session authentication opens `private-key-control`, check the rewrap recovery journal. If an entry is present:
- If the permanent bundle is complete and temporary items exist, the permanent bundle is treated as authoritative. Delete the temporary items and keep the original mode.
- If the permanent bundle is partial but the temporary bundle is complete, the temporary bundle is treated as authoritative. Delete the residual permanent items, then promote the temporary bundle to permanent names.
- If the permanent bundle is missing and the temporary bundle is complete, promote the temporary bundle to permanent names.
- If neither namespace contains a complete three-item bundle, recovery is **unrecoverable**. Clear the journal entry, surface a generic post-unlock warning, and require the user to restore from backup if private-key operations fail.
- If deletion or promotion fails for a retryable reason (for example, transient Keychain write/delete failure), preserve the recovery journal so the app retries recovery after the next successful unlock.
- Recovery diagnostics are surfaced through the app's existing post-unlock warning path and must remain generic — never include fingerprints or other key identifiers.
- Persist the new auth mode only after a full successful promotion of complete pending bundles. Cleaning stale pending items alone must not change auth mode.
- This ensures the app prefers a complete bundle over a partial one and avoids silently finalizing an inconsistent state.

Legacy `UserDefaults` keys such as `com.cypherair.internal.rewrapInProgress` and `com.cypherair.preference.authMode` are migration sources only. Verified Phase 5 migration moves them into `private-key-control` and removes the legacy keys.

### LAPolicy Selection

| Mode | LAPolicy | Fallback Button |
|------|----------|-----------------|
| Standard | `.deviceOwnerAuthentication` | Passcode shown |
| High Security | `.deviceOwnerAuthenticationWithBiometrics` | `context.localizedFallbackTitle = ""` (hidden) |

## 5. Protected App Data

Protected app data is a separate security domain for CypherAir-owned local state outside private-key material. It must not be conflated with the Secure Enclave wrapping path that protects OpenPGP secret key bytes.

Current protected app-data scope:

- `private-key-control` stores the private-key control source of truth: `settings.authMode` plus the rewrap / modify-expiry `recoveryJournal`.
- `key-metadata` stores `PGPKeyIdentity` payloads after app unlock. Legacy metadata Keychain rows are migration and cleanup sources only.
- `protected-settings` stores protected settings. Schema v2 preserves `clipboardNotice` and adds grace period, onboarding completion, color theme, encrypt-to-self, and guided tutorial completion.
- `protected-framework-sentinel` is a framework-owned sentinel domain with a schema/purpose marker only. It contains no user data, telemetry, contacts, or UI state.

Current non-goals and pending surfaces:

- Permanent and pending SE-wrapped private-key bundle rows remain in the existing private-key material domain.
- `appSessionAuthenticationPolicy` remains an early-readable boot-authentication setting.
- Self-test reports are short-lived export-only data held in memory until explicit user export, reset, or app exit; legacy `Documents/self-test/` content is cleanup-only on startup and local-data reset. Decrypted, streaming, export handoff, and tutorial artifacts are Phase 7 `ephemeral-with-cleanup` state: CypherAir-owned temporary files/directories use verified complete file protection where created by the app, per-operation or owner cleanup, startup cleanup, and Reset All Local Data cleanup. Phase 7 is complete. Contacts remain outside ProtectedData until unblocked Phase 8 implementation lands. Phase 7 PR 2 moved the targeted ordinary settings into `protected-settings`; legacy ordinary `UserDefaults` keys are cleanup-only after verified schema v2 readback.

Protected app-data authorization uses `AppSessionAuthenticationPolicy`, not private-key `AuthenticationMode`. `AppSessionOrchestrator` owns launch/resume privacy authentication and the grace window. When app authentication succeeds, it can hand the authenticated `LAContext` to `ProtectedDataSessionCoordinator`, which reads the shared app-data root secret through Keychain with `kSecUseAuthenticationContext`. That same authenticated handoff is reused by post-unlock domain openers so committed registered domains can open without a second Face ID / Touch ID prompt.

`ProtectedOrdinarySettingsCoordinator` owns ordinary-settings availability after Phase 7 PR 2. It loads grace period, onboarding completion, color theme, encrypt-to-self, and guided tutorial completion from `protected-settings` schema v2 only after app privacy authentication and an unlocked protected-settings handoff. Existing schema v1 payloads are upgraded through an explicit compatibility path using legacy ordinary settings as a migration source; schema v2 payloads are strict, so missing or corrupt ordinary settings enter protected-settings recovery instead of resetting to defaults. If the setting snapshot is unavailable, the resume grace window fails closed to immediate authentication, startup/onboarding routing waits for a loaded snapshot, and encryption does not silently use the app-default encrypt-to-self value for real work.

The shared root secret is not stored as raw bytes in the current format. Keychain stores a v2 `CAPDSEV2` envelope that must also unwrap through the ProtectedData-only Secure Enclave device-binding key described in Section 3. The raw root secret is used only to derive the wrapping root key and is immediately zeroized. Each protected domain has its own random domain master key, persisted only as a wrapped-DMK record under the derived wrapping root key. Unwrapped domain keys and decrypted payloads are session-local and must be cleared on relock.

`ProtectedDataRegistry` is the only authority for committed protected-domain membership and pending create/delete work. Cold start may read the registry and per-domain bootstrap metadata before app authentication, but it must not retrieve the root secret, unwrap any DMK, open domain payloads, or infer committed membership by directory enumeration. Invalid registry state enters framework recovery. Domain corruption enters the domain's recovery state; no protected domain may silently reset unreadable state to empty data.

Relock is fail-closed. `ProtectedDataSessionCoordinator` blocks new protected-domain access, fans out to all registered `ProtectedDataRelockParticipant`s, zeroizes the wrapping root key, clears unwrapped DMKs, and returns to `sessionLocked` only if teardown succeeds. The ordinary-settings coordinator also clears its loaded snapshot on relock/content clear. Any relock participant failure latches runtime-only `restartRequired`, blocking further protected-domain access until process restart.

ProtectedData files live under `Application Support/ProtectedData/`. Registry files, bootstrap metadata, scratch writes, wrapped-DMK files, and committed domain files use explicit file-protection verification where the platform supports it. Storage outside the app-owned container is not an allowed fallback for protected-domain files.

## 6. Guided Tutorial Sandbox Isolation

The guided tutorial is allowed to run real app services and real OpenPGP operations only inside an isolated tutorial dependency graph. It must not read or mutate the user's real keys, contacts, settings, files, exports, or private-key security assets.

Tutorial isolation boundaries:

- `TutorialSandboxContainer` uses the fixed `com.cypherair.tutorial.sandbox` `UserDefaults` suite and a temporary contacts directory with verified complete file protection instead of the app's real preferences and `Documents/contacts` storage. The product flow owns a single active tutorial sandbox at a time; container creation and current tutorial cleanup clear the fixed suite and directory. Startup and Reset All Local Data also remove legacy orphaned `com.cypherair.tutorial.<UUID>` suites.
- Tutorial key management, encryption, decryption, signing, certificate, QR, and self-test services are constructed against tutorial-local storage and the same Rust engine API shape used by the real app.
- Tutorial private-key protection uses mock Secure Enclave and mock Keychain primitives behind a real `AuthenticationManager` instance, so auth-mode behavior is exercised without touching real Secure Enclave-wrapped private keys or real Keychain rows.
- `OutputInterceptionPolicy` and page-level configuration must block or intercept real file import/export, clipboard writes, share-sheet export, URL handoff, app icon changes, onboarding management actions, and other real-workspace side effects.
- Tutorial completion state is the only tutorial fact that persists across app restarts. Tutorial keys, contacts, messages, settings, and unfinished module progress are ephemeral and are cleaned up when the tutorial is reset or finished.

Changes to tutorial isolation, output interception, or tutorial security simulation must be reviewed with the same care as other auth and local-data boundaries. A tutorial regression must never weaken the app's zero-network, minimal-permission, no-secret-logging, or real-workspace isolation guarantees.

## 7. Argon2id Parameters (Profile B Only)

Used only for private key export (backup) and for importing/unlocking passphrase-protected private key files. **Not used for routine message decryption or signing** — those operations use the SE-unwrapped private key directly.

**Not used by Profile A.** Profile A uses Iterated+Salted S2K (mode 3).

| Parameter | Value | RFC 9580 Encoding |
|-----------|-------|-------------------|
| Memory | 512 MB (524,288 KiB) | `encoded_m = 19` (2^19 KiB) |
| Parallelism | 4 lanes | `p = 4` |
| Time | Fixed at 3 passes (~3s target on contemporary hardware) | `t = 3` |

### iOS Memory Safety Guard

Before Argon2id derivation **when importing or unlocking a passphrase-protected private key file** (this guard does NOT apply to routine message decryption):

1. Parse the S2K specifier from the key file.
2. Calculate required memory: `2^encoded_m` KiB.
3. Query `os_proc_available_memory()`.
4. If required > 75% of available memory: **refuse** with error message: _"This key uses memory-intensive protection that exceeds this device's capacity."_
5. Return a user-facing refusal error before Argon2id derivation begins.

This prevents iOS Jetsam from killing the app. The 75% threshold provides a safety margin.

## 8. Memory Integrity Enforcement (MIE)

### What It Protects

MIE is built right into Apple hardware and software in all models of iPhone 17 and iPhone Air (A19/A19 Pro). It provides hardware-level defense against buffer overflows and use-after-free in all C/C++ code, including vendored OpenSSL. The system allocator assigns 4-bit tags to heap allocations. Every memory access is checked by hardware in real time. Tag mismatch = immediate process termination.

### Enablement

Enhanced Security is enabled via Signing & Capabilities → Add Capability → Enhanced Security → enable Hardware Memory Tagging. When this capability is added, Xcode writes the required entitlement keys into `CypherAir.entitlements`:

- `com.apple.security.hardened-process` → `true`
- `com.apple.security.hardened-process.enhanced-security-version` → `1`
- `com.apple.security.hardened-process.hardened-heap` → `true`
- `com.apple.security.hardened-process.platform-restrictions` → `2`
- `com.apple.security.hardened-process.dyld-ro` → `true`
- `com.apple.security.hardened-process.checked-allocations` → `true` (Hardware Memory Tagging)
- `com.apple.security.hardened-process.checked-allocations.enable-pure-data` → `true`
- `com.apple.security.hardened-process.checked-allocations.no-tagged-receive` → `true`

**These entitlement keys must be committed to source control.** Xcode reads the `.entitlements` file to determine which protections are enabled. Removing the keys disables the corresponding protections.

Additionally, verify `ENABLE_ENHANCED_SECURITY = YES` in both Debug and Release build settings in `project.pbxproj`.

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

## 9. Known Limitations

### 9.1 Passphrase `String` Cannot Be Reliably Zeroized

**Scope:** Affects passphrase-based flows that originate in Swift `String`, specifically private key import/export and password-message encrypt/decrypt operations. It does **not** affect routine recipient-key decryption or signing, which use SE-unwrapped key bytes (`Data`) that are properly zeroized.

**Issue:** Swift `String` is a value type with copy-on-write semantics. There is no supported API to overwrite a `String`'s internal buffer in place. When the user enters a passphrase for key export (S2K protection), key import (S2K unlock), or password-message encrypt/decrypt (`SKESK`), the passphrase exists as a `String` in memory until ARC deallocates it. The exact lifetime depends on the Swift runtime and is not deterministic.

**Why this is not fixed:**

1. **SwiftUI constraint:** `SecureField` — the only system-provided secure text input — binds to `String`. There is no `Data`-backed alternative.
2. **FFI boundary:** UniFFI transfers `String` by copying through `RustBuffer`. Even if the Swift side could zeroize its copy, the Rust side receives an independent copy (which Sequoia consumes and the Rust `zeroize` crate handles on its side).
3. **Platform-wide pattern:** No shipping iOS app (including Apple's own Keychain prompts) can zeroize `String` passphrases. This is an accepted platform limitation.

**Mitigations:**

- **Short lifetime:** The passphrase `String` is only alive for the duration of the active import/export or password-message call. It is not stored in any persistent state, UserDefaults, or Keychain.
- **Rust-side zeroize:** The `zeroize` crate ensures the Rust copy of the passphrase is overwritten after use.
- **iOS memory protections:** ASLR, sandboxing, and MIE (on A19+ devices) make memory scanning attacks significantly harder.
- **Immediate Rust conversion:** Password-message APIs convert the Swift `String` into Sequoia `Password` at the FFI boundary so the Rust-side representation is encrypted in memory and only decrypted on demand.

**Rejected alternatives:**

- `UnsafeMutableBufferPointer<UInt8>` with manual zeroing: Would require forking `SecureField` or building a custom UIKit text field, bypassing system-provided secure input. The security loss from a custom input field (no system-level screen recording protection, no secure text entry mode) would outweigh the benefit of zeroizable memory.
- `Data`-based passphrase: UniFFI does not support `Data` ↔ `String` conversion at the FFI boundary without an intermediate `String` allocation, negating the benefit.

## 10. AI Coding Red Lines

The following files and functions are security-critical. Claude Code must **stop and describe proposed changes** before editing them. Do not make autonomous modifications.

### Files Requiring Human Review

| File | Reason |
|------|--------|
| `Sources/Security/SecureEnclaveManager.swift` | SE wrapping/unwrapping logic. Error = keys lost or insecure. |
| `Sources/Security/KeychainManager.swift` | Access control flags. Wrong flags = wrong auth behavior. |
| `Sources/Security/AuthenticationManager.swift` | Mode switching re-wrap. Error = keys permanently lost. |
| `Sources/Security/ProtectedData/` | App-data root-secret authorization, SE device-binding envelope, domain master-key wrapping, reset semantics. Error = protected app data lost or opened under the wrong gate. |
| `Sources/Security/MemoryZeroingUtility.swift` | Removing a zeroize call = key material leaks. |
| `Sources/Extensions/Data+Zeroing.swift` | Contains `@_optimize(none)` zeroing barrier. Weakening = compiler may eliminate all memory zeroing app-wide. |
| `Sources/Services/DecryptionService.swift` | Phase 1/Phase 2 auth boundary. Skipping Phase 2 auth check = biometric bypass. |
| `Sources/Services/QRService.swift` | Parses untrusted external input (`cypherair://` URLs). Bugs here may trigger Sequoia parser on malicious data. |
| `pgp-mobile/src/decrypt.rs` | AEAD hard-fail enforcement. Weakening = plaintext leaks. |
| `pgp-mobile/src/streaming.rs` | Streaming file encrypt/decrypt with buffer zeroing. Error in temp file handling = plaintext leaks to disk. |
| `pgp-mobile/src/error.rs` | PgpError enum. Must stay 1:1 with Swift. |
| `Sources/Services/DiskSpaceChecker.swift` | Disk space validation threshold. Wrong threshold = Jetsam termination during file operations. |
| `CypherAir.entitlements` | MIE, Enhanced Security entitlements. |
| `CypherAir-Info.plist` | Only `NSFaceIDUsageDescription` permitted. No other usage descriptions. |

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
