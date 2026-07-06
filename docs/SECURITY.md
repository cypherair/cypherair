# Security Model

> Status: Canonical current-state.
> Purpose: The encryption scheme, key lifecycle, wrapping and authentication contracts, security invariants, and the AI coding red lines.
> Audience: Human developers, security auditors, and AI coding tools.
> Update triggers: Changes to crypto/profile behavior, key lifecycle, Secure Enclave wrapping, authentication modes, the ProtectedData model, tutorial isolation, MIE posture, or the Section 10 red lines.
> Last reviewed: 2026-07-05.

## 1. Encryption Scheme

All cryptographic operations use Sequoia PGP 2.4.0 (`crypto-openssl` backend). Three software profiles with different algorithm suites; the composite Post-Quantum suite also backs the Device-Bound Post-Quantum split-custody family.

### Profile A (Universal Compatible)

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Primary key (sign/certify) | Ed25519 (legacy EdDSA) | v4 key format |
| Encryption subkey | X25519 (legacy ECDH) | v4 key format |
| Symmetric encryption | AES-256 | |
| Message format | SEIPDv1 (MDC) | Non-AEAD; GnuPG compatible |
| Hash | SHA-512 | Accepts SHA-256 for legacy verification |
| S2K (key export) | Iterated+Salted (mode 3) | GnuPG compatible |
| Compression | DEFLATE (read-only) | Outgoing messages never compressed |
| Random | SecRandomCopyBytes | Via `getrandom` crate on Apple platforms |

### Profile B (Advanced Security)

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Primary key (sign/certify) | Ed448 | v6 key format; ~224-bit security |
| Encryption subkey | X448 | v6 key format; inherent AES-256 key wrap |
| Symmetric encryption | AES-256 | |
| AEAD | OCB (primary), GCM (secondary) | SEIPDv2; OCB mandatory per RFC 9580 |
| Hash | SHA-512 | |
| S2K (key export) | Argon2id (512 MB / p=4 / ~3s) | Memory-hard |
| Compression | DEFLATE (read-only) | Outgoing messages never compressed |
| Random | SecRandomCopyBytes | Via `getrandom` crate on Apple platforms |

### Post-Quantum (RFC 9980)

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Primary key (sign/certify) | ML-DSA-65+Ed25519 (composite, algo 30) | v6 key format; ~192-bit, quantum-resistant |
| Encryption subkey | ML-KEM-768+X25519 (composite, algo 35) | v6 key format; AES-256 floor for any PQ recipient |
| Symmetric encryption | AES-256 | RFC 9980 floor |
| AEAD | OCB | SEIPDv2 |
| Hash | SHA-512 | |
| S2K (key export) | Argon2id (512 MB / p=4 / ~3s) | Portable family only; device-bound is never exportable |

Full profile table and classification rule: [TDD.md](TDD.md) §1.3. Split custody for the device-bound variant: [SECURE_ENCLAVE_CUSTODY.md](SECURE_ENCLAVE_CUSTODY.md) §4.1.

**Interoperability:** per-profile compatibility exposure (which external tools each family works with) is product canon in [PRD.md](PRD.md) §3. The security-owned read-support contract: the App reads v4 keys, v6 keys, SEIPDv1, SEIPDv2 (OCB/GCM), Iterated+Salted S2K, and Argon2id S2K. Compression (`deflate`) is read-only for compatibility; outgoing messages are never compressed. Bzip2 is excluded (extra C dependency).

## 2. Key Lifecycle

```
Generate (family-aware: software families produce a secret certificate;
          device-bound families generate inside the Secure Enclave — see SECURE_ENCLAVE_CUSTODY.md)
    │
    ├──→ Software custody: SE Wrap (P-256 ephemeral-static ECDH + HKDF + AES-GCM, AAD-bound)
    │       └──→ Store one CAPKEV1 envelope row per identity in Keychain
    │
    ├──→ Store PGPKeyIdentity metadata in ProtectedData `key-metadata`
    │       └──→ Opened after app-session authentication; no private-key material
    │
    ├──→ Auto-generate revocation certificate → prompt user to export separately
    │
    └──→ Prompt user to back up private key (software custody) + share public key

Use (decrypt / sign):
    Keychain retrieve → decode envelope → SE reconstruct (device authentication)
    → ECDH(SE priv × envelope ephemeral pub) → HKDF → AES-GCM unseal (AAD-checked)
    → Perform PGP operation → Zeroize private key from memory

Export (backup):   Authenticate → strong passphrase → S2K protect (per profile) → .asc via Share Sheet
Import (restore):  .asc → passphrase → S2K derive (mode auto-detected) → recover key
                   → generate key-level revocation for the imported key → new SE wrap → Keychain
Revocation:        Export ASCII-armored revocation signature → contacts import it → key marked revoked
Deletion:          Double-confirm → delete the envelope row and the protected key-metadata entry
```

- **Metadata storage:** `PGPKeyIdentity` metadata is non-sensitive indexing data, but it lives in the ProtectedData `key-metadata` domain so key-list loading happens only after app-session authentication. The sealed envelope stays in the private-key Keychain namespace.
- **Revocation storage/export:** Revocation signatures are stored as binary OpenPGP packets and armored on demand at export. Export uses only the stored artifact and fails closed when it is missing.
- **Selective revocation:** Subkey and User ID revocations are generated and exported on demand; they do not write back into `PGPKeyIdentity.revocationCert` and create no persisted selective-revocation history.
- **Certification workflow:** Generated User ID certification signatures are saved to the protected `contacts` domain only when the user explicitly certifies and the signature verifies against the selected key and exact selector. Saved artifacts are canonical binary signature bytes, armored only for explicit export. Certification persistence never inserts signatures into a stored contact certificate, never changes manual verification state, and introduces no web-of-trust semantics.
- **Format selection:** message format is determined by recipient key version, never sender profile ([TDD.md](TDD.md) §1.4); the exact per-profile `CipherSuite`/`Profile` values are TDD.md §1.3's table.

## 3. Secure Enclave Wrapping Scheme

The Secure Enclave natively holds only some key types (P-256, and on current OS versions ML-KEM/ML-DSA) — not the classical curves the software families use. Software-custody private keys are therefore protected by an indirect wrapping scheme that is identical for every software-key algorithm: the SE wraps raw private key bytes regardless of curve.

### Wrapping (on key generation or import)

1. Generate `SecureEnclave.P256.KeyAgreement.PrivateKey()` with access-control flags matching the current auth mode.
2. Generate a software-ephemeral `P256.KeyAgreement.PrivateKey()` and compute `ECDH(ephemeral private × persistent SE public)`.
3. Derive an AES-256 key with HKDF-SHA256 over a random salt and `sharedInfo` (prefix `CAPKKI`) binding the magic, algorithmID, lowercase hex fingerprint, SHA-256 hashes of the SE key blob and both public keys, and the plaintext length.
4. Seal with AES-GCM, authenticating the same binding as AAD under prefix `CAPKAD` (domain-separated from the HKDF info).
5. Store one Keychain row: the encoded `CAPKEV1` envelope (SE key blob, both public keys, salt, nonce, ciphertext, tag). **Confirm the write succeeds.**
6. Only after successful storage: zeroize the raw private key bytes (CryptoKit's `SymmetricKey`/`SharedSecret` clear their own storage).

**Public-parameter binding:** the fingerprint and both public keys are bound through HKDF `sharedInfo` and the AES-GCM AAD, so no public field can be substituted without breaking authentication. **The envelope is the only supported private-key payload** — any row that does not decode as a current `CAPKEV1` envelope fails closed as ordinary undecodable input; there is no legacy wrapping format to migrate.

**Ordering rationale (steps 5–6):** storage before zeroization. If storage fails or the process crashes first, the raw bytes are still in memory and the operation can retry; the reverse order would permanently lose the key.

### Unwrapping (on decrypt or sign)

1. Retrieve and decode + validate the envelope row (magic/version/algorithm/lengths/fingerprint binding; both public keys parse as P-256 points).
2. Reconstruct the SE key from the envelope's folded `dataRepresentation` — this triggers device authentication per auth mode.
3. Fail closed if the envelope's bound SE public key does not match the reconstructed handle; then recompute the ECDH shared secret and re-derive the symmetric key + AAD.
4. `AES.GCM.open` (AAD-checked) → raw private key bytes; any tamper, wrong binding, or wrong fingerprint aborts with no plaintext.
5. Perform the PGP operation.
6. Zeroize the private key bytes immediately.

### Security Properties

- Keychain extraction without the SE hardware yields an encrypted blob that cannot be decrypted; the SE key's `dataRepresentation` is bound to the SoC UID.
- The raw private key exists in app memory briefly during use — the inherent tradeoff of non-SE-resident algorithms. Device-bound families avoid it entirely (operations run inside the enclave).
- SE ECDH latency is ~2–5 ms — imperceptible to users.

### Secure Enclave Custody (device-bound families) — red lines

A second, implemented custody model — the Device-Bound key families — performs private-key operations inside the Secure Enclave and never exports long-term private scalars, instead of unwrapping a secret certificate into app memory. The full custody contract, operation surface, split-custody model, and hardware evidence live in [SECURE_ENCLAVE_CUSTODY.md](SECURE_ENCLAVE_CUSTODY.md). Mode switching is custody-aware: device-bound keys have no SE-wrapped software bundle, so the re-wrap workflow and its recovery enumerate software-custody fingerprints only, and the High Security backup expectation applies to software-custody keys only.

The durable red lines below bind all code under `Sources/Security/SecureEnclaveCustody*`, `Sources/Security/SecureEnclaveComposite*`, and `pgp-mobile`:

- **Handles & access control.** For the classical device-bound families: two distinct role-tagged SE P-256 `SecKey` rows per identity (`.signing`, `.keyAgreement`), created with `kSecAttrTokenIDSecureEnclave` and access control `WhenUnlockedThisDeviceOnly + .privateKeyUsage + .biometryAny` — no `.devicePasscode`, no `.or`, and never the mode-dependent app helper. Creation sets no `kSecAttrCanSign`/`kSecAttrCanDerive` usage flags — role trust comes only from the role tag, public-key binding, and router policy. Application tags are a random handle-set id plus role, never a fingerprint. Load/inspect fail closed unless the stored role and the 65-byte X9.63 public key both match. (Composite custody uses a different handle shape under the same fixed access policy — [SECURE_ENCLAVE_CUSTODY.md](SECURE_ENCLAVE_CUSTODY.md) §4.1.)
- **External operation boundary.** Rust/Sequoia owns all OpenPGP semantics; the enclave performs only the private scalar operation through a narrow callback. Signing: public key + SHA-256 digest in, ECDSA `r/s` out, verified by Rust against that key and digest. Key agreement: recipient + ephemeral public keys in, raw 32-byte shared secret out; Rust owns the ECDH KDF, AES Key Wrap, session-key validation, payload authentication, and verification folding. Swift zeroizes the shared-secret buffers it owns; Rust hard-aborts a malformed or zero shared secret. The callback never carries secret certificate material.
- **Dispatch & fail-closed.** `PGPKeyCapabilityResolver` gates generation, signing-class, and key-agreement operations independently; `PrivateKeyOperationRouter` returns a Secure Enclave route only after the stored public certificate, fingerprint, key version, role, and public-key bindings agree with the Security-owned handles. A Secure Enclave route **never falls back** to software secret-certificate material. The decrypt Phase 1/Phase 2 boundary is preserved: Phase 1 recipient parsing is unauthenticated and the matched-key guard runs before any private-key access.
- **Sanitized failure mapping.** All custody error paths expose only stable app-owned categories. Logs, errors, UI, ProtectedData, and Rust never carry fingerprints, application tags, handle-set identifiers, public-binding bytes, Keychain locators, plaintext, private material, shared secrets, session keys, KEKs, digests, or signatures.
- **Storage, export & hard-fail.** Generation stores only the public certificate, the key-level revocation packet, and the custody kind in `key-metadata` — never private material, handle locators, or access-control policy. A missing revocation artifact fails closed and is never regenerated. Private-key backup/export is unsupported and must not touch the `privkey-envelope` row. Payload authentication is unchanged: MDC/AEAD hard-fail with no partial plaintext; streaming decrypt releases output only through the success-only `.tmp`-then-rename contract.
- **Reset & recovery.** Reset All Local Data inventories and deletes only app-owned custody rows (including malformed app-owned tags); startup classification never deletes orphan handles and produces only an in-memory sanitized report.

### ProtectedData Device-Binding Note

ProtectedData uses a separate app-data root-secret model — do not conflate it with private-key envelope wrapping. The root-secret Keychain payload is a single self-contained `CAPDSEV3` envelope: a ProtectedData-only P-256 SE device-binding key (`WhenPasscodeSetThisDeviceOnly + .privateKeyUsage`; never `.userPresence`/`.biometryAny`/`.devicePasscode`, because the user-facing prompt remains the existing app-session Keychain gate) is folded into the envelope and reconstructed at open time. The SE layer is a silent second factor that makes copied Keychain payloads and ProtectedData files useless off-device. `CAPDSEV3` and `CAPKEV1` share the ephemeral-static ECDH construction but are domain-separated by distinct magic values and HKDF/AAD prefixes, so neither blob can be misread as the other. The `CAPDSEV3` envelope is the only supported root-secret payload: anything else fails closed as undecodable input, and if the enclave cannot reconstruct the folded key (or its public key mismatches the bound key), ProtectedData fails closed into framework recovery — there is no fallback that opens ProtectedData without the SE factor.

Protected domain payloads open only after the app privacy gate produced an authenticated `LAContext` (or an already-authorized session). The post-unlock coordinator may reuse that context for registered committed domains but must skip pending-mutation, missing-context, and no-domain states without fetching the root secret or prompting again.

## 4. Authentication Modes

Authentication presentation is the **system authentication sheet** for both subsystems on every platform (macOS 27 denies embedded LocalAuthentication UI to non-Apple-signed processes, LA -1007). App lock is an explicit state machine (`AppLockController`: `.locked`/`.authenticating`/`.unlocked`) with per-platform away events. **Each system prompt runs inside a short operation-prompt session** covering the prompt plus the immediately following Keychain/Secure Enclave call that consumes the same `LAContext`; longer work (PGP generation, import parsing, journaling, commits, reset I/O, UI updates) stays outside the session, so prompt-lifecycle resigns are deferred while genuine away events under grace=0 still relock immediately. Key-expiry modification authenticates once per action with an `LAContext` confined to that action.

### Standard Mode (default)

```swift
SecAccessControlCreateWithFlags(kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryAny, .or, .devicePasscode], &error)
```

Face ID / Touch ID with device-passcode fallback (equivalent to `LAPolicy.deviceOwnerAuthentication`).

### High Security Mode

```swift
SecAccessControlCreateWithFlags(kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryAny], &error)
```

Biometrics only — no passcode fallback. If biometrics are unavailable (sensor damage, lockout after failed attempts), all private-key operations are blocked until restored. `.biometryAny` means keys are not invalidated by biometric re-enrollment.

### Mode Switching

Switching re-wraps every **software-custody** key under a single authentication: record the target in the `private-key-control.recoveryJournal`, authenticate under the **current** mode, unwrap each key and re-wrap it under the new flags into the pending row (`com.cypherair.v1.pending-privkey-envelope.<fingerprint>`), and only after **all** pending rows are verified stored: delete old rows, promote pending rows, persist the new `authMode`, clear the journal. If switching to High Security with un-backed-up software keys, a stronger warning requires explicit acknowledgment first.

**Crash-recovery invariant:** old rows stay authoritative until every new row is confirmed. Recovery (after unlock opens `private-key-control`) prefers an existing permanent row over a pending one; promotes a complete pending row only when the permanent row is absent or invalid; keeps the journal on retryable Keychain failures so recovery re-runs after the next unlock; treats no-complete-row-anywhere as unrecoverable (clear journal, surface a generic warning that never includes fingerprints); and persists the new auth mode only after a full successful promotion — cleaning stale pending rows alone never changes the mode.

### LAPolicy Selection

| Mode | LAPolicy | Fallback button |
|------|----------|-----------------|
| Standard | `.deviceOwnerAuthentication` | Passcode shown |
| High Security | `.deviceOwnerAuthenticationWithBiometrics` | `context.localizedFallbackTitle = ""` (hidden) |

## 5. Protected App Data

Protected app data is a separate security domain for CypherAir-owned local state outside private-key material. Row-level scope and classification live in [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md); this section records the invariants.

- Protected domains open only after app privacy authentication through the shared ProtectedData authorization path. `appSessionAuthenticationPolicy` remains the documented early-readable boot exception; UserDefaults is otherwise allowed only for documented boot/test/tutorial exceptions.
- Authorization uses `AppSessionAuthenticationPolicy`, not private-key `AuthenticationMode`. `AppLockController` owns lock state and the away/grace lifecycle; `AppSessionOrchestrator` owns the authentication record and hands the authenticated `LAContext` to `ProtectedDataSessionCoordinator`, which reads the root secret with `kSecUseAuthenticationContext`. Post-unlock domain openers reuse that handoff so committed domains open without a second prompt.
- The raw root secret exists only to derive the wrapping root key and is immediately zeroized. Each domain has its own random master key, persisted only as a Keychain-backed `CADMKV2` wrapped-DMK envelope under the wrapping root key. Unwrapped DMKs and decrypted payloads are session-local.
- `ProtectedOrdinarySettingsCoordinator` owns ordinary-settings availability, loading grace period, onboarding completion, encrypt-to-self, and tutorial completion from `protected-settings` schema v2 only after an unlocked handoff. Missing or corrupt payloads enter recovery instead of resetting to defaults; while the snapshot is unavailable, resume grace fails closed to immediate authentication, startup/onboarding routing waits for a loaded snapshot, and encryption never silently uses a default encrypt-to-self value.
- `KeyMetadataDomainStore` stores schema v2 `PGPKeyIdentity` records (configuration identity + custody kind) and stays metadata-only — no handle locators, access-control policy, salts, sealed boxes, or secret bytes. Corrupt or bootstrap-mismatched committed metadata enters recovery.
- Key-operation failure categories are sanitized app-owned classifications; local-authentication categories stay separate from payload-authentication failure, and none may contain plaintext, key material, shared secrets, session keys, KEKs, locators, stable fingerprints, or capability paths.
- Contacts production state lives in the protected `contacts` domain with SQLCipher as the authoritative payload: the unwrapped `contacts` domain master key is handed directly to SQLCipher via raw-key syntax (no second database-key Keychain row), the raw-key buffer is zeroized after keying, and the open connection is closed on relock and before reset/recovery deletion. Legacy flat Contacts files under `Documents/contacts` are outside supported app state (not read, migrated, quarantined, or reset-cleaned); legacy snapshot artifacts are never a fallback source of truth. Manual verification is a local fingerprint assertion, not OpenPGP certification; certification-signature export is an explicit artifact boundary, not a Contacts backup; any future Contacts package exchange must be mandatory encrypted.
- `ProtectedDataRegistry` is the only authority for committed domain membership and pending mutations. Cold start may read the registry and bootstrap metadata pre-auth but must not retrieve the root secret, unwrap DMKs, open payloads, or infer membership from directory listings. Invalid registry state enters framework recovery; domain corruption enters that domain's recovery; no domain silently resets unreadable state to empty.
- Relock is fail-closed: block new access, fan out to all relock participants, zeroize the wrapping root key, clear unwrapped DMKs and loaded snapshots, and return to `sessionLocked` only if teardown succeeds. Any participant failure latches runtime-only `restartRequired`.
- Registry files, bootstrap metadata, scratch writes, committed domain files, and SQLCipher sidecars verify explicit file protection where the platform supports it; storage outside the app-owned container is never a fallback.

## 6. Guided Tutorial Sandbox Isolation

The guided tutorial may run real app services and real OpenPGP operations only inside an isolated tutorial dependency graph; it must never read or mutate real keys, contacts, settings, files, or exports.

- `TutorialSandboxContainer` uses the fixed `com.cypherair.tutorial.sandbox` defaults suite and a temporary contacts directory with verified file protection. One active sandbox at a time; container creation, tutorial cleanup, startup, and Reset All Local Data all clear the fixed suite and directories.
- Tutorial private-key protection currently uses mock Secure Enclave and Keychain primitives behind a real `AuthenticationManager` — accepted debt. Mocks must remain visibly named `Mock*`, stay under `Sources/Security/Mocks`, and keep mock-owned errors instead of impersonating production `KeychainError`. The long-term direction is tutorial-specific isolated ProtectedData domains with real hardware-backed processing.
- `OutputInterceptionPolicy` and page configuration block real file import/export, clipboard writes, share-sheet export, URL handoff, app-icon changes, and other real-workspace side effects. Tutorial completion state is the only fact that persists across restarts.

Changes to tutorial isolation get the same review care as other auth/local-data boundaries; a tutorial regression must never weaken the zero-network, minimal-permission, no-secret-logging, or workspace-isolation guarantees.

## 7. Argon2id Parameters

Used for private-key export and for importing passphrase-protected key files with Argon2id S2K (Profile B and Portable Post-Quantum). Not used for routine decrypt/sign, and not used by Profile A (Iterated+Salted, mode 3). The exact parameter set (512 MB / p=4 / t=3, with RFC 9580 encodings) is [TDD.md](TDD.md) §4's table.

**Memory-safety guard (import/unlock only):** parse the S2K specifier, compute `2^encoded_m` KiB, query available memory (`os_proc_available_memory()` on iOS/iPadOS/visionOS; total physical memory on macOS, which has no Jetsam), and refuse above the 75% threshold with _"This key uses memory-intensive protection that exceeds this device's capacity."_ — before derivation begins. This prevents iOS Jetsam termination.

## 8. Memory Integrity Enforcement (MIE)

MIE (hardware memory tagging) protects all C/C++ code — including vendored OpenSSL — against buffer overflows and use-after-free on supported hardware; tag mismatches terminate the process, converting silent corruption into a detectable, non-exploitable crash.

Enablement is the Enhanced Security capability (`ENABLE_ENHANCED_SECURITY = YES` in both Debug and Release), which writes these entitlement keys into `CypherAir.entitlements` and `CypherAirMacOS.entitlements` — **the keys must stay committed to source control**:

- `com.apple.security.hardened-process` → `true`
- `com.apple.security.hardened-process.enhanced-security-version-string` → `2`
- `com.apple.security.hardened-process.hardened-heap` → `true`
- `com.apple.security.hardened-process.platform-restrictions-string` → `2`
- `com.apple.security.hardened-process.dyld-ro` → `true`
- `com.apple.security.hardened-process.checked-allocations` → `true` (Hardware Memory Tagging)
- `com.apple.security.hardened-process.checked-allocations.enable-pure-data` → `true`
- `com.apple.security.hardened-process.checked-allocations.no-tagged-receive` → `true`

Validation: enable Hardware Memory Tagging in Scheme → Run → Diagnostics and run the suite on supported hardware; pass criteria live in [TESTING.md](TESTING.md) §6.

| Device | MIE behavior |
|--------|-------------|
| A19/A19 Pro-or-newer (e.g. iPhone 17, iPhone Air) | Full hardware memory tagging |
| Older devices | Software-only typed allocator; no hardware tagging |

The capability is additive — unsupported devices run normally.

## 9. Known Limitations

**Passphrase `String` cannot be reliably zeroized.** Affects flows that originate in Swift `String`: key import/export passphrases and password-message (SKESK) encrypt/decrypt. It does **not** affect routine recipient-key decryption or signing, which use SE-unwrapped `Data` that is zeroized. `SecureField` binds to `String`, and UniFFI copies `String` across the boundary, so the Swift-side copy's lifetime is up to ARC — an accepted platform-wide limitation.

Shipped mitigations: the passphrase `String` lives only for the duration of the call and is never persisted; the Rust copy is zeroized by the `zeroize` crate; password-message APIs convert the Swift `String` into a Sequoia `Password` at the FFI boundary so the Rust-side representation is encrypted in memory; ASLR/sandboxing/MIE raise the bar for memory scanning.

## 10. AI Coding Red Lines

The following files and functions are security-critical. Coding agents may edit them directly, but every security-sensitive edit must be **explicitly called out — file, what changed, and why — in the task summary and PR description**, and requires human review before merge (see [WORKFLOW.md](WORKFLOW.md)); cover it with tests that meaningfully verify the change (see the testing guidance at the end of this section). Never merge such a change autonomously.

### Absolute Coding Invariants

These hold for every change, independent of which file is touched:

- **Secure random only.** Use `SecRandomCopyBytes` or CryptoKit (Swift) and the `getrandom` crate (Rust) for all security-relevant randomness. Never `arc4random` or `Int.random`.
- **No secret logging — not even in DEBUG.** Never `print()`, `os_log()`, or `NSLog()` key material, passphrases, or decrypted content, including in DEBUG builds.
- **Zero network, but local IPC is allowed.** The custom `cypherair://` URL scheme is local inter-process communication, not network access, and does not violate the zero-network rule.

### Files Requiring Human Review

| File | Reason |
|------|--------|
| `Sources/Security/SecureEnclaveManager.swift` | SE wrapping/unwrapping logic. Error = keys lost or insecure. |
| `Sources/Security/PrivateKeyEnvelope.swift` | `CAPKEV1` envelope (ephemeral-static ECDH, HKDF/AAD binding, contract validation). Error = keys lost, tamper accepted, or domain separation broken. |
| `Sources/Security/KeyBundleStore.swift` | Envelope persistence, pending/permanent promotion, interrupted-rewrap state. Error = key material lost or recovery fails open. |
| `Sources/Security/SecureEnclaveCustody*` | Custody handle lifecycle, access-control policy, role/public-key binding, sanitized failure mapping. |
| `Sources/Security/SecureEnclaveComposite*` | Split-custody component stores and in-enclave ML-DSA/ML-KEM operations for Device-Bound Post-Quantum. |
| `Sources/Security/KeychainManager.swift` | Access control flags. Wrong flags = wrong auth behavior. |
| `Sources/Security/AuthenticationManager.swift` | Mode switching re-wrap. Error = keys permanently lost. |
| `Sources/Security/ProtectedData/` | Root-secret authorization, SE device-binding envelope, domain master-key wrapping, reset semantics. Error = protected app data lost or opened under the wrong gate. |
| `Sources/Security/MemoryZeroingUtility.swift` | Removing a zeroize call = key material leaks. |
| `Sources/Extensions/Data+Zeroing.swift` | Contains the `@_optimize(none)` zeroing barrier. Weakening = compiler may eliminate all memory zeroing app-wide. |
| `Sources/Services/DecryptionService.swift` | Phase 1/Phase 2 auth boundary. Skipping Phase 2 auth = biometric bypass. |
| `Sources/Services/QRService.swift` | Parses untrusted external input (`cypherair://` URLs). |
| `pgp-mobile/src/decrypt.rs` | AEAD hard-fail enforcement. Weakening = plaintext leaks. |
| `pgp-mobile/src/streaming.rs` | Streaming encrypt/decrypt with buffer zeroing and the `.tmp`-then-rename output contract. |
| `pgp-mobile/src/composite_kem.rs` + `external_composite_*.rs` | Vendored RFC 9980 KEM combiner and composite seams. Error = wrong KEK derivation or split-custody boundary break. |
| `pgp-mobile/src/error.rs` | `PgpError` enum. Must stay 1:1 with Swift. |
| `Sources/Services/DiskSpaceChecker.swift` | Disk-space threshold. Wrong threshold = Jetsam termination during file operations. |
| `CypherAir.entitlements` / `CypherAirMacOS.entitlements` | MIE / Enhanced Security entitlements. |
| `CypherAir.xcodeproj/project.pbxproj` | Build settings (`ENABLE_ENHANCED_SECURITY`), script phases, target membership. |
| `CypherAir-Info.plist` | Only `NSFaceIDUsageDescription` permitted. No other usage descriptions. |

### Functions Requiring Human Review

- Any function that calls `SecAccessControlCreateWithFlags`
- Any function that calls `SecKeyCreateRandomKey`, `SecItemCopyMatching`, or `SecItemDelete` for `kSecClassKey`
- Any function that calls `SecureEnclave.P256.KeyAgreement.PrivateKey()` or the SecureEnclave ML-DSA/ML-KEM constructors
- Any function that calls `AES.GCM.seal()` or `AES.GCM.open()` on key material
- Any function that calls `HKDF<SHA256>.deriveKey()`
- Any function that writes to or deletes from Keychain
- The `os_proc_available_memory()` guard in Argon2id handling
- Any Rust function marked `pub` in `pgp-mobile/src/lib.rs`
- URL parsing logic in `QRService` that handles `cypherair://` scheme input
- Profile/CipherSuite selection in key generation

### Testing for Security Changes

Cover security-critical changes with tests that meaningfully verify what changed — using judgment about what actually adds confidence, not a fixed checklist. Depending on the change, the security value often lives in:

- the failure modes that matter (wrong key, wrong passphrase, tampered data, unavailable biometrics);
- crypto round-trips (encrypt/decrypt, sign/verify, wrap/unwrap);
- memory hygiene for memory-sensitive changes (sensitive data zeroized after use).

Human review before merge is the backstop.
