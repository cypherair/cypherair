## CypherAir Codebase - Comprehensive Architecture Report

I've conducted a thorough exploration of the CypherAir codebase. Here's a detailed analysis covering all major components:

---

### **PROJECT OVERVIEW**

**Purpose:** Offline OpenPGP encryption tool for iOS, iPadOS, and macOS. Fully offline (zero network), minimal permissions, dual encryption profiles.

**Architecture:** Three-layer bridge: Swift UI → Swift Services/Security → Rust (Sequoia PGP) via UniFFI

**Tech Stack:**
- Swift 6.2, SwiftUI (iOS 26 Liquid Glass)
- Sequoia PGP 2.2.0 (Rust)
- UniFFI 0.31 for FFI
- CryptoKit (SE wrapping), Security.framework (Keychain)
- Xcode 26, targets iOS 26.2+ / iPadOS 26.2+ / macOS 26.2+

---

### **FILE STRUCTURE & STATISTICS**

**Total Swift files:** 58 files
- App Layer: 27 view files + 1 app entry + 1 route enum
- Services: 9 files (Encryption, Decryption, Signing, KeyManagement, Contact, QR, SelfTest, DiskSpace, FileProgress)
- Security: 8 files (SE/Keychain/Auth managers + 5 mock implementations)
- Models: 6 files (Error, Key Identity, Config, Signature, Contact, Profile)
- Extensions: 3 files (Zeroing, TempFile, Codable)
- PgpMobile wrapper: 1 generated binding file
- Tests: 13 test files

**Rust crate (pgp-mobile):** 8 source files + build script
- `lib.rs` (200+ lines): Main PgpEngine with 30+ public methods
- `error.rs`: 30 typed PgpError variants
- `keys.rs` (200+ lines): Profile-aware key generation, info parsing, expiry modification
- `encrypt.rs` (150+ lines): Recipient collection, message pipeline setup
- `decrypt.rs` (150+ lines): Phase 1 recipient parsing, Phase 2 decryption, AEAD hard-fail
- `sign.rs`, `verify.rs`, `armor.rs`: Signing, verification, armor codec
- `streaming.rs`: File-based streaming I/O for large files
- Tests: 8 comprehensive test suites (profile A/B, cross-profile, GnuPG interop, streaming, security audit)

---

### **CORE ARCHITECTURE LAYERS**

#### **1. APP LAYER (`Sources/App/`)**

**Entry Point:** `CypherAirApp.swift` (270 lines)
- Initializes all shared dependencies (PgpEngine, Services, Security managers)
- Loads keys and contacts on launch (non-blocking)
- Crash recovery for interrupted operations (SE mode switch, key expiry modification)
- URL scheme handling for `cypherair://` import
- Privacy screen (background blur) + temp file cleanup

**Navigation:** `ContentView.swift` + `AppRoute.swift` + `HomeView.swift`
- TabView with 4 main tabs (Home, Keys, Contacts, Settings) + Tools section (hidden on iPhone)
- Type-safe routes using `NavigationStack`
- iOS 26 Liquid Glass design (auto-adopted by TabView)

**Key View Categories:**
- **Keys:** Generation (profile selection), detail, backup (Iterated+Salted/Argon2id), import, expiry modification
- **Contacts:** List, detail, add (QR/file/paste), key update detection
- **Encrypt:** Text/file toggle, recipient selection, signature toggle, encrypt-to-self, progress reporting
- **Decrypt:** Two-phase UI (Phase 1: parse recipients without auth; Phase 2: decrypt with biometric auth)
- **Sign/Verify:** Cleartext/detached signatures, graded results
- **Settings:** Auth mode, grace period, self-test, about, app icon picker
- **Onboarding:** 6-page tutorial + entry from Home/Settings

**Design Patterns:**
- `@Observable` services injected via `@Environment`
- No business logic in views (all delegated to services)
- `.task` for async operations
- `.sheet` / `.alert` for confirmations
- Localization via `String(localized:)` for all user-visible strings

---

#### **2. SERVICES LAYER (`Sources/Services/`)**

All services are `@Observable` classes injected into the environment.

| Service | Lines | Responsibilities |
|---------|-------|------------------|
| **KeyManagementService** | 350+ | Key generation (profile-aware, SE wrapping), import (passphrase unlock), export (S2K protection), expiry modification, default selection, crash recovery |
| **EncryptionService** | 300+ | Text/file encryption, streaming I/O (64KB buffers), disk space validation, recipient validation, encrypt-to-self, signing integration |
| **DecryptionService** | 350+ | Two-phase decryption (Phase 1: parse recipients no-auth; Phase 2: decrypt with biometric auth), streaming file decryption, signature verification |
| **SigningService** | 150+ | Cleartext text signatures, detached file signatures, verification with graded results |
| **ContactService** | 200+ | Public key CRUD, file storage (Documents/contacts/), duplicate detection, key update detection |
| **QRService** | 150+ | QR generation (CIQRCodeGenerator), decoding (PHPicker + CIDetector), URL scheme parsing (`cypherair://`), key inspection |
| **SelfTestService** | 200+ | One-tap diagnostic (both profiles), key gen → encrypt/decrypt → sign/verify → tamper test → QR round-trip |
| **DiskSpaceChecker** | 80 | Runtime disk space validation for file operations |
| **FileProgressReporter** | 100 | Progress tracking + cancellation for streaming operations |

**Key Design Principles:**
- Services call PgpEngine (Rust) for crypto operations
- Services use Security layer (SE wrapping, auth) for key access
- All private key material passed as `Data` (Vec<u8> across FFI)
- Memory zeroing after use (via `.zeroize()` extension)
- `@concurrent` on I/O-heavy methods for background execution
- Error mapping: `PgpError` → `CypherAirError` (user-facing messages)

---

#### **3. SECURITY LAYER (`Sources/Security/`)**

**CRITICAL FILES** (require human review per CLAUDE.md):

| File | Purpose | Key Design |
|------|---------|-----------|
| **SecureEnclaveManager** | P-256 key wrapping/unwrapping | Self-ECDH + HKDF(SHA-256) + AES-GCM seal. Wrapping scheme identical for Ed25519/X25519/Ed448/X448. Access control flags per auth mode. |
| **KeychainManager** | Keychain CRUD | kSecClassGenericPassword, WhenUnlockedThisDeviceOnly, no backups, device-bound (SoC UID) |
| **AuthenticationManager** | Biometric auth + mode switching | LAContext evaluation (Standard: passcode fallback; High Security: biometrics only). Mode switch: re-wrap all keys atomically. Crash recovery via UserDefaults flag. |
| **Argon2idMemoryGuard** | Memory validation (Profile B only) | 75% threshold prevents iOS Jetsam termination before Argon2id import |
| **MemoryZeroingUtility** | Secure memory clearing | `@_optimize(none)` barrier via indirect function call |

**Helper Protocols & Mocks:**
- `SecureEnclaveManageable` (protocol) → HardwareSecureEnclave (CryptoKit) + MockSecureEnclave (software P-256)
- `KeychainManageable` (protocol) → SystemKeychain (Security.framework) + MockKeychain (in-memory dict)
- `AuthenticationEvaluable` (protocol) → AuthenticationManager + MockAuthenticator
- `MemoryInfoProvidable` (protocol) → Real + Mock for memory checking

**SE Wrapping Flow (Security-Critical):**
```
Generate:
  1. P-256 key in SE with access control flags
  2. Self-ECDH (inside SE hardware)
  3. HKDF(salt=random, info="CypherAir-SE-Wrap-v1:"+fingerprint)
  4. AES-GCM seal(privateKey)
  5. Store 3 Keychain items + metadata
  6. Zeroize raw key bytes (only after storage confirmed)

Unwrap:
  1. Reconstruct SE key from Keychain (triggers Face ID/Touch ID)
  2. Re-ECDH + HKDF with stored salt
  3. AES-GCM open() → raw key bytes
  4. Perform PGP operation
  5. Zeroize immediately
```

**Auth Modes:**
- **Standard:** `[.privateKeyUsage, .biometryAny, .or, .devicePasscode]` → Face ID/Touch ID with passcode fallback
- **High Security:** `[.privateKeyUsage, .biometryAny]` → Biometrics only (blocks operations if unavailable)

**Keychain Layout (ARCHITECTURE.md §5):**
```
Per identity (fingerprint = lowercase hex):
  - com.cypherair.v1.se-key.<fp>          → SE key dataRepresentation
  - com.cypherair.v1.salt.<fp>            → HKDF salt
  - com.cypherair.v1.sealed-key.<fp>      → AES-GCM sealed private key
  - com.cypherair.v1.metadata.<fp>        → PGPKeyIdentity JSON (no SE auth needed)

During mode switch (temporary):
  - com.cypherair.v1.pending-se-key.<fp>  → deleted after successful switch
  - com.cypherair.v1.pending-salt.<fp>
  - com.cypherair.v1.pending-sealed-key.<fp>
```

---

#### **4. MODELS LAYER (`Sources/Models/`)**

| File | Purpose | Key Fields |
|------|---------|-----------|
| **CypherAirError** | App-level error enum (31 cases) | Maps PgpError variants 1:1. User-facing localized messages per PRD §4.7. Handles SE/Keychain/auth errors. |
| **PGPKeyIdentity** | Key metadata structure | Fingerprint, profile (A/B), userId, algorithms, expiry, revocation status, backup status, public key data |
| **AppConfiguration** | UserDefaults-backed state | Auth mode, grace period, encrypt-to-self toggle, clipboard notice, onboarding completion |
| **SignatureVerification** | Signature result wrapper | Status (valid/bad/unknownSigner/notSigned/expired), signer fingerprint, contact reference, color/icon for UI |
| **Contact** | Public contact key | Fingerprint, userId, profile, algorithms, expiry, canEncryptTo flag |
| **KeyProfile** | Enum (Universal/Advanced) | Codable for storage |

---

#### **5. RUST PGPENGINE (`pgp-mobile/`)**

**Cargo.toml Dependencies:**
- `sequoia-openpgp 2.2` with `crypto-openssl` backend (vendored) + `compression-deflate` (read-only)
- `uniffi 0.31` for Swift FFI
- `zeroize 1` for Rust-side memory zeroing
- `base64`, `thiserror` for utilities

**PgpEngine (`lib.rs`, 30+ public methods):**

```rust
pub struct PgpEngine;
```

Methods across domains:

**Key Generation:**
- `generate_key(name, email, expiry_seconds, profile)` → GeneratedKey
  - Profile A: CipherSuite::Cv25519 + Profile::RFC4880 → v4, Ed25519+X25519
  - Profile B: CipherSuite::Cv448 + Profile::RFC9580 → v6, Ed448+X448
  - Always default 2 years if expiry_seconds = None
  - Sets Features::empty().set_seipdv1() for Profile A (GnuPG compatibility)

**Key Info Parsing:**
- `parse_key_info(key_data)` → KeyInfo (fingerprint, version, userId, algo, expiry, profile, revocation)
- `get_key_version(cert_data)` → u8 (4 or 6)
- `detect_profile(cert_data)` → KeyProfile (inferred from key version)

**Key Modification:**
- `modify_expiry(cert_data, new_expiry_seconds)` → ModifyExpiryResult (new cert data + public key data)

**Encryption:**
- `encrypt(plaintext, recipients[], signing_key?, encrypt_to_self?)` → ASCII-armored ciphertext
  - Auto-selects format: all v4 → SEIPDv1; all v6 → SEIPDv2 (OCB); mixed → SEIPDv1
- `encrypt_binary(...)` → binary ciphertext (.gpg)

**Decryption (CRITICAL):**
- `parse_recipients(ciphertext)` → recipient Key IDs (hex strings) — Phase 1, no auth
- `match_recipients(ciphertext, local_certs)` → primary fingerprints of matching certs
- `decrypt(ciphertext, secret_keys[], verification_keys[])` → DecryptResult (plaintext + signature_status)
  - Handles SEIPDv1 (MDC) and SEIPDv2 (OCB/GCM)
  - **HARD-FAIL on AEAD/MDC failure** (no partial plaintext)

**Signing/Verification:**
- `sign_cleartext(text, signer_cert)` → ASCII-armored signed message
- `sign_detached(data, signer_cert)` → binary .sig
- `verify_cleartext(signed_msg, verification_keys[])` → VerifyResult (SignatureStatus + signer_fp)
- `verify_detached(data, signature, verification_keys[])` → VerifyResult

**QR Encoding/Decoding:**
- `encode_qr_url(publicKeyData)` → `cypherair://import/v1/<base64url>`
- `decode_qr_url(url: String)` → public key data

**Armor Codec:**
- `dearmor(armored)` → binary
- `armor(binary)` → ASCII-armored

**Streaming (File I/O):**
- `encrypt_file_streaming(input_path, recipients[], ..., progress_callback)` → output_path
- `decrypt_file_streaming(input_path, secret_keys[], ..., progress_callback)` → output_path

**Error Mapping (`error.rs`):**

30 typed errors, each maps to a Swift CypherAirError case:
- `AeadAuthenticationFailed` (hard-fail, no partial plaintext)
- `NoMatchingKey` (Phase 1 failure)
- `IntegrityCheckFailed` (MDC failure, SEIPDv1)
- `BadSignature`, `UnknownSigner`, `KeyExpired`
- `UnsupportedAlgorithm`, `CorruptData`, `WrongPassphrase`
- `Argon2idMemoryExceeded` (Profile B only)
- `OperationCancelled` (via progress callback)
- `FileIoError`

**Profile Handling:**

Profile A (Universal):
- v4 key format
- Ed25519 + X25519
- SEIPDv1 (MDC, not AEAD)
- Iterated+Salted S2K (mode 3) for export
- GnuPG compatible

Profile B (Advanced):
- v6 key format
- Ed448 + X448
- SEIPDv2 with AEAD (OCB primary, GCM secondary)
- Argon2id S2K (512 MB, p=4, ~3s) for export
- RFC 9580, NOT GnuPG compatible

**Encryption Format Auto-Selection (TDD.md §1.4):**
```
if all v4 → SEIPDv1
if all v6 → SEIPDv2 (OCB)
if mixed v4+v6 → SEIPDv1 (lowest common)
```

**Test Coverage (`pgp-mobile/tests/`):**
- `profile_a_tests.rs`: Key gen, encrypt/decrypt, sign/verify, round-trips (v4, Ed25519+X25519)
- `profile_b_tests.rs`: Same for v6, Ed448+X448, SEIPDv2
- `cross_profile_tests.rs`: A→B, B→A, format auto-selection verification
- `gnupg_interop_tests.rs`: Fixtures generated by `gpg`, tested against Sequoia
- `security_audit_tests.rs`: Tamper tests (1-bit flip), hard-fail on AEAD failure
- `streaming_tests.rs`: Large file encryption/decryption with progress
- `qr_url_tests.rs`: Encoding/decoding round-trips

---

### **DATA FLOW EXAMPLES**

#### **Encrypt (Profile-Aware)**

```
EncryptView (user inputs) 
  → EncryptionService.encryptText()
    → Collect recipients from ContactService (public keys)
    → Add self key if encryptToSelf=true
    → Call PgpEngine.encrypt(plaintext, recipients[], signingKey)
      (Rust side auto-selects SEIPDv1 vs SEIPDv2 by recipient key version)
    → Return ASCII-armored ciphertext
  → Copy to clipboard / Share
```

#### **Decrypt (Two-Phase)**

```
DecryptView (user pastes ciphertext)
  → Phase 1: DecryptionService.parseRecipients() 
    (NO authentication triggered)
    → Dearmor if needed
    → PgpEngine.matchRecipients() returns primary fingerprints
    → Match against local key identities
    → Show user "Addressed to [Key Name]"
  
  → Phase 2 (user confirms): DecryptionService.decrypt()
    (AUTHENTICATION TRIGGERED here)
    → AuthenticationManager.evaluate() [Face ID/Touch ID]
    → KeyManagementService.retrievePrivateKey(fingerprint)
      → SecureEnclaveManager.unwrap() [triggers SE auth again if not cached]
      → PgpEngine.decrypt(ciphertext, privateKey)
    → Return plaintext + SignatureVerification
    → Display plaintext (memory only, cleared on dismiss/grace period)
    → Zeroize private key bytes
```

#### **Key Generation**

```
KeyGenerationView (user enters name/email/expiry + selects profile)
  → KeyManagementService.generateKey(name, email, expiry, profile, authMode)
    → PgpEngine.generate_key() [Rust, returns unencrypted cert]
    → AuthenticationManager.createAccessControl(authMode)
    → SecureEnclaveManager.generateWrappingKey() [P-256, SE hardware]
    → SecureEnclaveManager.wrap() [self-ECDH, HKDF, AES-GCM seal]
    → KeychainManager.save() [3 items: SE key + salt + sealed box + metadata]
    → Zeroize raw cert bytes
    → Return PGPKeyIdentity
  → Prompt user to back up key + show QR for public key
```

#### **Mode Switch (High Security)**

```
SettingsView (user enables High Security)
  → AuthenticationManager.switchMode(.highSecurity)
    → Set rewrapInProgress flag
    → Evaluate auth (current mode) [Face ID/Touch ID once]
    → For each private key:
      → Unwrap (current SE key) [reuses auth context, no second prompt]
      → Generate new SE key (High Security flags)
      → Re-wrap (new SE key)
      → Store to temporary Keychain items
    → Verify all temporary items stored
    → Delete old Keychain items
    → Rename temporary items to permanent
    → Update mode preference
    → Clear rewrapInProgress flag
  
  → Crash recovery (on app launch): if rewrapInProgress flag set
    → Check for temporary items
    → If found: delete temp items, clear flag (original keys intact)
    → If not found: promote temp items to permanent, clear flag
```

---

### **SECURITY-CRITICAL FEATURES**

1. **Two-Phase Decryption Boundary (SECURITY.md §2)**
   - Phase 1 MUST NOT trigger SE unwrap
   - Phase 2 MUST trigger biometric auth before decryption
   - `DecryptionService.swift` (lines 3-10): Explicit comment on security boundary

2. **AEAD Hard-Fail (SECURITY.md §1, PRD §4.7)**
   - SEIPDv2 (OCB/GCM): fails on auth error → no plaintext returned
   - SEIPDv1 (MDC): fails on integrity check → no plaintext returned
   - Enforced in `decrypt.rs` (Rust side)

3. **Memory Zeroing (SECURITY.md §5)**
   - Swift: `Data+Zeroing.swift` → `resetBytes(in:)` across module boundary
   - Swift: `Array<UInt8>` → `@_optimize(none)` indirect call
   - Rust: `zeroize` crate on all sensitive buffers

4. **Secure Enclave Wrapping (SECURITY.md §3)**
   - P-256 self-ECDH + HKDF + AES-GCM
   - Identical scheme for all key algorithms
   - Device-bound (SoC UID)
   - Access control per auth mode (Standard vs High Security)

5. **MIE/Enhanced Security (SECURITY.md §6)**
   - `CypherAir.entitlements` contains hardened process flags
   - Hardware Memory Tagging on iPhone 17/iPhone Air (A19/A19 Pro)
   - Protects vendored OpenSSL from buffer overflows

6. **No Network Access (CLAUDE.md Hard Constraint #1)**
   - Zero URLSession, NWConnection, HTTP
   - Only local IPC via `cypherair://` URL scheme

7. **Minimal Permissions (CLAUDE.md Hard Constraint #2)**
   - Only `NSFaceIDUsageDescription` in Info.plist
   - QR: system Camera (no camera permission)
   - File I/O: system pickers (no photo library permission)

---

### **TEST COVERAGE**

**Swift Tests (`Tests/ServiceTests/` + `Tests/FFIIntegrationTests/`):**
- 13 test files covering Services, Models, FFI, Device Security
- Test patterns: round-trip (encrypt→decrypt), tamper (1-bit flip), cross-profile
- Fixtures: pre-generated GnuPG keys for Profile A interop
- Mocks: MockKeychain, MockSecureEnclave, MockAuthenticator, MockMemoryInfo

**Rust Tests (`pgp-mobile/tests/`):**
- 8 test suites: Profile A/B, cross-profile, GnuPG interop, streaming, security audit
- ~200 assertions across all tests
- Run via `cargo test`

**Test Plans:**
- `CypherAir-UnitTests.xctestplan`: Swift unit + FFI integration (simulator/CI)
- `CypherAir-DeviceTests.xctestplan`: SE, biometric, mode switch, crash recovery (device only)

---

### **BUILD & DEPENDENCY MANAGEMENT**

**Build Pipeline:**
```
1. Rust: cargo build --release --target aarch64-apple-ios/ios-sim/darwin
   (OpenSSL vendored, first build ~3-5 min)
2. Swift: uniffi-bindgen generate → pgp_mobile.swift bindings
3. Xcode: lipo (fat sim binary) → xcodebuild -create-xcframework
4. Xcode: Build and test via CypherAir scheme
```

**Cargo.toml Constraints:**
- `lto = false` (linker issues with vendored OpenSSL)
- `strip = "none"` (debugging)
- `codegen-units = 1` (binary size optimization)

**Key Versioning:**
- Sequoia PGP: 2.2.0
- UniFFI: 0.31
- Swift: 6.2 (SE-0466 main-actor implicit)
- MSRV: follows sequoia-openpgp requirements

---

### **CONVENTIONS & PATTERNS**

**Swift Conventions (CONVENTIONS.md):**
- API Design Guidelines, `guard let`, `async/await` (no Combine)
- `@Observable` for services, `NavigationStack` with typed routes
- One type per file, group by feature (not layer)
- Localization: String Catalog (`Localizable.xcstrings`)
- Accessibility: VoiceOver labels, 44pt touch targets, Dynamic Type

**Concurrency Model (Swift 6.2):**
- Main-actor implicit for views/view models
- `@concurrent` on I/O-heavy service methods
- Sendable crossing actor boundaries
- No `@Combine` in new code

**UI Patterns (Liquid Glass):**
- Standard components auto-adopt glass (TabView, NavigationStack, sheets)
- `.glassEffect()` only on custom floating controls
- `.tint()` for semantic meaning (blue=primary, red=destructive)
- No background override on glass elements

---

### **COMPLEXITY METRICS**

| Component | Complexity | Risk |
|-----------|-----------|------|
| SecureEnclaveManager | High | Security-critical wrapping scheme |
| KeyManagementService | Medium-High | 350+ lines, crash recovery, SE wrapping coordination |
| DecryptionService | Medium-High | Two-phase boundary enforcement, AEAD hard-fail |
| AuthenticationManager | Medium | Mode switching atomicity, crash recovery |
| PgpEngine (Rust) | High | 30+ public methods, Profile auto-selection, AEAD enforcement |
| EncryptionService | Medium | Recipient collection, streaming logic, signature toggle |
| QRService | Medium | Untrusted URL input parsing, validation |
| ContactService | Low-Medium | File I/O, key update detection |

---

### **RED FLAGS & CONSTRAINTS**

**Security Boundaries (SECURITY.md §7):**
- All edits to `Sources/Security/`, `DecryptionService`, `QRService`, `pgp-mobile/src/`, entitlements, Info.plist **REQUIRE HUMAN REVIEW**

**Hard Constraints (CLAUDE.md):**
1. Zero network access (code audit required)
2. Only `NSFaceIDUsageDescription` in Info.plist
3. AEAD hard-fail (no partial plaintext)
4. No plaintext/keys in logs
5. Memory zeroing on all sensitive data
6. SecRandomCopyBytes only for randomness
7. MIE enabled via Enhanced Security capability
8. Profile-correct message format (v4→SEIPDv1, v6→SEIPDv2, mixed→SEIPDv1)

**Known Limitations (SECURITY.md §7.1):**
- Swift `String` passphrases cannot be reliably zeroized (platform limitation)
  - Mitigated by short lifetime (import/export only), Rust-side zeroize, iOS protections

---

### **DOCUMENTATION RESOURCES**

- **`CLAUDE.md`**: Tech stack, build commands, hard constraints, security boundaries
- **`PRD.md`**: Product requirements, workflows, error messages, MVP scope
- **`ARCHITECTURE.md`**: Detailed module breakdown, data flows, storage layout, tightly-coupled files
- **`SECURITY.md`**: Full encryption scheme, key lifecycle, SE wrapping, auth modes, MIE validation, AI red lines
- **`TDD.md`**: Technical design, Sequoia integration, dual profiles, UniFFI architecture, Argon2id parameters
- **`TESTING.md`**: Test layers, patterns, cross-profile matrix, GnuPG fixtures, MIE validation
- **`CODE_REVIEW.md`**: PR checklist, security review criteria, testing requirements
- **`CONVENTIONS.md`**: Swift style, SwiftUI patterns, Liquid Glass, concurrency, file organization

---

### **SUMMARY**

CypherAir is a **security-first, layered architecture** with:
- **Thin UI layer** (SwiftUI, no business logic)
- **Rich services layer** (9 specialized services coordinating crypto + key management)
- **Hardened security layer** (SE wrapping, auth modes, memory zeroing, crash recovery)
- **Rust cryptographic engine** (Profile A/B dual keys, auto-format selection, hard-fail AEAD)

The codebase demonstrates **strong security practices** (two-phase decryption, memory zeroing, secure random, zero network, minimal permissions, MIE) while maintaining **clean separation of concerns** (protocols, mocks, testability) and **comprehensive documentation** (CLAUDE.md, PRD, ARCHITECTURE, SECURITY, TDD, TESTING).

**Total Codebase Size:** ~15,000 lines of Swift + ~8,000 lines of Rust + comprehensive test suite + 10 documentation files.
