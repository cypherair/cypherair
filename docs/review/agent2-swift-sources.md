## COMPREHENSIVE SWIFT SOURCE FILE ANALYSIS - CypherAir

I have completed a thorough read of all 60 Swift source files in the CypherAir project. Here is an exhaustive breakdown:

### **SUMMARY STATISTICS**
- **Total Swift files:** 60
- **Lines of code (approximate):** ~15,000
- **Major modules:** 6 (App, Services, Security, Models, Extensions, PgpMobile)

---

## **1. APP LAYER (Sources/App/)** 
### Purpose: SwiftUI presentation views, navigation, no business logic

**Key Files:**

| File | Type | Key Classes/Structs | Lines | Purpose |
|------|------|-------------------|-------|---------|
| `CypherAirApp.swift` | App | `CypherAirApp` | 270 | Entry point; initializes all services; handles URL scheme (`cypherair://`); manages app lifecycle and crash recovery |
| `AppRoute.swift` | Enum | `AppRoute` | 30 | Type-safe navigation routes for NavigationStack |
| `ContentView.swift` | View | `ContentView` | 120 | Root TabView with 8 tabs (Home, Keys, Contacts, Settings, Tools) |
| `HomeView.swift` | View | `HomeView` | 210 | Home screen with default key info; quick-action grid for encrypt/decrypt/sign/verify |
| **Onboarding/** | | | | |
| `OnboardingView.swift` | View | `OnboardingView` | ~100 | 3-page onboarding tutorial (if not completed) |
| `TutorialView.swift` | View | `TutorialView` | ~100 | Reusable tutorial page component |
| **Keys/** | | | | |
| `MyKeysView.swift` | View | `MyKeysView` | ~150 | Lists all user's keys; default selection; backup status badges |
| `KeyGenerationView.swift` | View | `KeyGenerationView` | ~200 | Profile selection, name/email/expiry input, key generation trigger |
| `KeyDetailView.swift` | View | `KeyDetailView` | ~250 | Shows full fingerprint, algorithms, expiry, backup/revocation export |
| `BackupKeyView.swift` | View | `BackupKeyView` | ~200 | Passphrase entry; S2K type (Iterated+Salted vs Argon2id); file export |
| `ImportKeyView.swift` | View | `ImportKeyView` | ~180 | Text paste; file picker; passphrase entry for restore |
| `PostGenerationPromptView.swift` | View | `PostGenerationPromptView` | ~80 | Post-generation prompt to back up and share public key |
| **Contacts/** | | | | |
| `ContactsView.swift` | View | `ContactsView` | ~180 | Lists all imported contacts (public keys); search; add/delete actions |
| `ContactDetailView.swift` | View | `ContactDetailView` | ~150 | Shows contact's fingerprint, algorithms, revocation/expiry status |
| `AddContactView.swift` | View | `AddContactView` | ~120 | Routes to QR photo import, file picker, paste methods |
| `QRDisplayView.swift` | View | `QRDisplayView` | ~180 | Generates and displays QR code for public key; copy/share actions |
| `QRPhotoImportView.swift` | View | `QRPhotoImportView` | ~120 | PHPicker + CIDetector to decode QR from photo library |
| `ImportConfirmView.swift` | View | `ImportConfirmView` | ~180 | Shows parsed key info (name, email, fingerprint, profile, algorithms) before confirming add |
| **Encrypt/Decrypt/Sign/Verify/** | | | | |
| `EncryptView.swift` | View | `EncryptView` | ~250 | Text input; recipient selection (contacts); encrypt-to-self toggle; signing key selection |
| `DecryptView.swift` | View | `DecryptView` | ~250 | Paste/file picker; Phase 1 parsing; Phase 2 decrypt with auth; result display |
| `SignView.swift` | View | `SignView` | ~200 | Text input; signing key selection; cleartext signature generation |
| `VerifyView.swift` | View | `VerifyView` | ~200 | Paste message + signature; verification; signer status (valid/bad/unknown/expired) |
| **Settings/** | | | | |
| `SettingsView.swift` | View | `SettingsView` | ~250 | Auth mode toggle (Standard/High Security); grace period; encrypt-to-self; clipboard notice |
| `SelfTestView.swift` | View | `SelfTestView` | ~200 | One-tap self-test; progress bar; results grid; shareable report |
| `AboutView.swift` | View | `AboutView` | ~100 | App info, version, license link |
| `AppIconPickerView.swift` | View | `AppIconPickerView` | ~120 | Alternate app icon selection (iOS only) |
| **Common/** | | | | |
| `PrivacyScreenModifier.swift` | ViewModifier | `PrivacyScreenModifier` | 150 | Blur overlay on background; re-auth on resume; grace period logic |

---

## **2. SERVICES LAYER (Sources/Services/)**
### Purpose: Business logic orchestration, encryption/decryption, key management, file I/O

| File | Type | Key Classes | Lines | Purpose & API |
|------|------|------------|-------|---------------|
| `KeyManagementService.swift` | @Observable | `KeyManagementService` | ~800 | **Responsibilities:** Generate keys (SE-wrap + Keychain store); import/export keys (S2K protect); modify expiry; delete keys; default selection; metadata persistence. **Key methods:** `generateKey()`, `loadKeys()`, `unwrapPrivateKey()`, `importKey()`, `exportKey()`, `deleteKey()`, `setDefault()`, `modifyExpiry()`, `checkAndRecoverFromInterruptedModifyExpiry()` |
| `EncryptionService.swift` | @Observable | `EncryptionService` | ~500 | **Responsibilities:** Text/file encryption; recipient selection; encrypt-to-self logic; signature toggle; auto format selection (SEIPDv1 vs SEIPDv2 by recipient key version); streaming file I/O. **Key methods:** `encryptText()`, `encryptFile()`, `encryptFileStream()`, `validateRecipients()` |
| `DecryptionService.swift` | @Observable | `DecryptionService` | ~600 | **SECURITY-CRITICAL:** Two-phase decryption. **Phase 1 (no auth):** `parseRecipients()` — parse header, match keys. **Phase 2 (auth required):** `decrypt()`, `decryptFile()`, `decryptFileStream()` — trigger SE unwrap, decrypt, auto-verify signatures. **Key structs:** `Phase1Result`, `FilePhase1Result`. **Boundary:** Phase 2 must never bypass authentication. |
| `SigningService.swift` | @Observable | `SigningService` | ~200 | **Responsibilities:** Cleartext text signatures; detached file signatures; signature verification. **Key methods:** `signCleartext()`, `signDetached()`, `verify()` |
| `ContactService.swift` | @Observable | `ContactService` | ~300 | **Responsibilities:** Public key import/storage; contact enumeration; key update detection (same UID, different FP). **Storage:** `Documents/contacts/` as binary .gpg files. **Key methods:** `loadContacts()`, `addContact()`, `confirmKeyUpdate()`, `deleteContact()`. **Return types:** `AddContactResult` enum (added/duplicate/keyUpdateDetected). |
| `QRService.swift` | @Observable | `QRService` | ~150 | **SECURITY-CRITICAL:** Parses untrusted external input (`cypherair://` URLs). **Key methods:** `generateQRCode()` (CIQRCodeGenerator), `parseImportURL()` (validates scheme, version, length; delegates parsing to Rust engine) |
| `SelfTestService.swift` | @Observable | `SelfTestService` | ~400 | **Responsibilities:** One-tap diagnostic for both profiles (v4/v6); key gen → encrypt/decrypt → sign/verify → tamper test → QR round-trip. **Generates shareable report in `Documents/self-test/`.** **Key types:** `RunState` enum (idle/running/completed/failed), `TestResult` struct. |
| `FileProgressReporter.swift` | Protocol | `FileProgressReporter` | ~50 | Protocol for file operation progress updates. Used by streaming encrypt/decrypt. |
| `DiskSpaceChecker.swift` | Struct | `DiskSpaceChecker` | ~60 | Validates available disk space before file operations. Injected into EncryptionService. |

---

## **3. SECURITY LAYER (Sources/Security/)**
### Purpose: Secure Enclave wrapping, Keychain access, device authentication, memory management
### ⚠️ SECURITY-CRITICAL: All files in this layer require human review for changes

| File | Type | Key Classes/Protocols | Lines | Purpose & API |
|------|------|----------------------|-------|---------------|
| **Protocols (Abstraction for Testing)** | | | | |
| `SecureEnclaveManageable.swift` | Protocol | `SecureEnclaveManageable`, `SEKeyHandle` | 108 | **CRITICAL:** Protocol for SE operations. **Methods:** `generateWrappingKey()`, `wrap()`, `unwrap()`, `deleteKey()`, `reconstructKey()`. **Constants:** `SEConstants.hkdfInfo()` (domain-separated HKDF info string: `"CypherAir-SE-Wrap-v1:{fingerprint}"`). **Struct:** `WrappedKeyBundle` (seKeyData + salt + sealedBox). |
| `KeychainManageable.swift` | Protocol | `KeychainManageable`, `KeychainConstants` | 97 | **CRITICAL:** Protocol for Keychain I/O. **Methods:** `save()`, `load()`, `delete()`, `exists()`, `listItems()`. **Constants:** Service/account naming: `com.cypherair.v1.se-key.{fp}`, `com.cypherair.v1.salt.{fp}`, `com.cypherair.v1.sealed-key.{fp}`, `com.cypherair.v1.metadata.{fp}`. |
| `AuthenticationEvaluable.swift` | Protocol | `AuthenticationEvaluable`, `AuthenticationMode` | 107 | **CRITICAL:** Protocol for device auth (Face ID / Touch ID). **Enum:** `AuthenticationMode` (.standard = biometry + passcode fallback; .highSecurity = biometry only). **Method:** `evaluate()`, `canEvaluate()`, `createAccessControl()` (creates SecAccessControl flags). **Constants:** Auth mode preference keys. |
| `MemoryInfoProvidable.swift` | Protocol | `MemoryInfoProvidable` | 11 | Protocol for `os_proc_available_memory()` queries (Argon2id guard). |
| **Implementation (Production)** | | | | |
| `SecureEnclaveManager.swift` | Struct | `HardwareSecureEnclave`, `HardwareSEKey` | 162 | **CRITICAL:** Production SE manager using CryptoKit. **Key class:** `HardwareSEKey(key: SecureEnclave.P256.KeyAgreement.PrivateKey)`. **Wrapping scheme:** (1) Generate P-256 SE key with access control. (2) Self-ECDH inside SE. (3) HKDF(SHA-256, salt, info) → AES-256 key. (4) AES.GCM.seal() → WrappedKeyBundle. **Unwrapping:** Reverse + ECDH inside SE. |
| `KeychainManager.swift` | Struct | `SystemKeychain`, `KeychainError` | 149 | **CRITICAL:** Production Keychain using Security.framework. **Item class:** `kSecClassGenericPassword`. **Accessibility:** `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (no backup, no migration). **Error enum:** itemNotFound, duplicateItem, userCancelled, authenticationFailed, unhandledError. |
| `AuthenticationManager.swift` | @Observable | `AuthenticationManager`, `AuthenticationError` | 578 | **CRITICAL:** Device auth + mode switching. **Key responsibilities:** (1) `evaluate(mode:)` using LAContext (Standard or High Security). (2) `switchMode(to:)` — atomic re-wrap all SE keys with new access control flags (in-progress flag + pending items for crash recovery). (3) `checkAndRecoverFromInterruptedRewrap()` — crash recovery logic. **Error enum:** biometricsUnavailable, cancelled, failed, accessControlCreationFailed, modeSwitchFailed, noIdentities, backupRequired. |
| `MemoryZeroingUtility.swift` | Class | `SensitiveData` | 54 | **CRITICAL:** Auto-zeroing wrapper for sensitive data. **Methods:** `withUnsafeBytes()` (no copy), `.zeroize()`, `deinit` (auto-zero). **Usage:** Wrap passphrases, plaintext, key bytes. |
| `Argon2idMemoryGuard.swift` | Struct | `Argon2idMemoryGuard`, `SystemMemoryInfo` | 95 | **CRITICAL:** Guards against Jetsam during key import. **Method:** `validate(s2kInfo:)` — checks required memory ≤ 75% of available. Uses 64-bit arithmetic with overflow checking. **C function:** `@_silgen_name("os_proc_available_memory")` for `UInt` available bytes. |
| **Mocks (For Unit Tests)** | | | | |
| `Mocks/MockAuthenticator.swift` | Class | `MockAuthenticator` | 62 | Mock LAContext; controls `shouldSucceed`, `biometricsAvailable`. Tracks call count, mode, reason. |
| `Mocks/MockKeychain.swift` | Class | `MockKeychain` | 122 | In-memory storage ([String: Data]). Throws `MockKeychainError`. Tracks save/load/delete counts. `failOnSaveNumber` for testing partial failures. |
| `Mocks/MockSecureEnclave.swift` | Class | `MockSecureEnclave` | ~180 | Software P-256 + HKDF + AES-GCM (same algo, no hardware binding). **Note:** dataRepresentation differs from hardware (32 bytes vs ~100+ bytes). Allows testing wrap/unwrap logic without SE hardware. |
| `Mocks/MockMemoryInfo.swift` | Class | `MockMemoryInfo` | 28 | Simulates device memory. Default: 4 GB. Tracks call count. |
| `Mocks/MockDiskSpace.swift` | Class | `MockDiskSpace` | 35 | Simulates disk space. Default: 10 GB. Can throw errors. Tracks call count. |

---

## **4. MODELS LAYER (Sources/Models/)**
### Purpose: Data types, error mapping, UI-facing representations

| File | Type | Key Classes/Enums | Lines | Purpose |
|------|------|-----------------|-------|---------|
| `CypherAirError.swift` | Enum | `CypherAirError` | 174 | **App-level error type.** Cases: AEAD/crypto errors (aeadAuthenticationFailed, noMatchingKey, etc.), Security errors (authenticationFailed, keychainError), App errors (fileTooLarge, insufficientDiskSpace). **Key method:** `errorDescription` (user-facing localized messages per PRD Section 4.7). **Factory:** `from(_ error:fallback:)` converts PgpError → CypherAirError. |
| `PGPKeyIdentity.swift` | Struct | `PGPKeyIdentity` | 76 | **User's own key metadata.** Stores: fingerprint, keyVersion (4 or 6), profile, userId, algorithms, expiry, isRevoked, isExpired, isDefault, isBackedUp, publicKeyData, revocationCert. **Conforms to:** Identifiable, Hashable, Codable (for Keychain metadata). **Computed:** shortKeyId, formattedFingerprint, expiryDate. |
| `Contact.swift` | Struct | `Contact` | 78 | **Imported contact (public key).** Stores: fingerprint, keyVersion, profile, userId, algorithms, revocationCert, publicKeyData. **Computed:** displayName (extracted from UID), email, canEncryptTo. |
| `SignatureVerification.swift` | Struct | `SignatureVerification` | 71 | **UI-facing signature result.** Wraps UniFFI `SignatureStatus` with signer info. **Computed:** symbolName (SF Symbol), statusColor, statusDescription, isWarning. |
| `KeyProfile+App.swift` | Extension | `KeyProfile` | 46 | Extends UniFFI `KeyProfile` (universal/advanced) with: displayName, shortDescription, keyVersion (4/6), securityLevel. |
| `AppConfiguration.swift` | @Observable | `AppConfiguration` | 129 | **App-wide config persisted in UserDefaults.** Properties: authMode, gracePeriod, encryptToSelf, clipboardNotice, requireAuthOnLaunch, hasCompletedOnboarding. **Methods:** `recordAuthentication()`, `requestContentClear()`, `isGracePeriodExpired`. **Constants:** UserDefaults keys; grace period options (0/60/180/300 sec). |

---

## **5. EXTENSIONS LAYER (Sources/Extensions/)**
### Purpose: Reusable helpers and category methods

| File | Type | Extensions/Functions | Purpose |
|------|------|---------------------|---------|
| `Data+Zeroing.swift` | Extension | `Data.zeroize()`, `Array<UInt8>.zeroize()` | **CRITICAL:** Memory zeroing using `resetBytes()` (Data) and `memset` (Array). Uses `@_optimize(none)` barrier on `_opaqueZero()` to prevent compiler optimizing away zeroing. |
| `Data+TempFile.swift` | Extension | `Data.writeToShareTempFile()` | Writes data to `tmp/share/` with sanitized filename. Used by ShareLink for proper filenames on exported files. |
| `KeyProfile+Codable.swift` | Extension | `KeyProfile` Codable | Manually implements Codable for UniFFI `KeyProfile` enum (since generated code may not include Codable). |

---

## **6. PGPMOBILE / UNIFFI BINDINGS (Sources/PgpMobile/)**

| File | Type | Key Types | Lines | Purpose |
|------|------|-----------|-------|---------|
| `pgp_mobile.swift` | Generated | `PgpEngine`, `KeyProfile` enum | ~1200 | **AUTO-GENERATED by uniffi-bindgen** from `pgp-mobile` Rust crate. Do NOT edit. **Key types:** `PgpEngine` (Rust FFI wrapper), `KeyProfile` (.universal, .advanced), `KeyInfo` (parsed key metadata). **Key methods:** `generateKey()`, `encrypt()`, `decrypt()`, `sign()`, `verify()`, `parseKeyInfo()`, `detectProfile()`, `matchRecipients()`, `encodeQrUrl()`, `decodeQrUrl()`, `dearmor()`, `armor()`. **Error type:** `PgpError` enum (1:1 map with Rust). |

---

## **ARCHITECTURAL PATTERNS & DEPENDENCIES**

### **State Management**
- **@Observable classes** for all services: `KeyManagementService`, `EncryptionService`, `DecryptionService`, `SigningService`, `ContactService`, `QRService`, `SelfTestService`, `AppConfiguration`, `AuthenticationManager`
- **@Environment injection** in views for dependency injection
- No Combine, no `@StateObject`, no ObservableObject

### **Navigation**
- **NavigationStack + AppRoute enum** for type-safe routing
- **No deprecated NavigationView**

### **Protocol-Based Design**
- Security layer uses **protocols for testability:** `SecureEnclaveManageable`, `KeychainManageable`, `AuthenticationEvaluable`, `MemoryInfoProvidable`
- Mocks for unit testing without SE hardware

### **Error Handling**
- **Single app-level error type:** `CypherAirError` wrapping `PgpError` + security/app errors
- **Localized error messages** via String Catalog
- **No force-unwrap** in production code

### **Concurrency**
- **async/await** everywhere (no Combine)
- **@concurrent** functions for CPU-intensive work (encrypt/decrypt off main actor)
- Main actor implicit for views

### **Memory Safety**
- **Secure zeroization** of sensitive data via `Data.zeroize()`, `Array<UInt8>.zeroize()`, `SensitiveData` wrapper
- **No plaintext/keys in logs** per hard constraint #4
- **MIE (Memory Integrity Enforcement)** enabled via Enhanced Security capability

### **Security Boundaries**
- **Phase 1/Phase 2 decryption:** Phase 1 parses header without auth; Phase 2 requires SE unwrap with device auth
- **SE wrapping scheme:** P-256 self-ECDH + HKDF + AES-GCM for all key types (Ed25519/X25519/Ed448/X448)
- **Auth modes:** Standard (biometry + passcode) vs High Security (biometry only, blocks ops if unavailable)
- **Mode switching:** Atomic re-wrap with in-progress flag + crash recovery

### **Testing**
- Protocol-based mocks for SE, Keychain, Auth, Memory
- Self-test service for both profiles
- Pre-generated GnuPG interop test fixtures

---

## **KEY INVARIANTS & RED LINES**

| Invariant | Files Affected | Enforcement |
|-----------|----------------|-------------|
| **Zero network access** | All files | No URLSession, NWConnection, HTTP |
| **Only NSFaceIDUsageDescription** | Info.plist, AuthenticationEvaluable.swift | No camera, photo lib, contacts permissions |
| **AEAD hard-fail** | DecryptionService.swift, pgp_mobile.swift | No partial plaintext on auth failure |
| **No logs of keys/passphrases** | All files | Never print/NSLog key material |
| **Memory zeroing** | Data+Zeroing.swift, SigningService, DecryptionService | Zeroize all sensitive data immediately |
| **Secure random only** | HardwareSecureEnclave, MockSecureEnclave | SecRandomCopyBytes, getrandom (Rust) |
| **Profile-aware encryption** | EncryptionService, pgp_mobile.swift | v4→SEIPDv1, v6→SEIPDv2, mixed→SEIPDv1 |
| **Phase 2 auth boundary** | DecryptionService.swift | Never skip auth before SE unwrap |
| **Mode switch atomicity** | AuthenticationManager.swift | In-progress flag + pending items + crash recovery |
| **SE key immutability** | SecureEnclaveManager.swift | Wrap → store → zeroize (in that order) |
| **Argon2id guard** | Argon2idMemoryGuard.swift | Check required ≤ 75% available before derive |

---

## **DEPENDENCY GRAPH (SUMMARY)**

```
CypherAirApp (init)
├─ SecurityLayer
│  ├─ HardwareSecureEnclave (SE operations)
│  ├─ SystemKeychain (Keychain CRUD)
│  ├─ AuthenticationManager (device auth + mode switch)
│  └─ Argon2idMemoryGuard (memory validation)
├─ Services
│  ├─ KeyManagementService (uses SE + Keychain + auth)
│  ├─ EncryptionService (uses KeyMgmt, ContactService, PgpEngine)
│  ├─ DecryptionService (uses KeyMgmt, ContactService, PgpEngine, auth boundary)
│  ├─ SigningService (uses KeyMgmt, ContactService, PgpEngine)
│  ├─ ContactService (public key storage)
│  ├─ QRService (untrusted URL parsing)
│  └─ SelfTestService (diagnostic)
├─ Models
│  ├─ CypherAirError (error mapping)
│  ├─ PGPKeyIdentity (key metadata, Codable for Keychain)
│  ├─ Contact (public key)
│  ├─ AppConfiguration (UserDefaults)
│  └─ SignatureVerification (UI signature result)
├─ PgpEngine (UniFFI → Sequoia PGP)
│  └─ KeyProfile enum (universal/advanced)
└─ Views (inject all services via @Environment)
   ├─ HomeView
   ├─ MyKeysView, KeyGenerationView, KeyDetailView, BackupKeyView, ImportKeyView
   ├─ ContactsView, ContactDetailView, AddContactView, QRDisplayView, QRPhotoImportView, ImportConfirmView
   ├─ EncryptView, DecryptView, SignView, VerifyView
   ├─ SettingsView, SelfTestView, AboutView, AppIconPickerView
   ├─ OnboardingView, TutorialView
   └─ PrivacyScreenModifier (re-auth on resume)
```

---

This comprehensive analysis covers every file, every type, every key method, and every security boundary in the CypherAir codebase.
