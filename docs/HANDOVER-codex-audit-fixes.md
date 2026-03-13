# Handover: Codex Audit Fixes + MVP App Layer

> Session: 2026-03-13
> Branch: `fix/build-scripts-and-gitignore`
> PR: https://github.com/cypherair/Cypherair_poc_new/pull/39
> Status: All fixes implemented. Build passes. **108/108 tests pass.** Ready for review.

## What Was Done

### MVP App Layer (27 views, 7 services, 6 models)

Complete SwiftUI view hierarchy covering all PRD workflows:
- **Home/Navigation**: `HomeView`, `ContentView` (TabView), `AppRoute`
- **Keys**: `MyKeysView`, `KeyGenerationView`, `KeyDetailView`, `BackupKeyView`, `ImportKeyView`
- **Contacts**: `ContactsView`, `ContactDetailView`, `AddContactView`, `QRDisplayView`, `QRPhotoImportView`, `ImportConfirmView`
- **Encrypt/Decrypt**: `EncryptView`, `FileEncryptView`, `DecryptView`, `FileDecryptView`
- **Sign/Verify**: `SignView`, `VerifyView`
- **Settings**: `SettingsView`, `SelfTestView`, `AboutView`
- **Common**: `PrivacyScreenModifier`, `OnboardingView`
- **Services**: `EncryptionService`, `DecryptionService`, `SigningService`, `KeyManagementService`, `ContactService`, `QRService`, `SelfTestService`
- **Models**: `CypherAirError`, `Contact`, `AppConfiguration`, `PGPKeyIdentity`, `SignatureVerification`, `KeyProfile+App`

### Codex Audit Fixes (10 issues + 1 additional finding)

A Codex security audit identified 10 issues + 1 additional finding. All have been confirmed and fixed.

#### Batch 2: Memory Zeroing CoW Fixes (4 fixes)

| Issue | File | Fix |
|-------|------|-----|
| #10 generateKey | `KeyManagementService.swift` | Changed `let generated` to `var generated`, added `defer { generated.certData.resetBytes(...) }` |
| #4 importKey | `KeyManagementService.swift` | Changed `let secretKeyData` to `var secretKeyData`, added `defer` zeroing, moved `armorPublicKey` call before zeroing |
| #5 EncryptionService signingKey | `EncryptionService.swift` | Changed `if var key = signingKey` pattern to `signingKey!.resetBytes(...)` directly on the original `var` |
| exportKey (additional) | `KeyManagementService.swift` | Changed `let secretKey` to `var secretKey`, added `defer` zeroing |

**Root cause for all four:** Swift Copy-on-Write semantics — `var copy = data; copy.resetBytes(...)` creates a new buffer and only zeroes the copy, leaving original data in memory.

#### Batch 4: Low Priority (2 fixes)

| Issue | File | Fix |
|-------|------|-----|
| #6 QR comment | `QRService.swift` | Changed "Uses Vision framework" to "Uses CIDetector" (comment-only) |
| #9 PgpError semantic folding | `CypherAirError.swift` | Added `s2kError(reason:)` and `internalError(reason:)` cases + mappings (previously both mapped to `corruptData`) |

#### Batch 3: Functional/Security (3 fixes)

| Issue | File | Fix |
|-------|------|-----|
| #8 isRevoked/isExpired | `ContactService.swift` | Changed hardcoded `false` to `keyInfo.isRevoked` / `keyInfo.isExpired` |
| #3 URL import confirmation | `CypherAirApp.swift` + new `ImportConfirmView.swift` | Added `pendingImport` state + confirmation sheet before adding contacts via `cypherair://` URL |
| #7 Grace period | `PrivacyScreenModifier.swift` | Injected `AppConfiguration` + `AuthenticationManager`, checks grace period on resume, triggers Face ID if expired |

#### Batch 1: Key Enumeration (1 complex fix, multiple files)

| Issue | Files | Fix |
|-------|-------|-----|
| #1 + #2 Key enumeration + crash recovery | See below | Added Keychain metadata items + `loadKeys()` for cold-launch enumeration |

**Files changed for Batch 1:**
- `KeychainManageable.swift` — Added `listItems(servicePrefix:account:)` protocol method + `KeychainConstants.metadataService(fingerprint:)` + `metadataPrefix`
- `KeychainManager.swift` (SystemKeychain) — Implemented `listItems` via `SecItemCopyMatching` + `kSecMatchLimitAll` + `kSecReturnAttributes`
- `MockKeychain.swift` — Implemented `listItems` by filtering storage dictionary keys
- `PGPKeyIdentity.swift` — Added `Codable` conformance
- `KeyProfile+Codable.swift` (new) — Added `Codable` extension for UniFFI-generated `KeyProfile` enum
- `KeyManagementService.swift` — Added `loadKeys()`, `saveMetadata()`, `updateMetadata()`, updated `generateKey()`, `importKey()`, `exportKey()`, `deleteKey()`
- `CypherAirApp.swift` — Added `try? keyMgmt.loadKeys()` before crash recovery in `init()`

### Bug Fix: PrivacyScreenModifier Environment Crash

**Problem:** `PrivacyScreenModifier` uses `@Environment(AppConfiguration.self)` and `@Environment(AuthenticationManager.self)`, but `.privacyScreen()` was applied **after** `.environment()` calls in `CypherAirApp.body`. In SwiftUI, modifiers applied later wrap outermost — the modifier was outside the environment scope and couldn't find the injected values.

**Error:** `Fatal error: No Observable object of type AppConfiguration found. A View.environmentObject(_:) for AppConfiguration may be missing as an ancestor of this view.`

**Fix:** Moved `.privacyScreen()` before `.environment()` calls so it sits inside the environment chain:
```swift
// Before (broken): modifier is outermost, outside environment scope
ContentView()
    .environment(config)
    .environment(authManager)
    .privacyScreen()          // ← can't see config or authManager

// After (fixed): modifier is innermost, inside environment scope
ContentView()
    .privacyScreen()          // ← receives config and authManager from above
    .environment(config)
    .environment(authManager)
```

### New Files Created

1. `Sources/App/Contacts/ImportConfirmView.swift` — Confirmation sheet for URL scheme key import
2. `Sources/Extensions/KeyProfile+Codable.swift` — Codable conformance for UniFFI KeyProfile enum

### Documentation Updated

- `docs/ARCHITECTURE.md` — Added `metadata.<fingerprint>` to Storage Layout, added metadata naming convention note
- `docs/SECURITY.md` — Updated Key Lifecycle diagram to mention metadata storage
- `docs/TDD.md` — Updated Section 3.5 Keychain Layout to include metadata item with access control info

## Test Results

**108 tests: 108 passed, 0 failed, 0 skipped**

| Target | Tests | Status |
|--------|-------|--------|
| DeviceSecurityTests | 59 | All passed |
| FFIIntegrationTests | 49 | All passed |

Test coverage includes: SE wrap/unwrap (both profiles), auth mode switching, crash recovery, MIE validation, performance benchmarks, binary round-trip, Unicode preservation, all PgpError mappings, Argon2id memory guard, two-phase decrypt.

## Remaining Manual Verification

- [ ] URL import: scan QR → confirmation sheet appears → only adds contact on confirm
- [ ] Privacy screen: background app → wait > grace period → re-auth required on resume
- [ ] Memory zeroing: run under Instruments Allocations, verify key bytes zeroed after operations

## PrivacyScreenModifier Concurrency Note

The `PrivacyScreenModifier` was fixed for a Swift 6.2 data race issue. The pattern used:
```swift
// Capture @Environment values before Task closure
let auth = authManager
let mode = config.authMode
Task {
    // Use captured values inside Task
    try await auth.evaluate(...)
}
```
This is needed because `@Environment`-injected `@Observable` objects can't be sent across actor boundaries in a `Task` closure.

## Architecture Decision: Keychain Metadata

The key enumeration solution uses a **4th Keychain item per key** (`com.cypherair.v1.metadata.<fingerprint>`) instead of alternatives:
- **Why not enumerate sealed-key items?** Those require SE auth to read, defeating the purpose of zero-auth cold launch
- **Why not UserDefaults?** Keychain provides better data integrity guarantees and keeps key-related data colocated
- **What's stored?** `PGPKeyIdentity` JSON: fingerprint, userId, keyVersion, profile, isBackedUp, primaryAlgo, subkeyAlgo. No sensitive data
- **Access control:** `nil` (no SE auth needed), just `WhenUnlockedThisDeviceOnly`
