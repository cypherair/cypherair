# Handover: Codex Audit Fixes

> Session: 2026-03-13
> Branch: `fix/build-scripts-and-gitignore`
> Status: All 10 issues + 1 additional finding implemented. Project builds (0 errors). Tests not yet run.

## What Was Done

A Codex security audit identified 10 issues + 1 additional finding. All have been confirmed and fixed.

### Fixes by Batch

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

### New Files Created

1. `Sources/App/Contacts/ImportConfirmView.swift` — Confirmation sheet for URL scheme key import
2. `Sources/Extensions/KeyProfile+Codable.swift` — Codable conformance for UniFFI KeyProfile enum

### Documentation Updated

- `docs/ARCHITECTURE.md` — Added `metadata.<fingerprint>` to Storage Layout, added metadata naming convention note
- `docs/SECURITY.md` — Updated Key Lifecycle diagram to mention metadata storage
- `docs/TDD.md` — Updated Section 3.5 Keychain Layout to include metadata item with access control info

## Known Issues / Remaining Work

### Tests Not Yet Run

The test suite (`RunAllTests` via Xcode MCP) was attempted twice but timed out / got stuck. Tests should be run manually:

```bash
# Swift unit + FFI tests (simulator)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=iOS Simulator,name=iPhone 17'

# Or in Xcode: Cmd+U
```

**Expected test targets:**
- `FFIIntegrationTests` — ~49 tests
- `DeviceSecurityTests` — ~59 tests (some require physical device)

### Potential Test Adjustments

The following changes may require test updates:
- `KeychainManageable` protocol now has a `listItems` method — `MockKeychain` already implements it, but existing tests that create `MockKeychain` instances should still work
- `PGPKeyIdentity` is now `Codable` — no breaking change
- `CypherAirError` has 2 new cases (`s2kError`, `internalError`) — existing `switch` statements may need updating if they don't have a `default` case

### PrivacyScreenModifier Concurrency Note

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
