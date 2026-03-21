# Service Layer Fix Plan

> **Status:** Approved plan, pending implementation
> **Scope:** 5 issues in the Services and Security layers
> **Constraint:** No code changes until plan is approved

## Overview

Code review identified 5 issues across the service layer. All have been verified against source code. This document captures the final fix plan after revision.

### Issue Summary

| # | Issue | Severity | Files Affected |
|---|-------|----------|----------------|
| 1 | KeyManagementService sync PGP operations blocking main thread | Medium | KMS + 4 views + tests |
| 2 | Error wrapping inconsistency in KMS and QRService | Low | KMS, QRService + tests |
| 3 | DecryptionService.parseRecipients discarding error details | Low | DecryptionService + tests |
| 4 | Argon2idMemoryGuard throwing PgpError instead of CypherAirError | Low | Argon2idMemoryGuard |
| 5 | Service constructor default parameters creating multi-instance risk | Low | All 7 services |

### Implementation Order

5 → 4 → 2 → 3 → 1

Rationale: Issue 1 is the largest change and benefits from Issues 2-4 being resolved first. Issues 2-5 are independent of each other.

---

## Issue 5: Remove Default PgpEngine Parameters

### Problem

All 7 services have `init(engine: PgpEngine = PgpEngine())` default parameters. While production code (`CypherAirApp.swift` lines 48-71) always passes a shared instance, any new code that calls `KeyManagementService()` without an explicit engine would silently create a separate `PgpEngine` instance.

### Affected Services

| Service | File | Line |
|---------|------|------|
| `KeyManagementService` | `Sources/Services/KeyManagementService.swift` | 23 |
| `ContactService` | `Sources/Services/ContactService.swift` | 27 |
| `EncryptionService` | `Sources/Services/EncryptionService.swift` | 19 |
| `DecryptionService` | `Sources/Services/DecryptionService.swift` | 40 |
| `SigningService` | `Sources/Services/SigningService.swift` | 12 |
| `QRService` | `Sources/Services/QRService.swift` | 15 |
| `SelfTestService` | `Sources/Services/SelfTestService.swift` | 36 |

### Fix

Remove `= PgpEngine()` from each service constructor's `engine` parameter:

```swift
// Before:
init(engine: PgpEngine = PgpEngine(), ...)

// After:
init(engine: PgpEngine, ...)
```

### Test Impact

`TestHelpers.swift` factory methods (lines 14, 35, 90) have their own `engine: PgpEngine = PgpEngine()` defaults. These are unaffected — they create a real engine and pass it explicitly to service constructors. No test changes needed.

### Production Impact

`CypherAirApp.swift` already passes the shared engine explicitly to all services. No production changes needed.

### Risk

Very low. This is a compile-time enforcement change. Any forgotten call site becomes a compiler error, which is the desired outcome.

---

## Issue 4: Argon2idMemoryGuard Error Type

### Problem

`Argon2idMemoryGuard.swift` (lines 44 and 73) throws `PgpError.Argon2idMemoryExceeded`, which is a Rust-defined error type. This is purely Swift-side logic that should throw a Swift app-layer error.

### Fix

Change two `throw` statements in `Sources/Security/Argon2idMemoryGuard.swift`:

```swift
// Line 44 — Before:
throw PgpError.Argon2idMemoryExceeded(requiredMb: requiredMb)
// Line 44 — After:
throw CypherAirError.argon2idMemoryExceeded(requiredMb: requiredMb)

// Line 73 — Before:
throw PgpError.Argon2idMemoryExceeded(requiredMb: requiredMb)
// Line 73 — After:
throw CypherAirError.argon2idMemoryExceeded(requiredMb: requiredMb)
```

Update the doc comment at line 25:

```swift
// Before:
/// - Throws: `PgpError.Argon2idMemoryExceeded` if memory requirement
// After:
/// - Throws: `CypherAirError.argon2idMemoryExceeded` if memory requirement
```

The target case `CypherAirError.argon2idMemoryExceeded(requiredMb:)` already exists at `CypherAirError.swift` line 20.

### Security Review Note

This file is in `Sources/Security/`. Per CLAUDE.md rules, changes require human review before editing.

### Test Impact

Tests asserting `PgpError.Argon2idMemoryExceeded` must be updated to assert `CypherAirError.argon2idMemoryExceeded`:

| Test File | Lines | Current Assertion | Action |
|-----------|-------|-------------------|--------|
| `FFIIntegrationTests.swift` | 831-841 | `guard let pgpError = error as? PgpError` → `case .Argon2idMemoryExceeded` | Change to `guard let error = error as? CypherAirError` → `case .argon2idMemoryExceeded` |
| `FFIIntegrationTests.swift` | 877-887 | Same pattern as above | Same change |
| `FFIIntegrationTests.swift` | 916-932 | `XCTAssertThrowsError` only (no type assertion) | **No change needed** |
| `ModelTests.swift` | 128-131 | `CypherAirError(pgpError: .Argon2idMemoryExceeded(...))` | **No change needed** — tests the error mapping itself, not Argon2idMemoryGuard |

### Risk

Very low. Straightforward type change with identical semantics.

---

## Issue 2: Error Wrapping Consistency

### Problem

`KeyManagementService` and `QRService` allow `PgpError` to propagate directly to callers, while `EncryptionService`, `DecryptionService`, and `SigningService` consistently wrap all errors in `CypherAirError`. Although view-layer call sites use `CypherAirError.from(error)` as a safety net, service-layer consistency is preferable.

### Reference Pattern

From `EncryptionService.swift` line 264-282:
```swift
do {
    result = try engine.encrypt(...)
} catch {
    throw CypherAirError.from(error) { .encryptionFailed(reason: $0) }
}
```

### Fix: KeyManagementService

Wrap engine calls in each method with `do/catch` using `CypherAirError.from()`:

| Method | Engine Calls That Escape | Fallback Case |
|--------|-------------------------|---------------|
| `generateKey()` | `engine.generateKey()`, `engine.parseKeyInfo()` | `.keyGenerationFailed(reason:)` |
| `importKey()` | `engine.parseS2kParams()`, `engine.importSecretKey()`, `engine.parseKeyInfo()`, `engine.detectProfile()`, `engine.armorPublicKey()` | `.invalidKeyData(reason:)` |
| `exportKey()` | `engine.exportSecretKey()` | `.s2kError(reason:)` |
| `modifyExpiry()` | `engine.modifyExpiry()` | `.keyGenerationFailed(reason:)` |
| `exportPublicKey()` | `engine.armorPublicKey()` | `.armorError(reason:)` |

**Note for `importKey()`:** The `Argon2idMemoryGuard` error (after Issue 4 fix) and `CypherAirError.duplicateKey` are already `CypherAirError`. `CypherAirError.from()` passes them through unchanged — no special handling needed.

Wrapping pattern — wrap engine calls in `do/catch` blocks:

**`generateKey()` example** — all engine calls are adjacent, so a single `do/catch` suffices:

```swift
func generateKey(...) throws -> PGPKeyIdentity {
    let generated: GeneratedKey
    let keyInfo: KeyInfo
    do {
        generated = try engine.generateKey(...)
        keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
    } catch {
        throw CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
    }
    // SE wrap + Keychain save + state update (these already throw CypherAirError)
    ...
}
```

**`importKey()` note** — engine calls are interleaved with non-engine operations (`memoryGuard.validate()`, duplicate check), so they cannot all be wrapped in a single `do/catch`. However, this is naturally resolved by Issue 1's refactor: the heavy engine calls (`importSecretKey`, `parseKeyInfo`, `detectProfile`, `armorPublicKey`) move into a `@concurrent` helper where they are grouped together and wrapped in a single `do/catch`. The fast `parseS2kParams()` call stays on the main actor and gets its own individual `do/catch` wrapping. See the "Issue 1+2 interaction" note in Issue 1 below.

### Fix: QRService

| Method | Engine Call | Fallback Case |
|--------|------------|---------------|
| `generateQRCode()` | `engine.encodeQrUrl()` | `.invalidKeyData(reason:)` |
| `parseImportURL()` | `engine.decodeQrUrl()` | `.invalidQRCode` |
| `inspectKeyInfo()` | `engine.parseKeyInfo()` | `.invalidKeyData(reason:)` |
| `detectKeyProfile()` | `engine.detectProfile()` | `.invalidKeyData(reason:)` |

Example for `parseImportURL()`:

```swift
// Line 76 — Before:
return try engine.decodeQrUrl(url: urlString)

// After:
do {
    return try engine.decodeQrUrl(url: urlString)
} catch {
    throw CypherAirError.from(error) { _ in .invalidQRCode }
}
```

### Test Impact

**QRServiceTests.swift:** Lines 168-234 currently use dual assertion pattern:
```swift
if let pgpError = error as? PgpError { ... }
else if let cypherError = error as? CypherAirError { ... }
```

After fix, update to expect only `CypherAirError`. The test comments documenting "QRService doesn't wrap it" (lines 165, 189, 214) should also be updated.

**KeyManagementServiceTests.swift:** Error assertion tests may need updating to check for `CypherAirError` instead of `PgpError`.

### Risk

Low. The `CypherAirError.from()` utility handles all conversion correctly. Existing view-layer safety nets become redundant (but harmless).

---

## Issue 3: parseRecipients Error Preservation

### Problem

In `DecryptionService.swift`, two `catch` blocks (line 81-82 and line 123-124) discard all error details from `engine.matchRecipients()`:

```swift
} catch {
    throw CypherAirError.noMatchingKey
}
```

This maps `PgpError.CorruptData` (malformed message) to `.noMatchingKey` ("not addressed to you"), which is a misleading user message.

### Fix

Replace the catch-all with differentiated error handling in **both** locations:

**`parseRecipients()` (line 81-83):**
```swift
// Before:
} catch {
    throw CypherAirError.noMatchingKey
}

// After:
} catch let error as PgpError {
    switch error {
    case .CorruptData(let reason):
        throw CypherAirError.corruptData(reason: reason)
    case .UnsupportedAlgorithm(let algo):
        throw CypherAirError.unsupportedAlgorithm(algo: algo)
    default:
        throw CypherAirError.noMatchingKey
    }
} catch {
    throw CypherAirError.noMatchingKey
}
```

**`parseRecipientsFromFile()` (line 123-124):** Same change.

### Error Mapping Rationale

| PgpError | CypherAirError | User Message |
|----------|---------------|--------------|
| `.CorruptData` | `.corruptData` | "Data damaged. Ask sender to resend." |
| `.UnsupportedAlgorithm` | `.unsupportedAlgorithm` | "Method not supported." |
| All others | `.noMatchingKey` | "Not addressed to your identities." |

### Security Note

This change does NOT affect the Phase 1/Phase 2 security boundary. Phase 1 still never reveals plaintext or triggers authentication. It only improves the error message shown to the user.

### Test Impact

Add new tests in `DecryptionServiceTests.swift`:
- `test_parseRecipients_corruptData_throwsCorruptDataError` — feed malformed (non-OpenPGP) data
- `test_parseRecipients_unsupportedAlgorithm_throwsUnsupportedError` — if feasible to construct

Existing `test_parseRecipients_noMatchingKey_throwsError` should still pass (it tests the "key deleted" case, which falls through to `.noMatchingKey`).

### Risk

Low. Improves error reporting without changing the happy path.

---

## Issue 1: KeyManagementService Async Refactor

### Problem

`KeyManagementService` is `@Observable` (implicitly `@MainActor`). Its methods `generateKey()`, `importKey()`, `exportKey()`, and `modifyExpiry()` call PGP engine operations synchronously on the main thread. Profile B key generation with Argon2id S2K can block the UI for ~3 seconds.

### Why `@concurrent` Cannot Be Applied Directly

Unlike `EncryptionService`/`DecryptionService`/`SigningService`, KMS methods **interleave** two types of operations:

1. **PGP engine calls** (CPU-intensive, should be off main thread)
2. **`@Observable` state mutations** (`keys.append()`, `keys[index].isBackedUp = true`, must stay on main actor)

Marking the entire method `@concurrent` would break `@Observable` state updates, which require main actor isolation.

*Note: SE wrapping and Keychain writes do NOT require the main thread — CryptoKit's SE operations are thread-safe, and biometric prompts are marshalled to the UI by the OS regardless of the calling thread. The existing `@concurrent` methods in EncryptionService/DecryptionService/SigningService already call `unwrapPrivateKey()` (which triggers Face ID) from background threads successfully.*

### Fix: Split Pattern

Each method becomes `async throws` (stays on the main actor) with only the engine call extracted to a `@concurrent` helper:

```swift
// Public method — stays on main actor for @Observable state mutations
func generateKey(...) async throws -> PGPKeyIdentity {
    // Step 1: PGP engine calls — off main thread via @concurrent helper
    // Helper returns CypherAirError (Issue 2 wrapping is inside the helper)
    var (generated, keyInfo) = try await generateKeyOffMainActor(
        name: name, email: email,
        expirySeconds: expirySeconds, profile: profile
    )
    defer { generated.certData.resetBytes(in: 0..<generated.certData.count) }

    // Step 2: SE wrap + Keychain (could run off main actor, but kept here for simplicity)
    let accessControl = try authMode.createAccessControl()
    let seHandle = try secureEnclave.generateWrappingKey(accessControl: accessControl)
    let bundle = try secureEnclave.wrap(
        privateKey: generated.certData,
        using: seHandle,
        fingerprint: keyInfo.fingerprint
    )
    try saveWrappedKeyBundle(bundle, fingerprint: keyInfo.fingerprint)

    // Step 3: State update — main actor
    let identity = PGPKeyIdentity(...)
    try saveMetadata(identity)
    keys.append(identity)
    return identity
}

// Private helper — runs on cooperative thread pool
// Error wrapping (Issue 2) lives here, so PgpError never escapes
@concurrent
private func generateKeyOffMainActor(
    name: String, email: String?,
    expirySeconds: UInt64?, profile: KeyProfile
) async throws -> (GeneratedKey, KeyInfo) {
    do {
        let generated = try engine.generateKey(
            name: name, email: email,
            expirySeconds: expirySeconds, profile: profile
        )
        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        return (generated, keyInfo)
    } catch {
        throw CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
    }
}
```

### Methods to Refactor

| Method | Engine Calls to Extract (`@concurrent`) | Operations Staying on Main Actor |
|--------|------------------------------------------|----------------------------------|
| `generateKey()` | `engine.generateKey()`, `engine.parseKeyInfo()` | `secureEnclave.wrap()`, `keychain.save()`, `keys.append()` |
| `importKey()` | `engine.importSecretKey()`, `engine.parseKeyInfo()`, `engine.detectProfile()`, `engine.armorPublicKey()` | `engine.parseS2kParams()` (fast, <1ms), `memoryGuard.validate()`, `secureEnclave.wrap()`, `keychain.save()`, `keys.append()` |
| `exportKey()` | `engine.exportSecretKey()` | `unwrapPrivateKey()` (SE unwrap, **must complete before** `exportSecretKey`), `keys[index].isBackedUp` |
| `modifyExpiry()` | `engine.modifyExpiry()` | `unwrapPrivateKey()` (SE unwrap, **must complete before** `modifyExpiry`), `secureEnclave.wrap()`, pending-item pattern, `keys[index] = updated` |

**Ordering constraints:**
- `exportKey()`: `unwrapPrivateKey()` (SE auth) → then `engine.exportSecretKey()` (off main actor). The engine call depends on the unwrapped key bytes.
- `modifyExpiry()`: `unwrapPrivateKey()` (SE auth) → then `engine.modifyExpiry()` (off main actor) → then SE re-wrap + pending-item pattern (main actor).
- `importKey()`: `engine.parseS2kParams()` stays on main actor because it only parses the S2K header (~tens of bytes, <1ms). The heavy operation is `engine.importSecretKey()` which performs Argon2id derivation (~3s for Profile B).

### Methods NOT Needing Async

These methods do not call PGP engine for CPU-intensive work:
- `loadKeys()` — Keychain metadata read only
- `deleteKey()` — Keychain delete only
- `setDefaultKey()` — Keychain metadata update only
- `exportPublicKey()` — calls `engine.armorPublicKey()` which is lightweight (not compute-intensive)
- `unwrapPrivateKey()` — SE unwrap only (called from other services' `@concurrent` methods, already off main actor in those contexts)
- `checkAndRecoverFromInterruptedModifyExpiry()` — Keychain-only recovery logic

### Call Site Updates

| Call Site | Current Pattern | After Fix |
|-----------|----------------|-----------|
| `KeyGenerationView.generate()` (line 128) | `Task { try keyManagement.generateKey(...) }` | `Task { try await keyManagement.generateKey(...) }` |
| `ImportKeyView.importKey()` (line 145) | `Task { try keyManagement.importKey(...) }` | `Task { try await keyManagement.importKey(...) }` |
| `BackupKeyView.exportBackup()` (line 97) | `Task { try keyManagement.exportKey(...) }` | `Task { try await keyManagement.exportKey(...) }` |
| `KeyDetailView.performModifyExpiry()` (line 379) | **Synchronous — no Task at all** | Wrap in `Task { try await ... }` |

**`KeyDetailView.performModifyExpiry()` is the most critical fix** — it currently calls `modifyExpiry()` synchronously without even a `Task {}` wrapper, fully blocking the main thread during the entire Rust engine call + SE rewrap operation.

### Test Impact

**`KeyManagementServiceTests.swift`:** 58 call sites need `await` added (25 `generateProfileAKey` + 14 `generateProfileBKey` + 6 `importKey` + 10 `exportKey` + 3 `modifyExpiry`). All test methods need `async throws`:

```swift
// Before:
func test_generateKey_profileA_storesKeychainItems() throws {
    let identity = try TestHelpers.generateProfileAKey(service: service)

// After:
func test_generateKey_profileA_storesKeychainItems() async throws {
    let identity = try await TestHelpers.generateProfileAKey(service: service)
```

**`TestHelpers.swift`:** Three helper methods need `async throws` signatures. `@discardableResult` must be preserved:

```swift
// Before:
@discardableResult
static func generateAndStoreKey(service:, profile:, ...) throws -> PGPKeyIdentity {
    try service.generateKey(...)
}

// After:
@discardableResult
static func generateAndStoreKey(service:, profile:, ...) async throws -> PGPKeyIdentity {
    try await service.generateKey(...)
}
```

Same for `generateProfileAKey()` (line 66) and `generateProfileBKey()` (line 76) — both have `@discardableResult`.

**`makeServiceStack()` (line 90) does NOT need async** — it only constructs service instances, does not call `generateKey()`.

**Other test files using these helpers** need `await` added at call sites:

| Test File | Calls Needing `await` | Already `async throws`? |
|-----------|----------------------|------------------------|
| `DecryptionServiceTests.swift` | 9 (5 ProfileA + 3 ProfileB + 1 AndStore) | Yes |
| `EncryptionServiceTests.swift` | 1 (AndStore) | Yes |
| `SigningServiceTests.swift` | 3 (AndStore) | Yes |
| `StreamingServiceTests.swift` | 1 (AndStore) | Yes |

**`ContactServiceTests.swift` is NOT affected** — its 12 `generateKey()` calls are direct `engine.generateKey()` calls (PgpEngine), not KMS method calls. All its tests use synchronous `throws`, not `async throws`.

### Issue 1+2 Interaction: Error Wrapping in `@concurrent` Helpers

When Issue 1 extracts engine calls into `@concurrent` private helpers, the Issue 2 `do/catch` + `CypherAirError.from()` wrapping should be placed **inside** those helpers rather than in the public method. This means each `@concurrent` helper directly throws `CypherAirError`, not `PgpError`:

```swift
// The @concurrent helper owns the error wrapping
@concurrent
private func generateKeyOffMainActor(
    name: String, email: String?,
    expirySeconds: UInt64?, profile: KeyProfile
) async throws -> (GeneratedKey, KeyInfo) {
    do {
        let generated = try engine.generateKey(
            name: name, email: email,
            expirySeconds: expirySeconds, profile: profile
        )
        let keyInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        return (generated, keyInfo)
    } catch {
        throw CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
    }
}

// The public method receives CypherAirError — no PgpError leaks
func generateKey(...) async throws -> PGPKeyIdentity {
    var (generated, keyInfo) = try await generateKeyOffMainActor(...)
    // SE wrap + state update (already throw CypherAirError)
    ...
}
```

**Implementation order consequence:** Issue 2 is implemented before Issue 1. When Issue 2 is applied, the `do/catch` blocks are added to the public methods (the only option at that point). When Issue 1 is subsequently applied, the `do/catch` blocks naturally migrate into the new `@concurrent` helpers as part of the extraction — the engine calls and their wrapping move together.

This applies to all KMS methods that get `@concurrent` helpers. For `importKey()`, the heavy engine calls (`importSecretKey`, `parseKeyInfo`, `detectProfile`, `armorPublicKey`) and their `do/catch` wrapping move together into the helper, while `parseS2kParams()` keeps its own `do/catch` on the main actor.

### Risk

Low-medium. The pattern is well-established in the other three services. The key consideration is ensuring `@Observable` state mutations remain on the main actor (they do, because the public method itself stays on the main actor — only the `@concurrent` helper runs off it).

---

## Verification Checklist

After all fixes are implemented:

- [ ] `xcodebuild build` succeeds with no new warnings
- [ ] `xcodebuild test -testPlan CypherAir-UnitTests` passes
- [ ] No `PgpError` escapes from any Service-layer method (except `unwrapPrivateKey` which is internal; `loadKeys`/`deleteKey` are Keychain-only and never produce `PgpError`)
- [ ] No `PgpError` thrown from Swift-only code (Argon2idMemoryGuard)
- [ ] `FFIIntegrationTests` Argon2id assertions (lines 831-841, 877-887) updated and passing
- [ ] No service constructor allows accidental `PgpEngine()` default instantiation
- [ ] `KeyDetailView.performModifyExpiry` no longer blocks synchronously
- [ ] `parseRecipients` returns `.corruptData` for malformed input (not `.noMatchingKey`)
- [ ] All existing tests updated and passing
- [ ] New negative tests added for Issue 3

## Appendix: Files Modified Per Issue

### Issue 5
- `Sources/Services/KeyManagementService.swift`
- `Sources/Services/ContactService.swift`
- `Sources/Services/EncryptionService.swift`
- `Sources/Services/DecryptionService.swift`
- `Sources/Services/SigningService.swift`
- `Sources/Services/QRService.swift`
- `Sources/Services/SelfTestService.swift`

### Issue 4
- `Sources/Security/Argon2idMemoryGuard.swift` *(Security review required)*
- `Tests/FFIIntegrationTests/FFIIntegrationTests.swift` (lines 831-841, 877-887)

### Issue 2
- `Sources/Services/KeyManagementService.swift`
- `Sources/Services/QRService.swift`
- `Tests/ServiceTests/QRServiceTests.swift`
- `Tests/ServiceTests/KeyManagementServiceTests.swift`

### Issue 3
- `Sources/Services/DecryptionService.swift`
- `Tests/ServiceTests/DecryptionServiceTests.swift`

### Issue 1
- `Sources/Services/KeyManagementService.swift`
- `Sources/App/Keys/KeyGenerationView.swift`
- `Sources/App/Keys/ImportKeyView.swift`
- `Sources/App/Keys/BackupKeyView.swift`
- `Sources/App/Keys/KeyDetailView.swift`
- `Tests/ServiceTests/TestHelpers.swift` (3 helpers: `generateAndStoreKey`, `generateProfileAKey`, `generateProfileBKey`)
- `Tests/ServiceTests/KeyManagementServiceTests.swift` (58 call sites)
- `Tests/ServiceTests/DecryptionServiceTests.swift` (9 call sites)
- `Tests/ServiceTests/SigningServiceTests.swift` (3 call sites)
- `Tests/ServiceTests/EncryptionServiceTests.swift` (1 call site)
- `Tests/ServiceTests/StreamingServiceTests.swift` (1 call site)
- **NOT affected:** `Tests/ServiceTests/ContactServiceTests.swift` (uses `engine.generateKey()` directly, not KMS)
