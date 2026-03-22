# Test Coverage Gap Fix Plan

> **Version:** v3.2 (Revised after third review)
> **Date:** 2026-03-21
> **Status:** Pending approval
> **Scope:** 10 confirmed test gaps, 2 production code changes, ~16 new Swift tests, 1 Rust test

## 1. Verification Summary

All 17 originally reported test gap items were re-verified against actual source code. Seven items were removed: two already have adequate coverage, four are based on incorrect assumptions, and one has a fundamentally infeasible approach.

### Items Removed (Already Covered)

| Item | Original Claim | Evidence of Coverage |
|------|---------------|---------------------|
| **L1** | Cross-profile encryption A→B missing | Rust: `cross_profile_tests.rs:15-55` (A→B), `:59-97` (B→A). Swift: `EncryptionServiceTests.swift:335` (B→A), `:361` (mixed v4+v6). |
| **L10** | Profile B SE wrapping round-trip missing | `DeviceSecurityTests.swift:134` (57-byte Ed448 round-trip), `:410` (full Profile B decrypt with SE unwrap), `:1121` (MIE workflow). |

### Items Removed (Incorrect Premise or Infeasible)

| Item | Original Claim | Reason for Removal |
|------|---------------|-------------------|
| **L6** | RSA-4096 key rejection test needed | Sequoia + crypto-openssl natively supports RSA. The codebase has no RSA rejection logic — `collect_recipients()` uses `.supported()` which passes RSA keys. Users can already import and use RSA keys. Testing a non-existent rejection is meaningless. |
| **L8** | UnsupportedAlgorithm end-to-end test | `UnsupportedAlgorithm` maps from `UnsupportedAEADAlgorithm` and `UnsupportedSymmetricAlgorithm` only — extremely rare in practice and infeasible to trigger with realistic fixtures. `ModelTests:38-45` already covers the enum mapping. |
| **L2** | Cross-profile signing verification | Signature verification uses `allVerificationKeys()` (all contact public keys) passed to `engine.verifyCleartext()`. The verifier's own key profile is never involved — Sequoia matches the signer's public key regardless of version. Rust `cross_profile_tests.rs` already covers the underlying cross-version verification. |
| **M1-T4** | SelfTestService tamper detection sub-test | Redundant with dedicated tamper detection tests in `EncryptionServiceTests` and `FFIIntegrationTests`. Only tests that "the test runner itself detects tampering," not a new scenario. |
| **H2** | Memory zeroing source-code audit test | The proposed approach (reading source files at test runtime) is infeasible — iOS test bundles cannot access project source files. `FixtureLoader` loads pre-bundled fixtures, not source code. This check should be a CI lint script, not an XCTest. |

---

## 2. Production Code Changes (2 files)

These are the only non-test files that require modification.

### 2.1 MockSecureEnclave.swift — Auth Mode Simulation

**File:** `Sources/Security/Mocks/MockSecureEnclave.swift`

**Problem:** `reconstructKey(from:authenticationContext:)` at line 153 has comment "Mock ignores authenticationContext" and always succeeds. In production, `SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:authenticationContext:)` triggers hardware biometric auth, which fails when High Security mode is active and biometrics are unavailable. No test can currently simulate this failure path.

**Architectural context:** The auth flow is: `DecryptionService.decrypt()` → `KeyManagementService.unwrapPrivateKey()` (line 612) → `secureEnclave.reconstructKey(from:)` → SE hardware auth. Authentication is enforced at the SE level, NOT through `AuthenticationEvaluable`/`MockAuthenticator`.

**Change:** Add two opt-in properties, a `nextError` check, and an auth mode check in `reconstructKey()`.

**Note:** The other four methods in `MockSecureEnclave` (`generateWrappingKey`, `wrap`, `unwrap`, `deleteKey`) all have `nextError` guard logic, but `reconstructKey()` lacks it. This is an existing consistency bug. The change below fixes it alongside adding auth mode simulation.

```swift
// Add after line 33 (after nextError declaration):
/// Simulated authentication mode. When set, reconstructKey() will enforce
/// auth mode constraints (e.g., High Security + no biometrics → failure).
/// Default: nil (no auth simulation, backward-compatible with existing tests).
var simulatedAuthMode: AuthenticationMode?

/// Whether biometrics are available in the simulated environment.
/// Only checked when simulatedAuthMode is set.
var biometricsAvailable: Bool = true
```

```swift
// Replace reconstructKey() implementation (lines 153-161):
func reconstructKey(from data: Data, authenticationContext: LAContext?) throws -> any SEKeyHandle {
    if let error = nextError {
        nextError = nil
        throw error
    }
    // Simulate auth mode enforcement.
    // In production, the SE hardware rejects key reconstruction when:
    // - Access control requires .biometryAny (High Security mode)
    // - Biometric authentication is unavailable or fails
    if let mode = simulatedAuthMode, mode == .highSecurity, !biometricsAvailable {
        throw MockSEError.authenticationFailed
    }
    #if canImport(CryptoKit)
    let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: data)
    return MockSEKey(privateKey: privateKey)
    #else
    fatalError("CryptoKit is required for MockSecureEnclave.")
    #endif
}
```

**Impact:** Default values (`nil` / `true`) mean all existing tests are unaffected. Only tests that explicitly set `simulatedAuthMode = .highSecurity` and `biometricsAvailable = false` trigger the new behavior. `MockSEError.authenticationFailed` already exists (line 192).

### 2.2 KeyManagementService.swift — MemoryInfo Injection

**File:** `Sources/Services/KeyManagementService.swift`

**Problem:** Line 163 hardcodes `let memoryGuard = Argon2idMemoryGuard()` which internally uses `SystemMemoryInfo()`. Tests cannot inject `MockMemoryInfo` to simulate low-memory devices refusing Profile B key imports.

**Note:** `Argon2idMemoryGuard.init(memoryInfo:)` already supports injection — the gap is only that `KeyManagementService` doesn't pass it through.

**Change 1:** Add stored property and init parameter:

```swift
// Add after line 17 (after authenticator declaration):
private let memoryInfo: any MemoryInfoProvidable
```

```swift
// Modify init (lines 22-32) to accept memoryInfo with default:
init(
    engine: PgpEngine,
    secureEnclave: any SecureEnclaveManageable,
    keychain: any KeychainManageable,
    authenticator: any AuthenticationEvaluable,
    memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo()
) {
    self.engine = engine
    self.secureEnclave = secureEnclave
    self.keychain = keychain
    self.authenticator = authenticator
    self.memoryInfo = memoryInfo
}
```

**Change 2:** Use injected memoryInfo at line 163:

```swift
// Replace line 163:
let memoryGuard = Argon2idMemoryGuard(memoryInfo: memoryInfo)
```

**Impact:** Default parameter means zero changes to existing call sites (production `CypherAirApp.swift` and existing tests).

---

## 3. Test Infrastructure Changes (1 file)

### 3.1 TestHelpers.swift — MockMemoryInfo Support

**File:** `Tests/ServiceTests/TestHelpers.swift`

**Change:** Add optional `memoryInfo` parameter to `makeKeyManagement()` and `makeServiceStack()`:

```swift
static func makeKeyManagement(
    engine: PgpEngine = PgpEngine(),
    memoryInfo: (any MemoryInfoProvidable)? = nil
) -> (service: KeyManagementService, mockSE: MockSecureEnclave,
      mockKC: MockKeychain, mockAuth: MockAuthenticator) {
    let mockSE = MockSecureEnclave()
    let mockKC = MockKeychain()
    let mockAuth = MockAuthenticator()

    let service = KeyManagementService(
        engine: engine,
        secureEnclave: mockSE,
        keychain: mockKC,
        authenticator: mockAuth,
        memoryInfo: memoryInfo ?? SystemMemoryInfo()
    )

    return (service, mockSE, mockKC, mockAuth)
}
```

Corresponding change to `makeServiceStack()` to accept and forward the parameter.

---

## 4. New Test File (1 file)

### 4.1 SelfTestServiceTests.swift (M1)

**File:** `Tests/ServiceTests/SelfTestServiceTests.swift` (new)

**Gap:** No test file exists for `SelfTestService`. The service runs 11 self-tests (5 per profile + 1 QR) and is the only service without any unit tests.

**Tests (3):**

| Test | Description |
|------|-------------|
| `test_selfTest_profileA_allChecksPass` | Run self-test for Profile A, verify all 5 checks pass (keygen, encrypt/decrypt, sign/verify, tamper detection, export/import) |
| `test_selfTest_profileB_allChecksPass` | Run self-test for Profile B, verify all 5 checks pass |
| `test_selfTest_reportGeneration_containsAllSections` | Verify report text includes expected section headers and both profile results |

**Dependencies:** `SelfTestService` only depends on `PgpEngine` — no mocks needed.

---

## 5. New Tests in Existing Files (~12 tests)

### 5.1 H1: High Security Biometrics Blocking (3 tests, 3 files)

**Root cause:** `MockSecureEnclave.reconstructKey()` ignores auth context, making it impossible to test the security invariant that High Security mode blocks private-key operations when biometrics are unavailable.

**Prerequisite:** Production change 2.1 (MockSecureEnclave auth simulation).

#### DecryptionServiceTests.swift (+1)

```
test_decrypt_highSecurity_biometricsUnavailable_throwsAuthError
```
- Generate Profile A key via `TestHelpers`
- Encrypt a message to that key
- Set `mockSE.simulatedAuthMode = .highSecurity`, `mockSE.biometricsAvailable = false`
- Attempt `decryptionService.decryptMessage(ciphertext:)` → expect `CypherAirError.authenticationFailed`

#### SigningServiceTests.swift (+1)

```
test_signCleartext_highSecurity_biometricsUnavailable_throwsAuthError
```
- Generate key, set mock SE to reject
- Attempt `signingService.signCleartext(...)` → expect error

#### KeyManagementServiceTests.swift (+1)

```
test_exportKey_highSecurity_biometricsUnavailable_throwsAuthError
```
- Generate key, export with passphrase (should work), then set mock SE to reject
- Attempt `service.exportKey(fingerprint:passphrase:)` → expect error

### 5.2 M2: Wrong Passphrase for Both Profiles (2 tests)

**File:** `KeyManagementServiceTests.swift`

**Gap:** All 6 existing import tests (lines 278, 305, 379, 403, 626, 656) use correct passphrases. No negative test for wrong passphrase.

```
test_importKey_profileA_wrongPassphrase_throwsError
```
- Generate Profile A key, export with passphrase "correct"
- Import with passphrase "wrong" → expect `.wrongPassphrase`

```
test_importKey_profileB_wrongPassphrase_throwsError
```
- Generate Profile B key, export with passphrase "correct"
- Import with passphrase "wrong" → expect `.wrongPassphrase` or `.s2kError`

### 5.3 M3: Argon2id Guard Service Integration (2 tests)

**File:** `KeyManagementServiceTests.swift`

**Prerequisite:** Production change 2.2 (MemoryInfo injection) + Infrastructure change 3.1 (TestHelpers).

```
test_importKey_profileB_lowMemory_throwsArgon2idExceeded
```
- Create `KeyManagementService` with `MockMemoryInfo(availableMemory: 500_000_000)` (500 MB)
- Profile B uses Argon2id with 512 MB; 512 MB > 75% of 500 MB (375 MB) → guard rejects
- Generate + export Profile B key (using a separate full-memory service), attempt import on low-memory service → expect `.argon2idMemoryExceeded`

```
test_importKey_profileA_lowMemory_succeeds
```
- Same low-memory setup, Profile A key (Iterated+Salted S2K) → import succeeds (guard is no-op for Profile A)

### 5.4 M4: Revocation Certificate Validity (2 tests)

**File:** `KeyManagementServiceTests.swift`

**Gap:** Current tests only check `XCTAssertFalse(identity.revocationCert.isEmpty)`. No structural or cryptographic validation. `FFIIntegrationTests.swift:518-536` has the negative case (garbage data → error); M4 is the positive complement.

**API:** Use `engine.parseRevocationCert(revData:certData:)` (`lib.rs:252-259`), which performs complete validation: parses the data as an OpenPGP signature packet, verifies the signature type is `KeyRevocation`, and cryptographically verifies the signature against the target key. This is strictly more correct than `parseKeyInfo()` (designed for keys, not signatures) or `dearmor()` (only checks ASCII armor format).

```
test_generateKey_profileA_revocationCertIsValidOpenPGP
```
- Generate Profile A key, extract `identity.revocationCert` and `identity.publicKeyData`
- Call `engine.parseRevocationCert(revData: identity.revocationCert, certData: identity.publicKeyData)`
- Verify it returns a success string containing the key's fingerprint

```
test_generateKey_profileB_revocationCertIsValidOpenPGP
```
- Same flow for Profile B (Ed448/v6 — different signature structure from Profile A's Ed25519/v4)

### 5.5 M5: ContactService Persistence (1 test)

**File:** `ContactServiceTests.swift`

**Gap:** No test verifies contacts survive a service restart (new instance, same directory).

```
test_contactPersistence_survivesServiceRestart
```
- Create `ContactService` with temp directory, add a contact
- Verify `contacts.count == 1`
- Create a NEW `ContactService` instance pointing to the same temp directory
- Call `loadContacts()` on the new instance
- Verify `contacts.count == 1` and fingerprint matches the original

### 5.6 L3: ZLIB Compression Decryption (1 test)

**File:** `GnuPGInteropTests.swift`

**Gap:** DEFLATE tested at line 197 (`test_c2a_9_decryptDeflateCompressedMessage_matchesPlaintext`). ZLIB fixture `gpg_encrypted_compressed_zlib.asc` exists in bundle but has no corresponding test.

**Prerequisite:** Verify that `gpg_encrypted_compressed_zlib.asc` is copied to the Swift test bundle via the Run Script build phase. If not, add it.

```
test_decryptZlibCompressedMessage_matchesPlaintext
```
- Load `gpg_encrypted_compressed_zlib.asc` via `FixtureLoader`
- Decrypt using GnuPG secret key fixture
- Verify plaintext matches expected content

### 5.7 L4: Signed+Compressed Verification (1 test)

**File:** `GnuPGInteropTests.swift`

**Gap:** Rust has `test_verify_gpg_signed_compressed` at `gnupg_interop_tests.rs:675`. No Swift counterpart. Fixture `gpg_signed_compressed.asc` exists in bundle.

**Prerequisite:** Same as L3 — verify fixture is in Swift test bundle.

```
test_verifySignedCompressedMessage_returnsValidSignature
```
- Load `gpg_signed_compressed.asc` via `FixtureLoader`
- Verify cleartext signature using GnuPG public key fixture
- Expect `SignatureStatus.Valid`

### 5.8 L5: QR Image Round-Trip (1 test)

**File:** `QRServiceTests.swift`

**Gap:** URL parsing round-trips exist (lines 26-78). QR image generation tested (line 272). But no test exercises CIQRCodeGenerator → CIDetector → URL parse full cycle.

```
test_qrCodeRoundTrip_generateThenDecode_recoversPublicKey
```
- Generate a key, get `publicKeyData`
- Call `qrService.generateQRCode(for: publicKeyData)` → get `CIImage`
- Call `qrService.decodeQRCodes(from: ciImage)` → get URL strings
- Call `qrService.parseImportURL(url)` on the decoded URL
- Verify the resulting public key's fingerprint matches the original

**Feasibility:** Both `CIFilter.qrCodeGenerator()` and `CIDetector(ofType: .QRCode)` work in iOS Simulator — they are CoreImage APIs, not camera-dependent.

**Implementation note:** `CIFilter.qrCodeGenerator()` outputs a low-resolution `CIImage` where each QR module is 1 pixel (typically ~25×25 to 33×33 pixels total). `CIDetector` may fail to detect QR codes at this resolution. If detection fails, apply `image.transformed(by: CGAffineTransform(scaleX: 10, y: 10))` to scale up to ~250×250 pixels before passing to `decodeQRCodes(from:)`.

### 5.9 L9: FileIoError + ModelTests Error Array Fix

**File 1:** `StreamingServiceTests.swift` (+1 test)

**Gap:** `FileIoError` is thrown in 11 locations in `pgp-mobile/src/streaming.rs` but has zero Swift test coverage.

```
test_encryptFileStreaming_invalidInputPath_throwsFileIoError
```
- Pass non-existent path `/nonexistent/path/file.txt` to streaming encryption
- Expect `PgpError.FileIoError` or `CypherAirError.fileIoError`

**File 2:** `ModelTests.swift` (modify existing test)

**Gap:** The comprehensive error description test array (line 175-204) is missing 4 `CypherAirError` cases.

```swift
// Add to existing error description test array:
.fileIoError(reason: "test io error"),
.operationCancelled,
.insufficientDiskSpace(fileSizeMB: 50, requiredMB: 100, availableMB: 30),
.duplicateKey,
```

This is not a new test method — it's adding 4 missing cases to the existing comprehensive test to match all cases in the `CypherAirError` enum.

---

## 6. Rust Layer Tests (1 test, tracked separately)

### 6.1 L7: Revoked Key Signature Verification

**File:** `pgp-mobile/tests/security_audit_tests.rs`

**Gap:** Encryption to revoked keys is tested (lines 336-374, 553-595). Signature verification with a revoked signer is not.

**Task:**
1. Generate key, create revocation cert, apply revocation
2. Verify a message signed by the (now-revoked) key
3. Expect appropriate status (e.g., `BadSignature` or signer-revoked indication)

---

## 7. Implementation Order

Recommended execution sequence to minimize conflicts:

1. **Production changes first** (2.1, 2.2) — MockSecureEnclave + KeyManagementService
2. **Test infrastructure** (3.1) — TestHelpers update
3. **HIGH priority tests** (H1) — Security-critical gap
4. **MODERATE priority tests** (M1–M5) — Feature coverage
5. **LOW priority Swift tests** (L3–L5, L9) — Completeness
6. **Rust layer test** (L7) — Tracked separately
7. **Build + full test run** to verify no regressions

---

## 8. File Change Matrix

| File | Action | Items Addressed |
|------|--------|----------------|
| `Sources/Security/Mocks/MockSecureEnclave.swift` | **Modify** (add 2 properties + auth check) | H1 |
| `Sources/Services/KeyManagementService.swift` | **Modify** (add memoryInfo param) | M3 |
| `Tests/ServiceTests/TestHelpers.swift` | **Modify** (forward memoryInfo) | M3 |
| `Tests/ServiceTests/SelfTestServiceTests.swift` | **New** (3 tests) | M1 |
| `Tests/ServiceTests/DecryptionServiceTests.swift` | **Modify** (+1 test) | H1 |
| `Tests/ServiceTests/SigningServiceTests.swift` | **Modify** (+1 test) | H1 |
| `Tests/ServiceTests/KeyManagementServiceTests.swift` | **Modify** (+6 tests) | H1, M2, M3, M4 |
| `Tests/ServiceTests/ContactServiceTests.swift` | **Modify** (+1 test) | M5 |
| `Tests/ServiceTests/GnuPGInteropTests.swift` | **Modify** (+2 tests) | L3, L4 |
| `Tests/ServiceTests/QRServiceTests.swift` | **Modify** (+1 test) | L5 |
| `Tests/ServiceTests/StreamingServiceTests.swift` | **Modify** (+1 test) | L9 |
| `Tests/ServiceTests/ModelTests.swift` | **Modify** (add 4 error cases) | L9 |
| `pgp-mobile/tests/security_audit_tests.rs` | **Modify** (+1 test) | L7 |

**Totals:** 2 production files, 1 test infrastructure file, 1 new test file, ~9 modified test files, ~16 new Swift tests, 1 Rust test.

---

## Appendix: Revision Log

### v3.2 (2026-03-21) — Third review corrections

| Item | Change |
|------|--------|
| M4 | Replaced incorrect API (`parseKeyInfo()`/`dearmor()`) with `parseRevocationCert(revData:certData:)`, which performs packet structure + cryptographic signature verification. Added Profile B test (+1 test, total M4 now 2 tests). |

### v3.1 (2026-03-21) — Second review corrections

| Item | Change |
|------|--------|
| 2.1 MockSecureEnclave | Explicitly noted that adding `nextError` check to `reconstructKey()` is fixing an existing consistency bug (other 4 methods have it, this one doesn't), not just adding auth simulation. |
| L5 QR round-trip | Added implementation note about `CIFilter.qrCodeGenerator()` low-resolution output (~1px per module) and the potential need for `CGAffineTransform(scaleX: 10, y: 10)` scaling before `CIDetector` can detect the QR code. |

### v3.0 (2026-03-21) — Post code-review revision

**Items removed (5 items, ~8 tests eliminated):**

| Removed | Tests Cut | Reason |
|---------|-----------|--------|
| L6 (RSA-4096 rejection) | 1 Rust | Sequoia + crypto-openssl natively supports RSA. No rejection logic exists. |
| L8 (UnsupportedAlgorithm e2e) | 1 Swift | Trigger condition is unrealistic. ModelTests enum mapping is sufficient. |
| L2 (Cross-profile signing) | 2 Swift | Verifier's profile is irrelevant to signature verification. Rust layer already covers. |
| M1-T4 (SelfTest tamper sub-test) | 1 Swift | Redundant with existing tamper tests in EncryptionServiceTests/FFIIntegrationTests. |
| H2 (Memory zeroing audit test) | 1 Swift | iOS test bundle cannot read source files at runtime. Should be CI lint script instead. |

**Items corrected:**

| Item | Change |
|------|--------|
| L9 ModelTests | Original plan listed 2 missing error cases; actual count is 4 (added `.insufficientDiskSpace` and `.duplicateKey`). |
| L3/L4 | Added prerequisite note to verify fixtures are in Swift test bundle. |
| M3 | Corrected memory threshold explanation. |
