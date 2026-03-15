# v1.1 Streaming File Processing — Implementation Plan (Revised v2)

## Overview

Replace in-memory file processing with file-path-based streaming. Rust handles file I/O internally via manual copy loops with `Zeroizing<Vec<u8>>` buffers (64 KB). Memory usage is constant regardless of file size. The fixed 100 MB file size limit is replaced by a runtime disk space check for streaming operations. Existing in-memory APIs remain for text operations.

## Four PRs, independently testable

```
PR 1: Rust streaming APIs + tests          (cargo test only, no Swift)
PR 2: UniFFI regen + Swift error/model      (build only, no behavior change)
PR 3: Swift service layer integration       (services use new APIs)
PR 4: UI layer — progress bar + cancel      (user-visible changes)
```

Each PR compiles and passes tests independently. See "PR Compilation Independence" section at the end.

---

## PR 1: Rust Layer — Streaming File APIs

### New file: `pgp-mobile/src/streaming.rs`

**Constants:**
- `STREAM_BUFFER_SIZE = 64 * 1024` (64 KB)

**Progress/cancellation trait (UniFFI foreign trait):**
```rust
#[uniffi::export(with_foreign)]
pub trait ProgressReporter: Send + Sync {
    fn on_progress(&self, bytes_processed: u64, total_bytes: u64) -> bool;
    // Returns false → cancel. total_bytes from file metadata.
}
```

**ProgressReader wrapper** — generic `Read` adapter that calls the callback:
```rust
struct ProgressReader<R: Read> {
    inner: R,
    bytes_read: u64,
    total_bytes: u64,
    progress: Option<Arc<dyn ProgressReporter>>,
}
// impl Read: after each read(), call on_progress(). If false → io::Error(Interrupted).
```

### Zeroing copy utilities

**Do not use `std::io::copy`.** It allocates an internal 8 KiB stack buffer that holds plaintext and is not zeroized. Instead, implement two manual copy functions using `Zeroizing<Vec<u8>>`:

```rust
/// Copy from reader to writer using a zeroing buffer.
/// The buffer is automatically zeroized on drop (including on panic/early return).
/// Used for ALL streaming paths where the data may contain plaintext.
fn zeroing_copy(
    reader: &mut impl Read,
    writer: &mut impl Write,
    buf_size: usize,
) -> io::Result<u64> {
    let mut buf = Zeroizing::new(vec![0u8; buf_size]);
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        writer.write_all(&buf[..n])?;
        total += n as u64;
    }
    // buf is zeroized on drop by Zeroizing
    Ok(total)
}

/// Copy with progress reporting and cancellation support.
fn zeroing_copy_with_progress(
    reader: &mut impl Read,
    writer: &mut impl Write,
    buf_size: usize,
    total_bytes: u64,
    progress: &Option<Arc<dyn ProgressReporter>>,
) -> Result<u64, PgpError> {
    let mut buf = Zeroizing::new(vec![0u8; buf_size]);
    let mut bytes_copied = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|e| PgpError::FileIoError {
            reason: e.to_string(),
        })?;
        if n == 0 { break; }
        writer.write_all(&buf[..n]).map_err(|e| PgpError::FileIoError {
            reason: e.to_string(),
        })?;
        bytes_copied += n as u64;
        if let Some(ref p) = progress {
            if !p.on_progress(bytes_copied, total_bytes) {
                return Err(PgpError::OperationCancelled);
            }
        }
    }
    // buf is zeroized on drop by Zeroizing
    Ok(bytes_copied)
}
```

**Why not `io::copy`:** `std::io::copy` allocates an internal 8 KiB stack buffer for the transfer. This buffer holds plaintext (during both encryption input and decryption output) and is not zeroized when the function returns. By using our own `Zeroizing<Vec<u8>>` buffer, we guarantee plaintext is zeroized on every exit path (normal return, error, panic). This is consistent with the existing `Zeroizing<Vec<u8>>` usage in `keys.rs` for protecting sensitive byte buffers.

**Rationale for not using `BufReader`/`BufWriter`:** Standard `BufReader` and `BufWriter` have internal buffers that are not zeroized on drop. Since our manual copy loop already buffers at 64 KB, adding `BufReader`/`BufWriter` would create *additional* uncontrolled buffers with no security benefit. The performance is equivalent: 64 KB syscalls are well amortized for file I/O on iOS.

**New functions:**

| Function | Input | Output | Notes |
|----------|-------|--------|-------|
| `encrypt_file(input_path, output_path, recipients, signing_key, encrypt_to_self, progress)` | File path | File path | `ProgressReader<File>` → Sequoia `Message::new(File)` pipeline via `zeroing_copy_with_progress` |
| `decrypt_file(input_path, output_path, secret_keys, verification_keys, progress)` | File path | `FileDecryptResult` + file | `DecryptorBuilder::from_reader(ProgressReader<File>)` → write to `output_path.tmp` via `zeroing_copy`, rename after full verification |
| `sign_detached_file(input_path, signer_cert, progress)` | File path | `Vec<u8>` (sig) | Signature is small, stays in memory |
| `verify_detached_file(data_path, signature, verification_keys, progress)` | File path | `VerifyResult` | Use `DetachedVerifier::verify_reader(ProgressReader<File>)` |
| `match_recipients_from_file(input_path, local_certs)` | File path | `Vec<String>` | Streaming `PacketParser::from_reader`, reads only PKESK header. Internally handles ASCII armor via `armor::Reader` wrapping. |

### Buffer zeroing analysis by data path

| Operation | Read side | Write side | Plaintext exposure |
|-----------|-----------|------------|-------------------|
| **encrypt_file** | `File` (plaintext input) → `zeroing_copy` buffer | Sequoia writer stack → `File` (ciphertext output) | Read buffer holds plaintext → **zeroized by `Zeroizing`** |
| **decrypt_file** | `Decryptor` (outputs plaintext) → `zeroing_copy` buffer | `File` (plaintext output, via `.tmp`) | Copy buffer holds plaintext → **zeroized by `Zeroizing`** |
| **sign_detached_file** | `File` (data input) → `zeroing_copy` buffer | Sequoia `Signer` (hash, no output file) | Read buffer holds data → **zeroized by `Zeroizing`** |
| **verify_detached_file** | `File` (data input) → Sequoia `verify_reader` | N/A (result in memory) | Sequoia manages internal buffers |

Note: Sequoia's `Decryptor` and `LiteralWriter` have their own internal buffers that hold plaintext transiently. These are managed by Sequoia and are outside our control. This is the same situation as the existing in-memory path — Sequoia necessarily holds plaintext during processing. Our `Zeroizing` buffers cover the data that passes through *our* code.

**AEAD safety for `decrypt_file` (critical):**
1. Decrypt to temporary file (`output_path.tmp`) via `zeroing_copy`
2. On ANY error (AEAD, MDC, cancel, I/O): call `secure_delete_file` on temp → return error
3. Only after complete successful read + `into_helper()` verification: rename `.tmp` → final path
4. No partial plaintext ever visible to caller

Note: APFS is copy-on-write, so zero-overwrite does not guarantee physical erasure. This matches the existing in-memory `zeroize` guarantee level (OS may cache pages). Acceptable tradeoff. Add a comment in `secure_delete_file` documenting this limitation for future auditors.

**`secure_delete_file` helper:** overwrite with zero chunks (using a stack-allocated buffer, not `Zeroizing` — we're writing zeros, not reading sensitive data) before `remove_file`.

**New `FileDecryptResult` record:**
```rust
#[derive(uniffi::Record)]
pub struct FileDecryptResult {
    pub signature_status: Option<SignatureStatus>,
    pub signer_fingerprint: Option<String>,
}
```

**Error handling constraint:** Following the existing design in `error.rs` (lines 90-94), streaming.rs must NOT use `?` to propagate `anyhow::Error` directly. All Sequoia errors must be mapped to specific `PgpError` variants via explicit `.map_err()` calls. This prevents silent misclassification of AEAD/MDC errors.

### Changes to existing Rust files

| File | Change | Details |
|------|--------|---------|
| `error.rs` | Add 2 variants | `OperationCancelled` and `FileIoError { reason: String }` |
| `encrypt.rs` | 3 functions → `pub(crate) fn` | `collect_recipients` (line 11), `build_recipients` (line 88), `setup_signer` (line 108). `write_and_finalize` stays private — streaming uses `zeroing_copy_with_progress` instead. |
| `decrypt.rs` | 2 items → `pub(crate)` | `DecryptHelper` struct (line 259, includes its `VerificationHelper` + `DecryptionHelper` trait impls) and `classify_decrypt_error` fn (line 356). `is_expired_error` already `pub(crate)`, no change. `map_openpgp_error` stays private (only called by `classify_decrypt_error`). |
| `sign.rs` | Extract new `pub(crate)` helper | `pub(crate) fn extract_signing_keypair(cert_data: &[u8], policy: &StandardPolicy) -> Result<openpgp::crypto::KeyPair, PgpError>` — extracts the repeated cert parse + key selection + into_keypair pattern from both `sign_cleartext` (lines 17-38) and `sign_detached` (lines 76-97). |
| `verify.rs` | 1 struct → `pub(crate)` | `VerifyHelper` (line 152, includes its `VerificationHelper` trait impl) — needed by `verify_detached_file` in streaming.rs. |
| `lib.rs` | Add module + 5 exports | `pub mod streaming;`, 5 new `#[uniffi::export]` methods on `PgpEngine`, export `ProgressReporter` trait. |

### Rust tests: `pgp-mobile/tests/streaming_tests.rs`

Both profiles unless noted:
1. `encrypt_file` + `decrypt_file` round-trip (Profile A + B)
2. AEAD tamper → temp file deleted, error returned (Profile B)
3. MDC tamper → temp file deleted, error returned (Profile A)
4. Cancellation mid-stream → output file cleaned up
5. `sign_detached_file` + `verify_detached_file` round-trip
6. Cross-profile: v6 sender → v4 recipient file encrypt → SEIPDv1
7. Missing input file → `FileIoError`
8. Progress callback receives correct `total_bytes`
9. `match_recipients_from_file` returns correct fingerprints (test with both binary and armored input)
10. Large file test (50 MB) round-trip
11. Encrypt-to-self file round-trip (both profiles), including mixed v4+v6 format selection with encrypt-to-self
12. Zeroing verification: after `decrypt_file` completes (success or error), read back the zeroing buffer memory region and confirm it contains zeros. Note: this tests the `Zeroizing<Vec<u8>>` drop behavior, not heap reuse — it verifies our code path, not OS memory management.

No new Cargo.toml dependencies needed (`tempfile` already in dev-deps).

---

## PR 2: UniFFI Bindings + Swift Error/Model Updates

### Regenerate bindings
```bash
# Build for all targets, generate Swift bindings, rebuild XCFramework
# (per CLAUDE.md Build Commands)
```

Regenerated `pgp_mobile.swift` will contain:
- `ProgressReporterProtocol` (Swift protocol from foreign trait)
- New methods on `PgpEngine`
- `FileDecryptResult` struct
- New `PgpError` cases: `.OperationCancelled`, `.FileIoError`

### Update `CypherAirError.swift`

Add two new PGP-layer cases mapping from the new `PgpError` variants:
```swift
case operationCancelled
case fileIoError(reason: String)
```

Add `init(pgpError:)` mapping for the two new cases (required for exhaustive switch):
```swift
case .OperationCancelled: self = .operationCancelled
case .FileIoError(let reason): self = .fileIoError(reason: reason)
```

Add new app-layer case (coexists with `fileTooLarge`):
```swift
case insufficientDiskSpace(fileSizeMB: Int, requiredMB: Int, availableMB: Int)
```

**IMPORTANT:** Do NOT remove `fileTooLarge(sizeMB:)`. It is still referenced by the in-memory `encryptFile` method (`EncryptionService.swift` line 81) and will continue to be used for that code path.

Error messages (localized, both en + zh-Hans):

`insufficientDiskSpace`:
> "Insufficient storage to process this file. Processing a [X] MB file requires approximately [Y] MB of temporary space, but only [Z] MB is available. Please free up storage and try again."

`operationCancelled`:
> "Operation cancelled."

`fileIoError`:
> "File operation failed: [reason]"

### String Catalog updates
- `error.insufficientDiskSpace` (en + zh-Hans)
- `error.operationCancelled` (en + zh-Hans)
- `error.fileIo` (en + zh-Hans)
- `error.fileTooLarge` retained (still used by in-memory path)

---

## PR 3: Swift Service Layer Integration

### New file: `Sources/Services/FileProgressReporter.swift`

```swift
@Observable
final class FileProgressReporter: ProgressReporterProtocol, @unchecked Sendable {
    // @unchecked Sendable safety justification:
    // - cancelFlag is protected by OSAllocatedUnfairLock (thread-safe)
    // - @Observable properties (progress, bytesProcessed, totalBytes) are only
    //   mutated via Task { @MainActor in }, ensuring main-actor isolation
    // - onProgress() is nonisolated and only reads cancelFlag + enqueues main-actor updates

    private(set) var progress: Double = 0
    private(set) var bytesProcessed: UInt64 = 0
    private(set) var totalBytes: UInt64 = 0
    private let cancelLock = OSAllocatedUnfairLock(initialState: false)

    nonisolated func onProgress(bytesProcessed: UInt64, totalBytes: UInt64) -> Bool {
        Task { @MainActor in
            self.bytesProcessed = bytesProcessed
            self.totalBytes = totalBytes
            if totalBytes > 0 { self.progress = Double(bytesProcessed) / Double(totalBytes) }
        }
        return !cancelLock.withLock { $0 }
    }

    func cancel() { cancelLock.withLock { $0 = true } }
}
```

Note: `nonisolated func onProgress` is called from a Rust background thread. `Task { @MainActor in }` enqueues UI updates to the main thread asynchronously. This is acceptable for progress display — exact real-time accuracy is not required.

### New file: `Sources/Services/DiskSpaceChecker.swift`

Follow the project's established protocol + default parameter pattern (identical to `Argon2idMemoryGuard` + `MemoryInfoProvidable` + `MockMemoryInfo`):

```swift
/// Protocol abstracting disk space queries for testability.
/// Follows the same pattern as MemoryInfoProvidable / Argon2idMemoryGuard.
protocol DiskSpaceProvidable: Sendable {
    func availableBytes() throws -> Int64
}

/// Production implementation: queries volumeAvailableCapacityForImportantUsageKey.
/// Uses "important usage" key because iOS clears purgeable caches for user-initiated operations.
struct SystemDiskSpace: DiskSpaceProvidable {
    func availableBytes() throws -> Int64 {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
        let values = try url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values.volumeAvailableCapacityForImportantUsage ?? 0
    }
}

/// Checks if sufficient disk space is available for a file streaming operation.
struct DiskSpaceChecker {
    private let diskSpace: any DiskSpaceProvidable

    init(diskSpace: any DiskSpaceProvidable = SystemDiskSpace()) {
        self.diskSpace = diskSpace
    }

    /// Requires fileSize * 2.2 available (input + output + temporary overhead).
    func check(fileSize: Int) throws {
        let available = try diskSpace.availableBytes()
        let required = Int64(Double(fileSize) * 2.2)
        guard available >= required else {
            throw CypherAirError.insufficientDiskSpace(
                fileSizeMB: fileSize / (1024 * 1024),
                requiredMB: Int(required / (1024 * 1024)),
                availableMB: Int(available / (1024 * 1024))
            )
        }
    }
}
```

### New file: `Sources/Security/Mocks/MockDiskSpace.swift`

```swift
final class MockDiskSpace: DiskSpaceProvidable, @unchecked Sendable {
    var availableBytes_: Int64 = 10 * 1024 * 1024 * 1024  // 10 GB default
    private(set) var callCount = 0

    func availableBytes() throws -> Int64 {
        callCount += 1
        return availableBytes_
    }
}
```

### `EncryptionService.swift` changes

Add `DiskSpaceChecker` as an injected dependency:
```swift
private let diskSpaceChecker: DiskSpaceChecker

init(engine: PgpEngine, keyManagement: KeyManagementService,
     contactService: ContactService,
     diskSpaceChecker: DiskSpaceChecker = DiskSpaceChecker()) {
    // ...
    self.diskSpaceChecker = diskSpaceChecker
}
```

Add streaming method:
```swift
@concurrent
func encryptFileStreaming(
    inputURL: URL, outputURL: URL,
    recipientFingerprints: [String], signWithFingerprint: String?,
    encryptToSelf: Bool, encryptToSelfFingerprint: String? = nil,
    progress: FileProgressReporter
) async throws { ... }
```

Key steps:
1. Get file size via `FileManager.attributesOfItem`
2. Call `diskSpaceChecker.check(fileSize:)`
3. Gather recipient keys, unwrap signing key (same pattern as current `encrypt` method, lines 109-142)
4. Call `engine.encryptFile(inputPath:outputPath:...progress:)`
5. Zeroize signing key in defer (same pattern as current lines 144-150)

The old `encryptFile(_ fileData: Data)` method retains its existing 100 MB hard limit and `fileTooLarge` error unchanged. That limit protects against in-memory `Data` exhausting RAM — a memory constraint, not a disk constraint. `DiskSpaceChecker` is only used by the new streaming method.

### `DecryptionService.swift` changes

Add file-based Phase 1 + Phase 2:
```swift
struct FilePhase1Result {
    let matchedFingerprints: [String]
    let matchedKey: PGPKeyIdentity?
    let inputPath: String  // Original file path for Phase 2 re-read
}

@concurrent
func parseRecipientsFromFile(fileURL: URL) async throws -> FilePhase1Result
// Calls engine.matchRecipientsFromFile(inputPath:localCerts:)
// Rust handles armor detection internally (wraps file reader with armor::Reader if needed).
// No auth needed. Returns matched key info + stores the input path for Phase 2.

@concurrent
func decryptFileStreaming(
    phase1: FilePhase1Result, outputURL: URL, progress: FileProgressReporter
) async throws -> SignatureVerification
// SE unwrap → engine.decryptFile(inputPath: phase1.inputPath, ...) → return signature info
```

Two-phase auth boundary preserved: Phase 1 = no auth (header parse only), Phase 2 = SE unwrap + biometric.

Note on security-scoped URL for two-phase decrypt: Phase 1 reads only PKESK headers (small, fast). Phase 2 re-reads the full file for streaming decryption. The view must call `startAccessingSecurityScopedResource()` separately for each phase (the URL remains valid between phases). This matches the existing pattern where security-scoped access is scoped to each operation. See PR 4 DecryptView changes for the view-side implementation.

### `SigningService.swift` changes

Add streaming methods:
```swift
@concurrent func signDetachedStreaming(fileURL: URL, signerFingerprint: String, progress: FileProgressReporter) async throws -> Data
@concurrent func verifyDetachedStreaming(fileURL: URL, signature: Data, progress: FileProgressReporter) async throws -> SignatureVerification
```

Both follow the same SE unwrap + defer zeroize pattern as existing `signDetached` (lines 60-79) and `verifyDetached` (lines 119-140).

### Temp file management

| Operation | Input | Output | Cleanup |
|-----------|-------|--------|---------|
| Encrypt | Original file (security-scoped URL) | `tmp/streaming/<UUID>_<name>.gpg` | On view dismiss |
| Decrypt Phase 1 | Ciphertext file (security-scoped URL) | N/A (Rust reads file directly, armor handled internally) | N/A |
| Decrypt Phase 2 | Ciphertext file (security-scoped URL, re-accessed) | `tmp/decrypted/<UUID>_<name>` | On view dismiss + app launch |
| Sign | Original file (security-scoped URL) | Signature `Data` in memory (small) | N/A |
| Verify | Original file (security-scoped URL) | `VerifyResult` in memory | N/A |

UUID prefix in temp file names prevents collisions if the user triggers operations on files with the same name. Follows the pattern established in `TestHelpers.swift` (line 37-38) where UUIDs provide isolation.

`CypherAirApp.swift` cleanup-on-launch: add `tmp/streaming/` to cleanup list (alongside existing `tmp/decrypted/` and `tmp/share/`).

### Swift tests: `Tests/ServiceTests/StreamingServiceTests.swift`

1. Encrypt + decrypt file round-trip (Profile A + B)
2. Disk space check — inject `MockDiskSpace` via `DiskSpaceChecker(diskSpace: mockDiskSpace)`, verify `insufficientDiskSpace` thrown when `availableBytes_` is set below threshold
3. Progress reporter updates correctly
4. Cancellation returns `operationCancelled`
5. AEAD tamper → no output file
6. Two-phase auth boundary preserved (mock SE unwrap count)
7. Sign + verify detached file round-trip
8. Encrypt-to-self file round-trip with mixed profiles

---

## PR 4: UI Layer — Progress Bar + Cancel

### `EncryptView.swift`

Current state (to change):
- `@State private var encryptedFileData: Data?` (line 44) — holds entire encrypted file in memory
- `Data(contentsOf: fileURL)` (line 387) — loads entire input file into memory
- `writeToShareTempFile` (line 210) — writes in-memory data to temp file for sharing
- "Maximum file size: 100 MB" footer (line 292)
- `ProgressView()` (line 145) — indeterminate

Changes:
- Replace `@State var encryptedFileData: Data?` with `@State var encryptedFileURL: URL?`
- Add `@State var progress: FileProgressReporter?`
- File mode: use `encryptFileStreaming` instead of `Data(contentsOf:)` + `encryptFile`
- Indeterminate `ProgressView()` → `ProgressView(value: progress.progress)`
- Cancel button calls `progress.cancel()`
- `ShareLink(item: encryptedFileURL!)` — file already on disk, no `writeToShareTempFile`
- Remove "Maximum file size: 100 MB" footer
- Security-scoped URL management for streaming:
  ```swift
  guard fileURL.startAccessingSecurityScopedResource() else { /* error */ }
  defer { fileURL.stopAccessingSecurityScopedResource() }
  // The defer keeps access alive for the entire streaming operation.
  // Rust opens the file descriptor immediately on entry to encrypt_file(),
  // so even if iOS revokes the security-scoped bookmark mid-operation,
  // the already-opened fd remains valid (POSIX semantics).
  let outputURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("streaming/\(UUID().uuidString)_\(filename).gpg")
  try await service.encryptFileStreaming(
      inputURL: fileURL, outputURL: outputURL, ...progress: progress)
  ```

### `DecryptView.swift`

Current state (to change):
- `@State private var decryptedFileData: Data?` (line 37) — holds entire decrypted file in memory
- `Data(contentsOf: fileURL)` (line 319) — loads entire ciphertext file into memory in Phase 1
- `onDisappear` zeroes data via `resetBytes` (lines 196-211)
- `writeToShareTempFile` (line 143)

Changes:
- File mode Phase 1: `parseRecipientsFromFile(fileURL:)` — no full file read. Security-scoped access needed only briefly (Rust reads PKESK headers only):
  ```swift
  guard fileURL.startAccessingSecurityScopedResource() else { /* error */ }
  defer { fileURL.stopAccessingSecurityScopedResource() }
  phase1 = try await service.parseRecipientsFromFile(fileURL: fileURL)
  // phase1.inputPath stores the file path for Phase 2
  ```
- File mode Phase 2: `decryptFileStreaming(phase1:outputURL:progress:)` with progress bar. Requires a second security-scoped access since the file must be re-read for full decryption:
  ```swift
  guard fileURL.startAccessingSecurityScopedResource() else { /* error */ }
  defer { fileURL.stopAccessingSecurityScopedResource() }
  // Rust opens the fd immediately; POSIX fd survives bookmark revocation
  let outputURL = FileManager.default.temporaryDirectory
      .appendingPathComponent("decrypted/\(UUID().uuidString)_\(filename)")
  let sigVerification = try await service.decryptFileStreaming(
      phase1: phase1, outputURL: outputURL, progress: progress)
  ```
- Replace `@State var decryptedFileData: Data?` with `@State var decryptedFileURL: URL?`
- onDisappear: delete temp file instead of `resetBytes` (plaintext is on disk, not in memory):
  ```swift
  if let url = decryptedFileURL {
      try? FileManager.default.removeItem(at: url)
      decryptedFileURL = nil
  }
  ```

### `SignView.swift`

Current state (to change):
- `Data(contentsOf: fileURL)` (line 262) — loads entire file into memory for signing
- `ProgressView()` (line 79) — indeterminate

Changes:
- File mode: use `signDetachedStreaming` instead of loading file + `signDetached`
- Indeterminate `ProgressView()` → `ProgressView(value: progress.progress)`
- Add cancel button for file signing
- Security-scoped URL: same `start/defer stop` pattern as EncryptView

### `VerifyView.swift`

Current state (to change):
- `Data(contentsOf: origURL)` (line 228) — loads entire original file into memory
- Signature file `Data(contentsOf: sigURL)` (line 229) — small, stays in memory

Changes:
- File mode: use `verifyDetachedStreaming` for original file (streaming), signature stays in memory (small)
- Add progress bar for file verification
- Security-scoped URL: both URLs get `start/defer stop`; signature file is loaded immediately (small), original file is streamed

### String Catalog

Add/update localized strings for:
- `fileEncrypt.encrypting` / `fileDecrypt.decrypting` (progress labels, en + zh-Hans)
- Remove `fileEncrypt.sizeLimit` footer string (no fixed limit for streaming)

---

## PR Compilation Independence

Each PR must compile and pass tests independently when merged in order:

| PR | Why it compiles independently |
|----|-------------------------------|
| PR 1 | Only Rust changes. No Swift files modified. `cargo test` passes. |
| PR 2 | Adds new Swift types (`operationCancelled`, `fileIoError`, `insufficientDiskSpace`) and `init(pgpError:)` mappings for the two new `PgpError` variants (required for exhaustive switch). Nothing calls the new types yet. Keeps `fileTooLarge` — still referenced by EncryptionService line 81. |
| PR 3 | Adds new service methods. Old UI still calls old methods. `fileTooLarge` retained (old in-memory `encryptFile` still uses it). Adds `DiskSpaceChecker` with protocol-based testability. |
| PR 4 | UI switches to new streaming service methods for file operations. Old in-memory methods remain available for text operations. |

---

## Security Invariants Preserved

| Invariant | How |
|-----------|-----|
| AEAD hard-fail | Decrypt writes to `.tmp`, renames only after full verification. Temp file zero-overwritten + deleted on any error. |
| Memory zeroing | Manual `zeroing_copy` with `Zeroizing<Vec<u8>>` buffers replaces `io::copy` — all transfer buffers holding plaintext are zeroized on drop. No uncontrolled `BufReader`/`BufWriter`/`io::copy` internal buffers. Signing key `Data` zeroized in Swift `defer`. |
| No plaintext in logs | Streaming functions log byte counts + paths only |
| Secure random | No change — handled by Sequoia internally |
| Two-phase decrypt | Phase 1 (header parse, no auth) → Phase 2 (SE unwrap + biometric) boundary unchanged. Phase 2 re-reads file via fresh security-scoped access. |
| Zero network | No change |
| Error classification | All errors use explicit `.map_err()`, no blanket `From<anyhow::Error>` — consistent with existing error.rs design |

## Files to Modify

### Rust (security boundary — require human review)
- `pgp-mobile/src/streaming.rs` — **NEW** (includes `zeroing_copy`, `zeroing_copy_with_progress`, `ProgressReader`, 5 streaming functions, `secure_delete_file`)
- `pgp-mobile/src/lib.rs` — add `pub mod streaming`, 5 new exports
- `pgp-mobile/src/error.rs` — add `OperationCancelled`, `FileIoError`
- `pgp-mobile/src/encrypt.rs` — 3 functions → `pub(crate)` visibility
- `pgp-mobile/src/decrypt.rs` — `DecryptHelper` struct + `classify_decrypt_error` → `pub(crate)`
- `pgp-mobile/src/sign.rs` — extract `extract_signing_keypair` as `pub(crate)` helper
- `pgp-mobile/src/verify.rs` — `VerifyHelper` struct → `pub(crate)`
- `pgp-mobile/tests/streaming_tests.rs` — **NEW**

### Swift
- `Sources/PgpMobile/pgp_mobile.swift` — regenerated (do not hand-edit)
- `Sources/Models/CypherAirError.swift` — PR 2: add 3 new cases + 2 `init(pgpError:)` mappings; `fileTooLarge` retained
- `Sources/Services/FileProgressReporter.swift` — **NEW**
- `Sources/Services/DiskSpaceChecker.swift` — **NEW** (includes `DiskSpaceProvidable` protocol, `SystemDiskSpace`, `DiskSpaceChecker`)
- `Sources/Security/Mocks/MockDiskSpace.swift` — **NEW**
- `Sources/Services/EncryptionService.swift` — add streaming method, inject `DiskSpaceChecker`, old method unchanged
- `Sources/Services/DecryptionService.swift` — add file Phase 1/2 with re-read in Phase 2
- `Sources/Services/SigningService.swift` — add streaming methods
- `Sources/App/Encrypt/EncryptView.swift` — progress bar, file URL state, remove size limit footer, security-scoped lifecycle
- `Sources/App/Decrypt/DecryptView.swift` — progress bar, file URL state, two-phase security-scoped access, temp file cleanup
- `Sources/App/Sign/SignView.swift` — progress bar, security-scoped lifecycle
- `Sources/App/Sign/VerifyView.swift` — progress bar, security-scoped lifecycle
- `Sources/App/CypherAirApp.swift` — add `tmp/streaming/` to cleanup
- `Sources/Resources/Localizable.xcstrings` — new/updated strings
- `Tests/ServiceTests/StreamingServiceTests.swift` — **NEW**

### Docs
- `docs/PRD.md` — update v1.1 description, file size limit section, error messages table
- `docs/TDD.md` — add streaming architecture section
- `docs/ARCHITECTURE.md` — update data flow diagrams

## Verification

1. `cargo test --manifest-path pgp-mobile/Cargo.toml` — all streaming tests pass
2. `xcodebuild test -testPlan CypherAir-UnitTests` — all Swift tests pass
3. Manual: encrypt/decrypt 200 MB file, observe progress bar, verify memory stays flat in Xcode Memory Gauge
4. Manual: cancel mid-stream, verify no orphan temp files
5. Manual: tamper with encrypted file, verify error + no output
6. Manual: fill disk to near-capacity, verify disk space error message
7. Device test: run full streaming workflow on A19 device with MIE Hardware Memory Tagging enabled
8. Manual: after decrypt completes, check Xcode Memory Graph Debugger for any residual plaintext in freed heap — should find none from our buffers (Sequoia's internal buffers are outside our control)

---

## Revision Log (v1 → v2)

| # | Issue | Resolution |
|---|-------|------------|
| 1 | `BufWriter` plaintext buffer not zeroized during decryption | Replaced `BufReader`/`BufWriter`/`io::copy` with manual `zeroing_copy` using `Zeroizing<Vec<u8>>` for all paths where data may contain plaintext |
| 2 | `io::copy` internal stack buffer holds plaintext | Same fix — manual copy loop eliminates `io::copy` entirely |
| 3 | Encryption input `BufReader` holds plaintext | Same fix — manual copy loop eliminates `BufReader` |
| 4 | Security-scoped URL lifetime during streaming | Explicit `start/defer stop` pattern documented for each view; Rust opens fd immediately; POSIX fd semantics survive bookmark revocation |
| 5 | DecryptView two-phase security-scoped access | Phase 1 and Phase 2 each get their own `start/defer stop` block; file re-read in Phase 2 |
| 6 | `DiskSpaceChecker` not mockable | Refactored to protocol + default parameter pattern (matching `Argon2idMemoryGuard`/`MemoryInfoProvidable`) |
| 7 | Old `encryptFile` getting disk space check instead of memory check | Old method retains its 100 MB hard limit unchanged; `DiskSpaceChecker` only for streaming |
| 8 | `fileTooLarge` removal breaking old method | `fileTooLarge` retained; old in-memory method unchanged |
| 9 | Temp file name collisions | UUID prefix: `<UUID>_<name>.gpg` |
| 10 | Missing encrypt-to-self file test | Added as Rust test #11 and Swift test #8 |
| 11 | `@unchecked Sendable` on `FileProgressReporter` undocumented | Added safety justification comment |
| 12 | `init(pgpError:)` mapping for new variants not explicit | Explicitly noted as PR 2 requirement for exhaustive switch |
