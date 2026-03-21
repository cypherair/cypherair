# Security Audit Fix Plan (Revised v4)

> **Date:** 2026-03-21
> **Scope:** pgp-mobile Rust crate — 4 medium-severity (M1–M4) + 9 low-severity (L1–L9) findings
> **Status:** Approved for implementation
> **Constraint:** All changes within Rust `pgp-mobile` crate. No FFI API changes. No Swift-side changes.
> **Revision:** v4 incorporates 6 amendments — see [Revision Log](#revision-log) at end.

---

## Summary

| Batch | Findings | Type | Risk | Dependencies |
|-------|----------|------|------|-------------|
| 1 | M2 + L8 | Streaming decrypt error chain fix + function dedup | Low | None |
| 2 | L5 | encrypt.rs intermediate buffer elimination | Negligible | None |
| 3 | M3 + L7 | Temp file name randomization | Very low | None |
| 4 | M1 + L4 | Error classification regression tests + string tightening | Very low | Depends on Batch 1 |
| 5 | L2 + L3 + L6 Phase 1 | Data quality + simple parameter zeroing | Low | None |
| 6 | L6 Phase 2 | `Vec<Vec<u8>>` parameter zeroing | Medium | Depends on Batch 5 |
| 7 | M4 + L1 + L9 | Documentation & comments | Zero | None |

**Dependency graph:**

```
Phase 1 (parallelizable):
  ├── Batch 1: M2 + L8 (error chain fix, highest priority)
  ├── Batch 2: L5 (write_all replacement, trivial)
  ├── Batch 3: M3 + L7 (temp file randomization)
  ├── Batch 5: L2 + L3 + L6p1 (data quality + simple zeroing)
  └── Batch 7: M4 + L1 + L9 (comments)

Phase 2 (depends on Phase 1):
  ├── Batch 4: M1 + L4 (depends on Batch 1 error chain fix)
  └── Batch 6: L6p2 (depends on Batch 5 Zeroizing pattern validation)
```

Each batch is an independent PR with corresponding tests.

---

## Batch 1: M2 + L8 — Streaming Decrypt Error Chain Fix + zeroing_copy Dedup

### Problem

**M2 (Medium):** `streaming.rs:104-111` — `zeroing_copy()` converts Sequoia's AEAD/MDC errors into `PgpError::FileIoError { reason: "Read failed: ..." }`, destroying the original typed error chain. `decrypt_file` at `streaming.rs:341-355` can only do string matching on the `reason` field — it cannot call `classify_decrypt_error()`.

Error flow path:

```
Sequoia Decryptor::read()
  → io::Error::new(ErrorKind::Other, anyhow::Error)  // Sequoia wrapping layer
    → zeroing_copy reader.read()
      → map_err to PgpError::FileIoError { reason: format!("Read failed: {e}") }
        → Original anyhow::Error lost, cannot downcast
```

**L8 (Low):** `zeroing_copy` (`streaming.rs:95-123`) and `zeroing_copy_with_progress` (`streaming.rs:129-157`) have identical logic, differing only in parameter types. `ProgressReader` already implements `Read`, making the dedicated variant unnecessary.

### Fix

**Step 1:** Introduce internal enum `CopyError` in `streaming.rs`:

```rust
/// Internal error type for zeroing_copy that preserves the original io::Error
/// from the reader, allowing callers to extract and reclassify decryption errors.
#[derive(Debug)]
enum CopyError {
    /// Read error — preserves the original io::Error (may wrap Sequoia anyhow::Error)
    Read(std::io::Error),
    /// Write error — preserves the original io::Error
    Write(std::io::Error),
    /// Operation cancelled by user (progress callback returned false)
    Cancelled,
}
```

> **Note:** `#[derive(Debug)]` is required because `Result<T, CopyError>` requires `E: Debug`
> for `.unwrap()` in tests. Without it, test code that calls `zeroing_copy(...).unwrap()` will
> fail to compile.

**Step 2:** Change `zeroing_copy` to return `Result<u64, CopyError>`:

```rust
fn zeroing_copy<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
) -> Result<u64, CopyError> {
    let mut buf = Zeroizing::new(vec![0u8; buf_size]);
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                CopyError::Cancelled
            } else {
                CopyError::Read(e)  // Preserve original io::Error
            }
        })?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(CopyError::Write)?;
        total += n as u64;
    }

    Ok(total)
}
```

**Step 3:** Delete `zeroing_copy_with_progress`. Since `ProgressReader<R: Read>` itself implements `Read`, `zeroing_copy`'s generic parameter `R: Read` already covers `ProgressReader`.

**Step 4:** Update the three call sites:

**(a) `decrypt_file` (`streaming.rs:338`) — core fix point:**

```rust
// Stream decrypted data to temp file using zeroing copy
if let Err(e) = zeroing_copy(&mut decryptor, &mut temp_file, STREAM_BUFFER_SIZE) {
    drop(temp_file);
    secure_delete_file(temp_path_ref);
    return Err(match e {
        CopyError::Read(io_err) => {
            // Sequoia's Decryptor implements Read; its read() wraps decryption
            // errors as io::Error::new(ErrorKind::Other, anyhow_error).
            // Extract the inner error and pass to classify_decrypt_error()
            // for proper AEAD/MDC/NoMatchingKey classification.
            if let Some(inner) = io_err.into_inner() {
                // Attempt to downcast Box<dyn Error> to anyhow::Error
                match inner.downcast::<openpgp::anyhow::Error>() {
                    Ok(anyhow_err) => classify_decrypt_error(*anyhow_err),
                    Err(other) => PgpError::CorruptData {
                        reason: format!("Decryption failed: {other}"),
                    },
                }
            } else {
                // Pure I/O error (no inner error), keep as FileIoError
                PgpError::FileIoError {
                    reason: "Read failed during decryption".to_string(),
                }
            }
        }
        CopyError::Write(io_err) => PgpError::FileIoError {
            reason: format!("Write failed: {io_err}"),
        },
        CopyError::Cancelled => PgpError::OperationCancelled,
    });
}
```

**Key technical detail:** `io::Error::into_inner()` returns `Option<Box<dyn Error + Send + Sync>>`. Sequoia wraps decryption errors as `io::Error::new(ErrorKind::Other, anyhow_error)`, where the inner type is `anyhow::Error`. Via `downcast::<anyhow::Error>()` the original error can be extracted and passed to `classify_decrypt_error()` for structured downcast (`openpgp::Error` variants) and string matching (OpenSSL AEAD tag errors).

If `into_inner()` returns `None` (pure I/O error such as disk full), or `downcast` fails (non-anyhow wrapped error), fall back to generic error handling.

**(b) `encrypt_file` (`streaming.rs:252`):**

```rust
let result = zeroing_copy(&mut progress_reader, &mut literal, STREAM_BUFFER_SIZE);
if let Err(e) = result {
    drop(literal);
    secure_delete_file(std::path::Path::new(output_path));
    return Err(match e {
        CopyError::Read(io_err) => PgpError::EncryptionFailed {
            reason: format!("Read failed: {io_err}"),
        },
        CopyError::Write(io_err) => PgpError::EncryptionFailed {
            reason: format!("Write failed: {io_err}"),
        },
        CopyError::Cancelled => PgpError::OperationCancelled,
    });
}
```

**(c) `sign_detached_file` (`streaming.rs:423`):**

```rust
if let Err(e) = zeroing_copy(&mut progress_reader, &mut signer, STREAM_BUFFER_SIZE) {
    return Err(match e {
        CopyError::Read(io_err) => PgpError::SigningFailed {
            reason: format!("Read failed: {io_err}"),
        },
        CopyError::Write(io_err) => PgpError::SigningFailed {
            reason: format!("Write failed: {io_err}"),
        },
        CopyError::Cancelled => PgpError::OperationCancelled,
    });
}
```

**Step 5:** Add tests in `streaming_tests.rs` asserting **specific error types** (not just `is_err()`):

```rust
#[test]
fn test_streaming_decrypt_aead_tamper_returns_specific_error() {
    // Generate Profile B key (SEIPDv2 AEAD)
    // Encrypt file → tamper ciphertext AEAD tag area → streaming decrypt
    // Assert: error is AeadAuthenticationFailed or IntegrityCheckFailed
    // (NOT CorruptData or FileIoError)
}

#[test]
fn test_streaming_decrypt_mdc_tamper_returns_specific_error() {
    // Generate Profile A key (SEIPDv1 MDC)
    // Encrypt file → tamper ciphertext → streaming decrypt
    // Assert: error is IntegrityCheckFailed
    // (NOT CorruptData or FileIoError)
}
```

### Files Changed

| File | Changes |
|------|---------|
| `pgp-mobile/src/streaming.rs` | Add `CopyError`; change `zeroing_copy` return type; delete `zeroing_copy_with_progress`; update 3 call sites |
| `pgp-mobile/tests/streaming_tests.rs` | Add 2 specific error type assertion tamper tests |

### Impact Analysis

- `CopyError` is crate-internal, does not cross FFI boundary, no Swift-side impact
- `encrypt_file` and `sign_detached_file` error behavior remains equivalent (only mapping changes)
- `decrypt_file` error behavior becomes **more correct** (upgraded from string matching to structured classification)
- Removing `zeroing_copy_with_progress` eliminates ~30 lines of duplicate code

---

## Batch 2: L5 — encrypt.rs Intermediate Buffer Elimination

### Problem

**L5 (Low):** `encrypt.rs:158` uses `std::io::copy(&mut &plaintext[..], &mut literal)` to write plaintext through the encryption pipeline. `std::io::copy` internally uses an 8KiB stack buffer that is not zeroed, inconsistent with `streaming.rs`'s explicit `Zeroizing<Vec<u8>>` policy.

### Fix

Replace `std::io::copy` with `write_all`. Since `plaintext` is already a contiguous `&[u8]` slice in memory, `write_all` writes it directly to the writer without any intermediate buffer.

```rust
// Before (encrypt.rs:158):
std::io::copy(&mut &plaintext[..], &mut literal).map_err(|e| PgpError::EncryptionFailed {
    reason: format!("Write failed: {e}"),
})?;

// After:
literal.write_all(plaintext).map_err(|e| PgpError::EncryptionFailed {
    reason: format!("Write failed: {e}"),
})?;
```

Also fix `sign.rs:102` in `sign_detached`:

```rust
// Before (sign.rs:102):
std::io::copy(&mut &data[..], &mut signer).map_err(|e| PgpError::SigningFailed {
    reason: format!("Write failed: {e}"),
})?;

// After:
signer.write_all(data).map_err(|e| PgpError::SigningFailed {
    reason: format!("Write failed: {e}"),
})?;
```

Note: `sign_cleartext` (`sign.rs:65`) already uses `std::io::Write::write_all` — no change needed.

### Files Changed

| File | Changes |
|------|---------|
| `pgp-mobile/src/encrypt.rs` | Line 158: `std::io::copy` → `write_all` (1 line) |
| `pgp-mobile/src/sign.rs` | Line 102: `std::io::copy` → `write_all` (1 line) |

### Impact Analysis

- `write_all` is semantically equivalent to `std::io::copy` for contiguous in-memory data
- Eliminates non-zeroed 8KiB stack buffer
- Simpler code (no `&mut &plaintext[..]` Read adapter syntax)
- Risk: Negligible

---

## Batch 3: M3 + L7 — Temp File Security

### Problem

**M3 (Medium):** `streaming.rs:330` uses predictable temp file name `{output_path}.tmp`. Although `output_path` is constructed by Swift-side `DecryptionService` (containing `UUID()`), the `.tmp` suffix relative to the final path is predictable, presenting a theoretical symlink/race attack surface.

**L7 (Low):** If the process is SIGKILL'd (iOS Jetsam) between temp file creation and rename, the temp file persists until next app launch. `CypherAirApp.swift:cleanupTempDecryptedFiles()` recursively deletes the `tmp/decrypted/` directory, covering `.tmp` files within that directory. But if `output_path` were outside that directory, cleanup would miss the temp file.

### Fix

**Step 1:** Add random suffix to temp file name.

```rust
// Before (streaming.rs:330):
let temp_path = format!("{output_path}.tmp");

// After:
let mut random_bytes = [0u8; 8];
openpgp::crypto::random(&mut random_bytes);
let hex_suffix: String = random_bytes.iter().map(|b| format!("{b:02x}")).collect();
let temp_path = format!("{output_path}.{hex_suffix}.tmp");
```

Uses `openpgp::crypto::random()` (already used in `keys.rs:298`, backed by OpenSSL CSPRNG → iOS `SecRandomCopyBytes`). While CSPRNG for filename randomization is cryptographically overkill, it is already available with no additional dependency.

**Step 2:** Add tests.

```rust
#[test]
fn test_decrypt_file_error_cleans_up_temp_file() {
    // Create corrupted encrypted file → call decrypt_file
    // → verify no .tmp files remain in output directory
}

#[test]
fn test_decrypt_file_temp_has_random_suffix() {
    // Call decrypt_file twice (can deliberately fail to inspect temp paths)
    // → verify the two temp paths differ
}
```

### Files Changed

| File | Changes |
|------|---------|
| `pgp-mobile/src/streaming.rs` | Line 330: add random suffix generation (~4 lines) |
| `pgp-mobile/tests/streaming_tests.rs` | Add 2 tests |

### Impact Analysis

- Random suffix only affects temp file name, created and deleted within the same function call
- `secure_delete_file` in all existing error paths references the `temp_path_ref` local variable — changes apply automatically
- Swift-side `cleanupTempDecryptedFiles()` recursively deletes entire directory, does not depend on specific filenames
- Risk: Very low

---

## Batch 4: M1 + L4 — Error Classification Regression Tests + String Tightening

> **Dependency:** Batch 1 (M2 fix must be in place so streaming decrypt tamper tests verify the corrected error classification)

### Problem

**M1 (Medium):** `classify_decrypt_error()` string matching fallback (`decrypt.rs:379-394`) depends on Sequoia/OpenSSL error message wording. Sequoia version bumps may change wording, causing AEAD/MDC errors to be misclassified as `CorruptData`. Existing tests (`security_audit_tests.rs`) accept 4 error variants (`IntegrityCheckFailed`, `AeadAuthenticationFailed`, `CorruptData`, `NoMatchingKey`), too broad to detect regression.

**L4 (Low):** `is_expired_error()` string fallback (`decrypt.rs:459-460`) uses `err_str.contains("expired")`, too broad — could false-positive on any error containing the word "expired".

### Fix

**M1 — New tests only, no production code changes:**

Add targeted regression tests in `security_audit_tests.rs`:

```rust
#[test]
fn test_classify_decrypt_error_aead_tag_mismatch_returns_aead_failure() {
    // Generate Profile B key → encrypt → locate and tamper AEAD tag area
    // → decrypt → assert error is exactly AeadAuthenticationFailed
    // Do NOT accept CorruptData, IntegrityCheckFailed, or other variants
}

#[test]
fn test_classify_decrypt_error_mdc_tamper_returns_integrity_check_failed() {
    // Generate Profile A key → encrypt → tamper MDC-related area
    // → decrypt → assert error is exactly IntegrityCheckFailed
}
```

Keep existing broad tamper tests (for general regression coverage), but add comments noting their limitations:

```rust
// NOTE: This test accepts multiple error variants because the specific error
// depends on WHERE in the ciphertext the tamper occurs. For precise error type
// assertions, see test_classify_decrypt_error_aead_tag_mismatch_* tests.
```

**L4 — Tighten string matching:**

```rust
// Before (decrypt.rs:459-460):
let err_str = error.to_string().to_lowercase();
err_str.contains("expired")

// After:
let err_str = error.to_string().to_lowercase();
err_str.contains("key expired")
    || err_str.contains("certificate expired")
    || err_str.contains("signature expired")
    || err_str.contains("validity period expired")
```

**Risk note:** The structured downcast (`decrypt.rs:448-456`) handles >99% of cases (directly matches `openpgp::Error::Expired(_)`). The string fallback is defense-in-depth, only triggered if Sequoia changes its error type wrapping. The tightened strings cover Sequoia's known expired error message formats.

### Files Changed

| File | Changes |
|------|---------|
| `pgp-mobile/src/decrypt.rs` | Lines 459-460: tighten `is_expired_error` string matching (~4 lines) |
| `pgp-mobile/tests/security_audit_tests.rs` | Add 2+ precise error type assertion tests; add comments to existing broad tests |

### Impact Analysis

- `is_expired_error` structured downcast path unchanged
- String fallback normal operation unaffected (Sequoia's expired error messages contain "key expired" or "certificate expired")
- New tests provide regression protection for `classify_decrypt_error` string matching path
- Risk: Very low

---

## Batch 5: L2 + L3 + L6 Phase 1 — Data Quality + Simple Parameter Zeroing

### Problem

**L2 (Low):** `keys.rs:267-272` — `parse_key_info` uses `cert.with_policy(&policy, Some(now))` to get expiry timestamp. For expired certs, `with_policy` fails at the current time point returning `Err`, `.ok()` maps it to `None`, causing `expiry_timestamp` field to be `None`. Swift side cannot display the specific expiry time for expired keys.

**L3 (Low):** `keys.rs:604-650` — `parse_s2k_params` only checks the primary key's S2K parameters. If subkeys use higher Argon2id memory parameters (rare but possible), the memory check misses them, potentially causing Jetsam termination.

**L6 Phase 1 (Low):** FFI entry functions in `lib.rs` accepting key material as `Vec<u8>` do not wrap parameters in `Zeroizing`. After the function returns, `Vec<u8>` is freed but memory is not zeroed.

### Fix

**L2 — Two-level fallback for expiry timestamp:**

```rust
// Before (keys.rs:267-272):
let expiry_timestamp = cert
    .with_policy(&policy, Some(now))
    .ok()
    .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
    .map(|d| d.as_secs());

// After:
let expiry_timestamp = cert
    .with_policy(&policy, Some(now))
    .ok()
    .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
    .or_else(|| {
        // Fallback for expired certs: validate without temporal check
        // to retrieve the expiry timestamp for display purposes.
        // Note: this also succeeds for not-yet-valid certs (creation_time
        // in the future), which is accepted — displaying the planned expiry
        // for such certs is not harmful.
        cert.with_policy(&policy, None)
            .ok()
            .and_then(|valid_cert| valid_cert.primary_key().key_expiration_time())
    })
    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
    .map(|d| d.as_secs());
```

Two-level approach: first try `Some(now)` (normal certs), then fall back to `None` (expired certs). Using `None` directly would also return expiry for not-yet-valid certs (creation_time in the future) — this is accepted as harmless (displaying a planned expiry time is not incorrect behavior). The `is_expired` field (independently computed at `keys.rs:230-240`) is unaffected.

**L3 — Scan all keys for S2K parameters:**

```rust
pub fn parse_s2k_params(armored_data: &[u8]) -> Result<S2kInfo, PgpError> {
    let cert = openpgp::Cert::from_bytes(armored_data).map_err(|e| PgpError::InvalidKeyData {
        reason: e.to_string(),
    })?;

    let mut max_info: Option<S2kInfo> = None;

    // Check primary key + all subkeys, return the highest memory requirement
    let all_keys = std::iter::once(cert.primary_key().key().clone())
        .chain(cert.keys().subkeys().map(|ka| ka.key().clone()));

    for key in all_keys {
        match key.optional_secret() {
            Some(openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)) => {
                let info = match encrypted.s2k() {
                    openpgp::crypto::S2K::Argon2 { t, p, m, .. } => {
                        let memory_kib: u64 = 1u64 << (*m as u64);
                        S2kInfo {
                            s2k_type: "argon2id".to_string(),
                            memory_kib,
                            parallelism: *p as u32,
                            time_passes: *t as u32,
                        }
                    }
                    openpgp::crypto::S2K::Iterated { .. } => S2kInfo {
                        s2k_type: "iterated-salted".to_string(),
                        memory_kib: 0, parallelism: 0, time_passes: 0,
                    },
                    _ => S2kInfo {
                        s2k_type: "unknown".to_string(),
                        memory_kib: 0, parallelism: 0, time_passes: 0,
                    },
                };
                // Keep the S2K info with the highest memory requirement
                if max_info.as_ref().map_or(true, |existing| info.memory_kib > existing.memory_kib) {
                    max_info = Some(info);
                }
            }
            Some(openpgp::packet::key::SecretKeyMaterial::Unencrypted(_)) => {
                // Unencrypted key — skip (no S2K check needed)
            }
            None => {
                // No secret key material — skip (subkey may be public-only)
            }
        }
    }

    max_info.ok_or(PgpError::InvalidKeyData {
        reason: "No encrypted secret key material found".to_string(),
    })
}
```

**L6 Phase 1 — Simple `Vec<u8>` parameter zeroing:**

For FFI methods accepting a single `Vec<u8>` of key material, wrap in `Zeroizing` immediately at the entry point:

```rust
// Example: sign_cleartext (lib.rs:168-174)
pub fn sign_cleartext(
    &self,
    text: Vec<u8>,
    signer_cert: Vec<u8>,
) -> Result<Vec<u8>, PgpError> {
    let signer_cert = Zeroizing::new(signer_cert);  // Zero on drop
    sign::sign_cleartext(&text, &signer_cert)
}
```

`Zeroizing<Vec<u8>>` implements `Deref<Target=Vec<u8>>`, so `&signer_cert` auto-dereferences when passed to inner functions accepting `&[u8]`. No inner function signature changes needed.

**Affected methods (9, simple `Vec<u8>` or `Option<Vec<u8>>` parameters):**

| Method | Parameter | Line | Material Type |
|--------|-----------|------|---------------|
| `sign_cleartext` | `signer_cert: Vec<u8>` | `lib.rs:171` | Secret key |
| `sign_detached` | `signer_cert: Vec<u8>` | `lib.rs:180` | Secret key |
| `encrypt` | `signing_key: Option<Vec<u8>>` | `lib.rs:101` | Secret key |
| `encrypt_binary` | `signing_key: Option<Vec<u8>>` | `lib.rs:117` | Secret key |
| `encrypt_file` | `signing_key: Option<Vec<u8>>` | `lib.rs:277` | Secret key |
| `export_secret_key` | `cert_data: Vec<u8>` | `lib.rs:212` | Secret key |
| `modify_expiry` | `cert_data: Vec<u8>` | `lib.rs:83` | Secret key |
| `sign_detached_file` | `signer_cert: Vec<u8>` | `lib.rs:315` | Secret key |
| `parse_revocation_cert` | `cert_data: Vec<u8>` | `lib.rs:245` | May contain secret key |

Notes:
- `import_secret_key`'s `armored_data: Vec<u8>` contains passphrase-protected key data (already encrypted), lower zeroing priority but still recommended for completeness.
- `encrypt` / `encrypt_binary` / `encrypt_file`'s `encrypt_to_self: Option<Vec<u8>>` does **not** need zeroing — Swift side passes `publicKeyData` (verified in `EncryptionService.swift:158,247`).
- `parse_revocation_cert`'s `cert_data` only performs public key operations internally, but callers may pass a full cert containing secret material (confirmed in `FFIIntegrationTests.swift:527`). Included for defense-in-depth.

For `Option<Vec<u8>>` parameters, the wrapping pattern is:

```rust
let signing_key: Option<Zeroizing<Vec<u8>>> = signing_key.map(Zeroizing::new);
encrypt::encrypt(&plaintext, &recipients, signing_key.as_ref().map(|z| z.as_slice()), ...)
```

**Important:** `as_deref()` cannot be used here. `Zeroizing<Vec<u8>>` implements `Deref<Target=Vec<u8>>`, so `Option<Zeroizing<Vec<u8>>>.as_deref()` yields `Option<&Vec<u8>>`, **not** `Option<&[u8]>`. Rust does not perform unsized coercion (`Vec<u8>` → `[u8]`) inside `Option`. The correct conversion uses `.as_ref().map(|z| z.as_slice())` to explicitly go through both deref layers.

### Files Changed

| File | Changes |
|------|---------|
| `pgp-mobile/src/keys.rs` | Lines 267-272: two-level fallback for `expiry_timestamp` (L2) |
| `pgp-mobile/src/keys.rs` | Lines 604-650: refactor `parse_s2k_params` to scan all keys (L3) |
| `pgp-mobile/src/lib.rs` | 9 methods add `Zeroizing::new()` / `.map(Zeroizing::new)` wrapping (L6 Phase 1) |
| `pgp-mobile/tests/` | Add tests: L2 expired key timestamp, L3 subkey S2K |

### Impact Analysis

- L2: Only affects `KeyInfo.expiry_timestamp` display field, does not affect encrypt/decrypt/sign logic
- L3: Conservative strategy (returns max memory requirement), can only cause earlier rejection (safe direction), never false-allow
- L6 Phase 1: `Zeroizing` wrapping is transparent to callers (`Deref` handles conversion), no API change
- Risk: Low

---

## Batch 6: L6 Phase 2 — `Vec<Vec<u8>>` Parameter Zeroing

> **Dependency:** Batch 5 (Phase 1 validates the `Zeroizing` wrapping pattern before extending to more complex cases)

### Problem

`decrypt` (`lib.rs:159`) and `decrypt_file` (`lib.rs:297`) have `secret_keys: Vec<Vec<u8>>` parameters containing multiple key materials. `encrypt_file` (`lib.rs:277`) has `signing_key: Option<Vec<u8>>` which contains key material when present. These parameters are freed but not zeroed when the function returns.

### Fix

Unlike Phase 1, `Vec<Vec<u8>>` parameters cannot be transparently passed via simple `Zeroizing::new()` wrapping because `&[Zeroizing<Vec<u8>>]` is not the same type as `&[Vec<u8>]` in Rust's type system. Inner function signatures must be changed.

**Recommended approach — generic `AsRef<[u8]>`:**

```rust
// decrypt.rs — change function signature
pub fn decrypt<K: AsRef<[u8]>>(
    ciphertext: &[u8],
    secret_keys: &[K],
    verification_keys: &[Vec<u8>],
) -> Result<DecryptResult, PgpError> {
    // In inner loop: Cert::from_bytes(key_data.as_ref()) instead of Cert::from_bytes(key_data)
}
```

```rust
// lib.rs — FFI entry point
pub fn decrypt(
    &self,
    ciphertext: Vec<u8>,
    secret_keys: Vec<Vec<u8>>,
    verification_keys: Vec<Vec<u8>>,
) -> Result<DecryptResult, PgpError> {
    let secret_keys: Vec<Zeroizing<Vec<u8>>> =
        secret_keys.into_iter().map(Zeroizing::new).collect();
    decrypt::decrypt(&ciphertext, &secret_keys, &verification_keys)
}
```

The generic `K: AsRef<[u8]>` is backward-compatible — it accepts both `Vec<u8>` and `Zeroizing<Vec<u8>>`, so test code does not need to use `Zeroizing`.

**Affected methods (2 — `Vec<Vec<u8>>` parameters requiring inner function signature changes):**

| FFI Method | Parameter | Inner Function |
|------------|-----------|---------------|
| `decrypt` | `secret_keys: Vec<Vec<u8>>` | `decrypt::decrypt` |
| `decrypt_file` | `secret_keys: Vec<Vec<u8>>` | `streaming::decrypt_file` |

Note: `encrypt` / `encrypt_binary` / `encrypt_file`'s `signing_key: Option<Vec<u8>>` is already covered in Batch 5 Phase 1 (simple `Option` wrapping via `.map(Zeroizing::new)` + `.as_ref().map(|z| z.as_slice())`, no inner signature change needed).

### Files Changed

| File | Changes |
|------|---------|
| `pgp-mobile/src/lib.rs` | 2 methods add `Zeroizing` wrapping for `Vec<Vec<u8>>` |
| `pgp-mobile/src/decrypt.rs` | `decrypt` function signature changed to generic `K: AsRef<[u8]>` |
| `pgp-mobile/src/streaming.rs` | `decrypt_file` function signature likewise |
| `pgp-mobile/tests/` | Update affected test call sites (if any) |

### Impact Analysis

- Inner function signature changes do not affect FFI API (UniFFI only sees `lib.rs` `#[uniffi::export]` methods)
- Generic `K: AsRef<[u8]>` is backward-compatible with existing `&[Vec<u8>]` calls
- Test code may require minor adjustments (if directly calling inner functions)
- Risk: Medium (multiple function signature changes, requires careful compilation and test verification)

---

## Batch 7: M4 + L1 + L9 — Documentation & Comments

### Problem

**M4 (Medium):** `verify.rs:180-182` — `MissingKey` branch does not have `return Ok(())` (falls through to next iteration), inconsistent with `BadKey` and catch-all `Err(_)` branches (which have `return Ok()`).

**After code analysis:** This is intentional. If a message has multiple signatures and one signer is unknown (MissingKey), continuing the loop can find a subsequent matching valid signature. Returning early would miss valid signatures.

**Contrast with `decrypt.rs:289-333`:** In `DecryptHelper::check()`, ALL non-GoodChecksum arms fall through (including MissingKey, BadKey, and catch-all). This differs from `verify.rs` where `BadKey` and catch-all return early, but both behaviors are correct in their respective contexts.

**Note:** The original audit report's description of `decrypt.rs:304-306` is inaccurate — the report claimed "BadKey and catch-all Err(_) both execute `return Ok()`", but actually all non-GoodChecksum arms in `decrypt.rs` fall through without `return Ok(())`.

**L1 (Low):** `keys.rs:260-262` — subkey algorithm name fallback takes the first subkey regardless of encryption capability. This is display-only fallback logic that does not affect encryption operations.

**L9 (Low):** `armor.rs:42` uses `ReaderMode::Tolerant(None)` which silently accepts non-armored binary input. This is intentional — callers may pass raw binary (from Keychain) or ASCII-armored text (from clipboard), and the reader auto-detects format.

### Fix

Comments only, no functional changes.

**M4 — `verify.rs:180-182`:**

```rust
Err(VerificationError::MissingKey { .. }) => {
    // INTENTIONAL: No `return Ok(())` here — fall through to continue
    // checking subsequent signatures in the results list. If a message
    // has multiple signatures and one signer is unknown, a later signature
    // may match a known key. Returning early would miss valid signatures.
    //
    // This differs from BadKey and catch-all Err(_) which return immediately
    // because those represent definitive verification outcomes for a known key,
    // while MissingKey means we simply cannot evaluate this particular signature.
    self.status = SignatureStatus::UnknownSigner;
}
```

**M4 — `decrypt.rs` `DecryptHelper::check()` overall comment (added at function top):**

```rust
// NOTE: All non-GoodChecksum arms intentionally fall through (no early return).
// This differs from VerifyHelper::check() where BadKey and catch-all return early.
// In the decryption context, signature verification is "graded" — decryption succeeds
// regardless of signature status, and the UI shows the result alongside plaintext.
// Only GoodChecksum triggers early return (found a valid signature, no need to continue).
// For other outcomes, the last-set status wins based on iteration order.
```

**L1 — `keys.rs:260-262`:**

```rust
.or_else(|| {
    // Fallback for display only: if no policy-valid encryption subkey found
    // (e.g., expired key), report the first subkey's algorithm name.
    // This does NOT affect encryption operations — encrypt() independently
    // uses with_policy() to find valid encryption subkeys and will correctly
    // reject keys with no valid encryption-capable subkey.
    cert.keys().subkeys().next().map(|ka| ka.key().pk_algo().to_string())
})
```

**L9 — `armor.rs:42`:**

```rust
// ReaderMode::Tolerant(None): accepts both ASCII-armored and raw binary OpenPGP data.
// This is intentional — callers may pass raw binary (e.g., from Keychain storage
// or .gpg files) or ASCII-armored text (e.g., from clipboard paste or .asc files).
// The reader auto-detects format. Passing binary to a strict armor reader would
// reject valid input; tolerant mode avoids requiring callers to pre-detect format.
```

### Files Changed

| File | Changes |
|------|---------|
| `pgp-mobile/src/verify.rs` | Lines 180-182: add comment |
| `pgp-mobile/src/decrypt.rs` | `DecryptHelper::check()` function top: add comment |
| `pgp-mobile/src/keys.rs` | Lines 260-262: add comment |
| `pgp-mobile/src/armor.rs` | Line 42: add comment |

### Impact Analysis

- Zero functional changes
- Risk: Zero

---

## Appendix: Finding Verification Summary

| ID | Severity | Confirmed | Notes |
|----|----------|-----------|-------|
| M1 | Medium | Yes | String matching fragility in `classify_decrypt_error()`. Test coverage gap. |
| M2 | Medium | Yes | `zeroing_copy` destroys Sequoia error chain. Streaming tamper tests only assert `is_err()`. |
| M3 | Medium | Yes | Predictable temp file name, mitigated by UUID in parent path. |
| M4 | Medium | Partial | `verify.rs` MissingKey fallthrough is **intentional**. Report's description of `decrypt.rs` is **inaccurate**. |
| L1 | Low | Yes | Informational display fallback, does not affect crypto operations. |
| L2 | Low | Yes | `with_policy(Some(now))` returns None for expired certs. |
| L3 | Low | Yes | Primary-key-only S2K check, subkeys could have higher memory requirements. |
| L4 | Low | Yes | `contains("expired")` is overly broad but structured downcast handles >99% of cases. |
| L5 | Low | Yes | `std::io::copy` uses non-zeroed 8KiB buffer, inconsistent with zeroing policy. |
| L6 | Low | Yes | FFI entry points don't zero key material parameters on drop. |
| L7 | Low | Yes | SIGKILL orphan temp files covered by app-launch cleanup within `tmp/decrypted/`. |
| L8 | Low | Yes | Duplicate `zeroing_copy` / `zeroing_copy_with_progress` functions. |
| L9 | Low | Yes | Tolerant armor reader is intentional design, not a bug. |

---

## Revision Log

### v2 → v3: Five amendments

| # | Location | Issue | Resolution |
|---|----------|-------|------------|
| 1 | Batch 1 | `CopyError` missing `#[derive(Debug)]` — test `.unwrap()` would fail to compile | Added `#[derive(Debug)]` to `CopyError` enum definition |
| 2 | Batch 5 (L2) | `with_policy(&policy, None)` returns expiry for not-yet-valid certs too | Changed to two-level fallback: try `Some(now)` first, then `None`. Documented not-yet-valid behavior as accepted |
| 3 | Batch 5/6 | `encrypt()`, `encrypt_binary()`, `encrypt_file()`'s `signing_key: Option<Vec<u8>>` omitted from L6 zeroing scope | Added to Batch 5 Phase 1 table (3 methods). Confirmed `encrypt_to_self` is public key data — does not need zeroing. Moved `encrypt_file`'s `signing_key` from Batch 6 to Batch 5 (simple `Option` wrapping) |
| 4 | Batch 7 (M4) | Comment "priority: Valid > Expired > Bad > Unknown" implies explicit priority logic that doesn't exist | Reworded to "last-set status wins based on iteration order; GoodChecksum triggers early return" |
| 5 | Batch 5 | `parse_revocation_cert` (`lib.rs:242-248`) accepts `cert_data: Vec<u8>` that may contain secret material | Added to Batch 5 Phase 1 table. Function only does public key ops but callers may pass full certs |

**Net effect:** Batch 5 L6 Phase 1 expanded from 6 to 9 methods. Batch 6 reduced from 3 to 2 methods.

### v3 → v4: One amendment

| # | Location | Issue | Resolution |
|---|----------|-------|------------|
| 6 | Batch 5 (L6 Phase 1) + Batch 6 note | `Option<Zeroizing<Vec<u8>>>.as_deref()` yields `Option<&Vec<u8>>`, not `Option<&[u8]>` — Rust does not perform unsized coercion inside `Option` | Changed pattern from `.as_deref()` to `.as_ref().map(\|z\| z.as_slice())`. Added explanation of the `Deref` chain issue. Updated Batch 6 cross-reference. |
