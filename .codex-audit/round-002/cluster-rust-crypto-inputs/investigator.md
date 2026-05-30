# Round 2 Investigator: cluster-rust-crypto-inputs

Current HEAD inspected: `d075268f61154227b5ff8545bb53808cccfda66c`.

## CA-30: Predictable decrypt temp file enables plaintext and symlink attacks

- Title: Predictable decrypt temp file enables plaintext and symlink attacks.
- Relevant code locations:
  - `pgp-mobile/src/streaming.rs:238-258` best-effort `secure_delete_file`, using `fs::metadata` and `OpenOptions::open`.
  - `pgp-mobile/src/streaming.rs:397-409` temp path generation and creation.
  - `pgp-mobile/src/streaming.rs:415-451` error cleanup, sync, and rename-to-final.
  - `Sources/Services/DecryptionService.swift:161-173` shipped file decrypt output artifact and Rust call.
  - `Sources/App/Common/AppTemporaryArtifactStore.swift:159-174` app-owned `decrypted/op-<UUID>` output directory creation and complete file protection.
  - `Sources/App/Decrypt/DecryptScreenModel.swift:394-423` shipped file decrypt flow.
- Mechanism-present status: Partially present. The exact original predictable `<output>.tmp` path is not present in current HEAD: the temp path now includes 8 random bytes rendered as hex. However, the Rust primitive still creates the temp file with `File::create`, not exclusive/no-follow semantics, and `secure_delete_file` still follows symlinks through `metadata` and `OpenOptions::open`. The temp file also contains plaintext before final payload authentication has fully completed; the hard-fail property depends on deleting it before final rename and on the directory not being observable by an attacker.
- Shipped reachability: Shipped but significantly narrowed. File decrypt is reachable from the Decrypt screen through `DecryptScreenModel`, `DecryptionService`, `PGPMessageOperationAdapter`, and `PgpEngine::decrypt_file_detailed`. The output path is not a user-selected external path: Swift creates an app-owned temporary artifact under `FileManager.temporaryDirectory/decrypted/op-<UUID>/...`, then the user exports later via `fileExporter`.
- Mitigations:
  - Random 64-bit suffix avoids the CSV-described fixed predictable `<output>.tmp` path.
  - Swift creates a per-operation UUID directory and applies complete file protection to the temp directory/output.
  - Rust deletes the temp file on read/write/cancel/auth/integrity errors and only renames after successful stream completion.
  - Rust and Swift tests cover tampered streaming decrypt cleanup and absence of final decrypted output.
- Evidence-real:
  - `File::create(&temp_path)` follows symlinks and truncates existing paths if an attacker can pre-create or race the random path.
  - `secure_delete_file` uses symlink-following metadata/open calls, so a hostile symlink at the temp path would make the overwrite target the link target before `remove_file` removes only the link.
  - The UniFFI/Rust primitive accepts arbitrary `output_path`, so future or non-current callers could place output in a shared attacker-writable directory.
- Evidence-false-positive:
  - The path is no longer predictably `format!("{output_path}.tmp")`; it is `"{output_path}.{hex_suffix}.tmp"`.
  - Current shipped Swift reachability uses app-owned temporary artifact directories rather than caller-selected shared output directories.
  - AEAD/MDC hard-fail cleanup is implemented and covered by tests.
- Preliminary disposition: Partially real as a Rust primitive hardening gap, but the original predictable-temp-path claim is already mitigated in current HEAD and current shipped UI reachability is low-risk. Treat as defense-in-depth or latent unless another caller can choose attacker-writable output directories.
- Confidence: Medium-high.
- Open questions:
  - Should `decrypt_file_detailed` use an exclusive temp-file API (`create_new`, no-follow semantics, or a `tempfile`-style primitive) regardless of current Swift callers?
  - Should Rust set restrictive permissions/file protection before writing plaintext, rather than relying on Swift after completion?
  - Are there macOS deployment modes where another local process can observe the app temporary directory despite the current artifact-store layout?

## CA-34: Bad signatures no longer hard-fail verification

- Title: Bad signatures no longer hard-fail verification.
- Relevant code locations:
  - `pgp-mobile/src/verify.rs:24-68` cleartext verification returns `VerifyDetailedResult`, including `content`.
  - `pgp-mobile/src/verify.rs:87-95` `VerifyHelper::check` records signature results and returns `Ok(())`.
  - `pgp-mobile/src/streaming.rs:523-590` detached file verification returns a detailed bad result for verification failure.
  - `pgp-mobile/src/signature_details.rs:163-211` maps bad verification results to `SignatureStatus::Bad` / invalid summary state.
  - `Sources/Services/SigningService.swift:85-110` shipped Swift verification service.
  - `Sources/App/Sign/VerifyScreenModel.swift:282-315` shipped verify screen stores returned text/status.
  - `Sources/App/Common/DetailedSignatureSectionView.swift:8-68` and `Sources/App/Common/SignatureVerification+Presentation.swift:45-47` display invalid signature state.
- Mechanism-present status: Present as described at the mechanism level. Bad cleartext and detached signatures are modeled as non-throwing graded results, not as `Err(PgpError::BadSignature)`. Cleartext verification may return the cleartext content along with an invalid/bad status.
- Shipped reachability: Shipped. The Verify screen reaches these APIs through `SigningService`. Decrypt and password-message flows also use graded signature status, but payload authentication failures remain separate fatal decrypt errors.
- Mitigations:
  - Current product/architecture docs define verify helpers as graded-result APIs, not hard-fail APIs.
  - The UI renders invalid signatures with a red invalid status and the localized warning "Signature verification failed - content may have been modified".
  - Tests explicitly assert tampered cleartext and detached signatures return `Bad` as a graded result, not a throw, for both profiles.
  - Fatal parse/setup/I/O/cancellation errors still throw; successful parsing followed by cryptographic invalidity is represented in the result type.
- Evidence-real:
  - A caller that treats "no thrown error" as "valid signature" would accept tampered content.
  - The Swift signatures are still `async throws`, so the API shape alone does not force status inspection.
  - `verify_cleartext_detailed` returns `content: Some(content)` after reading even when the collected legacy status is `Bad`.
- Evidence-false-positive:
  - Current HEAD intentionally changed the contract to detailed graded verification. `docs/TDD.md` says successful parsing followed by crypto failure should stay in family-specific result or graded-status types.
  - `docs/ARCHITECTURE.md` labels `verify.rs` as "Cleartext verification helpers with graded results".
  - `docs/PRD.md` acceptance criteria says signature failure is communicated, while AEAD auth failure is the hard-fail/no-plaintext invariant.
  - Shipped UI uses the status to show invalid signature state; I found no shipped caller that treats non-throwing verification as valid without checking the returned verification result.
- Preliminary disposition: False positive against the current documented product contract, with a real API-ergonomics footgun for future callers. If maintainers want standalone verify to hard-fail, docs and tests need to change together.
- Confidence: High.
- Open questions:
  - Should the Swift service or result type make invalid-signature handling harder to ignore, for example by avoiding `throws`-like success/failure intuition or by adding helper properties?
  - Is the stale comment in `pgp-mobile/src/decrypt.rs:304-311` claiming standalone verify hard-fails misleading enough to fix separately?

## CA-39: Unbounded SKESK S2K can exhaust memory

- Title: Unbounded SKESK S2K can exhaust memory.
- Relevant code locations:
  - `pgp-mobile/src/password.rs:64-144` password decrypt loop over collected SKESKs.
  - `pgp-mobile/src/password.rs:213-260` unbounded SKESK collection before the encrypted container.
  - `pgp-mobile/src/password.rs:262-298` validation limited to packet version and supported symmetric/AEAD algorithms before `skesk.decrypt(password)`.
  - `pgp-mobile/src/decrypt.rs:223-248` full in-memory payload decrypt via `read_to_end`, with partial plaintext zeroized on error.
  - `Sources/Security/Argon2idMemoryGuard.swift:3-8` guard explicitly limited to passphrase-protected key import/unlock, not password-message decrypt.
  - `Sources/Services/PasswordMessageService.swift:58-64` Swift wrapper around password decrypt.
  - `Sources/App/AppContainer.swift:260-288` service graph instantiates `PasswordMessageService`.
- Mechanism-present status: Present. Current Rust collects all SKESK packets into an unbounded `Vec`, validates only outer algorithm support, and calls `skesk.decrypt(password)` for each candidate with no SKESK count limit, S2K memory preflight, or KDF work budget. `Argon2idMemoryGuard` is not applied to password/SKESK messages.
- Shipped reachability: Latent/service-only. The Rust API is exported through `PgpEngine::decrypt_with_password` and wrapped by `PGPMessageOperationAdapter`/`PasswordMessageService`, and it is covered by service/FFI tests. The shipped app has no route, screen model, or environment consumer for `PasswordMessageService`; docs explicitly mark password/SKESK messages as service-only and not exposed in shipped UI.
- Mitigations:
  - Unsupported symmetric/AEAD algorithms are rejected.
  - Payload authentication failure remains fatal and partial plaintext is zeroized before returning an error.
  - Current app-authored password messages use Sequoia's default S2K baseline in tests.
  - Shipped UI has no end-user path into password-message decrypt.
- Evidence-real:
  - `collect_message_context` pushes every SKESK until `SEIP` without a cap.
  - `derive_candidate` calls `skesk.decrypt(password)` directly; malicious Argon2id S2K parameters can force expensive allocations/work before any Swift memory guard runs.
  - Tests intentionally cover multiple SKESKs and fall-through to later candidates, confirming repeated candidate work is part of the current behavior.
- Evidence-false-positive:
  - This is availability-only and not currently shipped-reachable from user UI.
  - It does not weaken AEAD/MDC hard-fail behavior; tampered password messages still throw fatal auth/integrity errors without returning plaintext.
  - The separate key-import Argon2id guard is real but intentionally scoped outside this message-decrypt path.
- Preliminary disposition: Real at the Rust/FFI service layer, latent and not currently shipped-reachable. Fix before shipping any password-message route by bounding SKESK count and S2K/KDF memory/work.
- Confidence: High.
- Open questions:
  - What SKESK count and total KDF work budget should be accepted for interoperability?
  - Can Rust inspect SKESK S2K parameters cheaply enough to reject high-memory Argon2id before `skesk.decrypt(password)`?
  - Should the existing Swift `Argon2idMemoryGuard` be mirrored at the Rust boundary for message SKESKs, or should all password-message S2K policy live in Rust?
