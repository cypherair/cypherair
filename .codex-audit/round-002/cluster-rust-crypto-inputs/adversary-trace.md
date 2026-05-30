# Round 2 Adversary Trace: cluster-rust-crypto-inputs

Current HEAD inspected: `d075268f61154227b5ff8545bb53808cccfda66c`.

I did not read `investigator-trace.md`. Its filename appeared in directory listings, but I did not inspect its contents.

## Required Sources Read

- `docs/CODEX_SECURITY_REVIEW_INDEX.md`
  - `nl -ba docs/CODEX_SECURITY_REVIEW_INDEX.md | sed -n '64,79p'`
  - CA-30 row: line 68.
  - CA-34 row: line 72.
  - CA-39 row: line 77.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - `rg -n "Predictable decrypt temp file|Bad signatures no longer hard-fail|Unbounded SKESK S2K" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - CA-30 source finding: line 31.
  - CA-34 source finding: line 35.
  - CA-39 source finding: line 40.
- `.codex-audit/round-002/cluster-rust-crypto-inputs/investigator.md`
  - `sed -n '1,260p' .codex-audit/round-002/cluster-rust-crypto-inputs/investigator.md`
  - `nl -ba .codex-audit/round-002/cluster-rust-crypto-inputs/investigator.md | sed -n '1,115p'`
  - CA-30 investigator section: lines 5-35.
  - CA-34 investigator section: lines 37-68.
  - CA-39 investigator section: lines 70-101.

## Repository State Commands

- `pwd && ls -la .codex-audit/round-002/cluster-rust-crypto-inputs && sed -n '1,220p' docs/CODEX_SECURITY_REVIEW_INDEX.md`
- `git rev-parse HEAD`
  - Output: `d075268f61154227b5ff8545bb53808cccfda66c`.
- `git status --short`
  - Output was empty before writing adversary files.
- `find .codex-audit/round-002/cluster-rust-crypto-inputs -maxdepth 1 -type f -print | sort`
  - Used only to confirm existing files; did not read `investigator-trace.md`.

## CA-30 Files And Line References

- `pgp-mobile/src/streaming.rs`
  - `nl -ba pgp-mobile/src/streaming.rs | sed -n '220,470p'`
  - `secure_delete_file` uses `fs::metadata`, `OpenOptions::open`, and `fs::remove_file`: lines 238-258.
  - `decrypt_file_detailed` documents temp-file AEAD hard-fail intent: lines 338-344.
  - Random 8-byte temp suffix generation: lines 397-405.
  - Temp file creation with `File::create`: lines 407-409.
  - Error cleanup on copy failure: lines 415-430.
  - Sync, close, helper extraction, and rename to final output: lines 433-451.
- `pgp-mobile/src/lib.rs`
  - `nl -ba pgp-mobile/src/lib.rs | sed -n '440,530p'`
  - UniFFI-exposed `decrypt_file_detailed` accepts caller-supplied `input_path` and `output_path`: lines 468-486.
- `Sources/Services/DecryptionService.swift`
  - `nl -ba Sources/Services/DecryptionService.swift | sed -n '1,240p'`
  - File decrypt creates app temporary artifact and passes `outputArtifact.fileURL.path` to Rust: lines 159-173.
  - Cleanup on Rust/Swift errors: lines 174-179.
- `Sources/App/Common/AppTemporaryArtifactStore.swift`
  - `nl -ba Sources/App/Common/AppTemporaryArtifactStore.swift | sed -n '1,260p'`
  - `temporaryDirectory` source: lines 17-30.
  - `makeDecryptedArtifact`: lines 38-42.
  - Complete file protection helper: lines 71-85.
  - Per-operation UUID directory and sanitized output filename: lines 159-169.
  - Protected directory creation: lines 172-175.
  - Filename sanitization through last path component: lines 251-259.
- `Sources/App/Common/AppTemporaryArtifact.swift`
  - `nl -ba Sources/App/Common/AppTemporaryArtifact.swift | sed -n '1,120p'`
  - Artifact cleanup removes owner directory when present: lines 12-18.
- `Sources/App/Common/TemporaryFileOutput.swift`
  - `nl -ba Sources/App/Common/TemporaryFileOutput.swift | sed -n '1,80p'`
  - Temporary output cleanup wrapper: lines 7-26.
  - `AppTemporaryArtifact` bridges to cleanup of owner directory: lines 29-34.
- `Sources/App/Decrypt/DecryptScreenModel.swift`
  - `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '80,170p'`
  - File parse uses security-scoped read access: lines 91-106.
  - File decrypt uses security-scoped access, then calls `DecryptionService.decryptFileStreamingDetailed`: lines 162-184.
  - `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '340,470p'`
  - Shipped file decrypt action adopts temporary output only after success: lines 394-423.
  - `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '520,620p'`
  - File selection commits selected input URL only; output remains service-owned: lines 533-563.
  - Temporary decrypted output cleanup/adoption: lines 593-603.
- `Sources/App/Decrypt/DecryptView.swift`
  - `nl -ba Sources/App/Decrypt/DecryptView.swift | sed -n '1,260p'`
  - File decrypt UI path and export button: lines 191-245.
  - Detailed signature display after decrypt: lines 247-253.
  - `nl -ba Sources/App/Decrypt/DecryptView.swift | sed -n '260,340p'`
  - File importer and file exporter surfaces: lines 261-310.
- `Sources/App/Common/SecurityScopedFileAccess.swift`
  - `nl -ba Sources/App/Common/SecurityScopedFileAccess.swift | sed -n '1,120p'`
  - Security-scoped access wrappers: lines 21-55.
- `CypherAir.entitlements`
  - `nl -ba CypherAir.entitlements | sed -n '1,160p'`
  - iOS family entitlement source inspected for app hardening keys: lines 5-20.
- `CypherAirMacOS.entitlements`
  - `nl -ba CypherAirMacOS.entitlements | sed -n '1,180p'`
  - macOS app sandbox and user-selected read-write file entitlement: lines 25-28.
- `pgp-mobile/tests/streaming_resilience_tests.rs`
  - `nl -ba pgp-mobile/tests/streaming_resilience_tests.rs | sed -n '1,260p'`
  - Tampered Profile A file decrypt asserts no final output and no `.tmp` files: lines 66-113.
  - Tampered Profile B file decrypt asserts no final output: lines 116-152.
  - Tampered streaming decrypt returns non-FileIoError for Profile B/A: lines 155-240.

## CA-34 Files And Line References

- `pgp-mobile/src/verify.rs`
  - `nl -ba pgp-mobile/src/verify.rs | sed -n '1,180p'`
  - `verify_cleartext_detailed` returns `VerifyDetailedResult` with optional content: lines 23-69.
  - Setup verification errors become empty detailed `Bad`/`Expired` result: lines 38-49.
  - `VerifyHelper::check` observes structure and returns `Ok(())`: lines 87-95.
- `pgp-mobile/src/decrypt.rs`
  - `nl -ba pgp-mobile/src/decrypt.rs | sed -n '1,360p'`
  - `SignatureStatus` enum includes `Bad`: lines 14-28.
  - In-memory decrypt zeroizes partial plaintext and returns error on read/decrypt failure: lines 238-244.
  - Stale design note claiming standalone verify hard-fails: lines 302-311.
  - Decrypt verification helper also records graded status: lines 317-320.
- `pgp-mobile/src/streaming.rs`
  - `nl -ba pgp-mobile/src/streaming.rs | sed -n '500,620p'`
  - Detached file verify returns `Bad` graded result for verification failure after nonfatal reader error classification: lines 523-592.
- `pgp-mobile/src/signature_details.rs`
  - `nl -ba pgp-mobile/src/signature_details.rs | sed -n '1,260p'`
  - Detailed result record includes content: lines 36-45.
  - Collector records `Bad`/`Invalid` states: lines 163-211.
  - `BadSignature` maps to `DetailedSignatureStatus::Bad` and `SignatureVerificationState::Invalid`: lines 249-257.
- `Sources/Services/SigningService.swift`
  - `nl -ba Sources/Services/SigningService.swift | sed -n '1,170p'`
  - Shipped verification service returns detailed result: lines 79-111.
- `Sources/Services/FFI/PGPMessageOperationAdapter.swift`
  - `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '1,240p'`
  - Cleartext verification maps Rust result to detailed Swift result: lines 226-240.
  - `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '240,520p'`
  - Detached file verification maps Rust result to detailed Swift result: lines 245-267.
  - FFI calls for `verifyCleartextDetailed` and `verifyDetachedFileDetailed`: lines 431-457.
- `Sources/Services/FFI/PGPMessageResultMapper.swift`
  - `nl -ba Sources/Services/FFI/PGPMessageResultMapper.swift | sed -n '1,180p'`
  - Verify result maps content and detailed status: lines 73-90.
  - Detailed status and contact context mapping: lines 108-158.
- `Sources/App/Sign/VerifyScreenModel.swift`
  - `nl -ba Sources/App/Sign/VerifyScreenModel.swift | sed -n '240,340p'`
  - Verify actions store content and detailed verification, not just success: lines 273-315.
- `Sources/App/Common/DetailedSignatureSectionView.swift`
  - `nl -ba Sources/App/Common/DetailedSignatureSectionView.swift | sed -n '1,150p'`
  - Detailed signature status rows are rendered: lines 8-68.
  - Entry status mapping includes `.bad`: lines 83-95.
- `Sources/App/Common/SignatureVerification+Presentation.swift`
  - `nl -ba Sources/App/Common/SignatureVerification+Presentation.swift | sed -n '1,110p'`
  - Invalid signature uses red icon and warning text: lines 16-24 and 45-47.
- `Sources/Models/DetailedSignatureVerification.swift`
  - `nl -ba Sources/Models/DetailedSignatureVerification.swift | sed -n '1,170p'`
  - Detailed verification model maps bad legacy/entry status to `.invalid`: lines 90-117.
- `Sources/Services/SelfTestService.swift`
  - `nl -ba Sources/Services/SelfTestService.swift | sed -n '220,275p'`
  - Self-test explicitly checks `legacyStatus == .valid` after decrypt and verify: lines 242-265.
- Tests
  - `nl -ba pgp-mobile/tests/security_signature_policy_tests.rs | sed -n '35,95p;265,320p'`
    - Tampered cleartext/detached tests expect graded `Bad`, not throw: lines 39-88 and 268-319.
  - `nl -ba pgp-mobile/tests/detailed_signature_tests.rs | sed -n '250,320p'`
    - Detached tampered runtime data reports `Bad`/`Invalid`: lines 273-288.
  - `nl -ba Tests/ServiceTests/SigningServiceTests.swift | sed -n '220,320p'`
    - Swift service detached tamper tests expect `.bad`: lines 266-314.
  - `nl -ba Tests/FFIIntegrationTests/FFIIntegrationTests.swift | sed -n '930,980p;1298,1345p'`
    - FFI cleartext/detached tamper tests expect `.bad`: lines 942-972 and 1305-1341.
- Docs
  - `nl -ba docs/ARCHITECTURE.md | sed -n '80,140p'`
    - Service ownership and shipped richer signature result owner: lines 84-96 and 113-132.
  - `nl -ba docs/ARCHITECTURE.md | sed -n '300,390p'`
    - Rust file map says `verify.rs` uses graded results: lines 308-314.
    - Decrypt hard-fail is payload-auth specific: lines 354-388.
  - `nl -ba docs/TDD.md | sed -n '260,292p'`
    - Parse/setup failure vs crypto invalidity contract: lines 267-278.
    - Current capability families show richer signature results shipped: lines 279-289.
  - `nl -ba docs/PRD.md | sed -n '104,120p;176,188p;270,282p;310,320p'`
    - AEAD hard-fail rule: lines 110-116.
    - Signing/verification graded results and password service-only notes: lines 176-183 and 273-279.
    - Acceptance criteria distinguishes AEAD hard-fail from signature failure communication: lines 313-317.

## CA-39 Files And Line References

- `pgp-mobile/src/password.rs`
  - `nl -ba pgp-mobile/src/password.rs | sed -n '1,340p'`
  - Password decrypt normalizes message and collects context: lines 64-72.
  - Iterates every collected SKESK candidate: lines 84-129.
  - `PasswordMessageContext` stores `Vec<SKESK>`: lines 208-211.
  - `collect_message_context` pushes every SKESK until `SEIP`: lines 213-259.
  - `validate_skesk` only validates versions and supported symmetric/AEAD algorithms: lines 262-291.
  - `derive_candidate` calls `skesk.decrypt(password)` without count or S2K budget: lines 293-327.
- `pgp-mobile/src/decrypt.rs`
  - `nl -ba pgp-mobile/src/decrypt.rs | sed -n '1,360p'`
  - Full payload decrypt reads to end and zeroizes partial plaintext on error: lines 223-248.
  - Fixed session key password path calls shared decrypt helper: lines 250-276.
- `pgp-mobile/src/lib.rs`
  - `nl -ba pgp-mobile/src/lib.rs | sed -n '180,310p'`
  - UniFFI-exposed `decrypt_with_password`: lines 282-291.
- `Sources/Services/PasswordMessageService.swift`
  - `nl -ba Sources/Services/PasswordMessageService.swift | sed -n '1,220p'`
  - Service is separate from recipient-key decrypt: lines 3-9.
  - Decrypt wrapper calls `messageAdapter.decryptWithPassword`: lines 58-65.
- `Sources/Services/FFI/PGPMessageOperationAdapter.swift`
  - `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '1,240p'`
  - Swift adapter password decrypt result mapping: lines 172-190.
  - `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '240,520p'`
  - FFI call to `engine.decryptWithPassword`: lines 394-406.
- `Sources/Security/Argon2idMemoryGuard.swift`
  - `nl -ba Sources/Security/Argon2idMemoryGuard.swift | sed -n '1,180p'`
  - Guard explicitly limited to key import, not message decrypt/signing: lines 3-8.
  - Memory validation logic: lines 21-75.
- `Sources/Services/KeyManagement/KeyProvisioningService.swift`
  - `nl -ba Sources/Services/KeyManagement/KeyProvisioningService.swift | sed -n '90,130p'`
  - `Argon2idMemoryGuard` is wired into key import before `importSecretKey`: lines 100-119.
- `Sources/App/AppContainer.swift`
  - `nl -ba Sources/App/AppContainer.swift | sed -n '230,310p'`
  - `PasswordMessageService` instantiated in PGP service graph: lines 260-288.
  - `nl -ba Sources/App/AppContainer.swift | sed -n '590,635p;900,930p'`
  - Service graph stored in default and UI-test containers: lines 610-620 and 912-922.
- App route/search reachability
  - `rg -n "enum AppRoute|case .*password|PasswordMessage|passwordMessageService|DecryptView|VerifyView|SignView" Sources/App Sources/Models`
  - `nl -ba Sources/App/AppRoute.swift | sed -n '1,180p'`
  - `AppRoute` has encrypt/decrypt/sign/verify but no password-message route: lines 27-33.
- Tests
  - `nl -ba pgp-mobile/tests/password_message_tests.rs | sed -n '472,620p'`
  - Multi-password message uses multiple SKESKs and accepts second password: lines 504-522.
  - Multi-SKESK fall-through tests: lines 554-608.
  - Tampered password-message auth/integrity tests: lines 538-550 and 611-620.
- Docs
  - `nl -ba docs/ARCHITECTURE.md | sed -n '80,140p'`
    - PasswordMessageService responsibility and service-only current owner: lines 84-88 and 113-132.
  - `nl -ba docs/TDD.md | sed -n '260,292p'`
    - Password/SKESK current state is service-only with no shipped route/screen-model owner: lines 279-286.
  - `nl -ba docs/PRD.md | sed -n '104,120p;176,188p;270,282p;310,320p'`
    - Password/SKESK not shipped UI: lines 183 and 279.
  - `nl -ba docs/CODEX_SECURITY_REVIEW.md | sed -n '112,128p'`
    - Prior CA-21 assessment documents adjacent SKESK fallback issue as real-low latent and service-only: lines 118-124.

## Searches

- `rg -n "CA-30|CA-34|CA-39|crypto-inputs|rust-crypto" codex-security-findings-2026-05-29T13-11-03.346Z.csv docs/CODEX_SECURITY_REVIEW_INDEX.md .codex-audit/round-002/cluster-rust-crypto-inputs/investigator.md`
- `rg -n "PasswordMessageService|decryptWithPassword|encryptWithPassword|decrypt_with_password|passwordMessage|PasswordMessage|PasswordDecrypt|SKESK|skesk" Sources Tests pgp-mobile docs --glob '!**/investigator-trace.md'`
- `rg -n "hard-fail|hard fail|graded|signature failure|Signature verification|bad signature|verify helpers|VerifyLike|AEAD|MDC|Password / SKESK|service-only|Service-only" docs/ARCHITECTURE.md docs/SECURITY.md docs/PRD.md docs/TDD.md docs/CODEX_SECURITY_REVIEW.md docs/TESTING.md`
- `rg -n "tamper|tampered|Bad|bad signature|SignatureStatus::Bad|passwordRejected|multi_skesk|auth failure|tmp|cleanup|decrypted output|file decrypt" pgp-mobile/tests Tests/ServiceTests Tests/FFIIntegrationTests --glob '!**/investigator-trace.md'`
- `rg -n "temporaryDirectory|makeDecryptedArtifact|makeOperationArtifact|decryptedOutputFilename|applyAndVerifyCompleteProtection|fileExporter|securityScoped|startAccessingSecurityScopedResource|selectedFileURL|fileImporter" Sources/App Sources/Services Tests/ServiceTests/StreamingServiceTests.swift Tests/ServiceTests/DecryptScreenModelTests.swift`
- `rg -n "verifyCleartextDetailed|verifyDetachedStreamingDetailed|verifyDetachedFileDetailed|legacyStatus|summaryState" Sources Tests/ServiceTests --glob '!Sources/PgpMobile/pgp_mobile.swift'`
- `rg -n "decrypt_file_detailed|encrypt_file|verify_detached_file_detailed|match_recipients_from_file" pgp-mobile/src/lib.rs Sources/PgpMobile/pgp_mobile.swift Sources/Services/FFI/PGPMessageOperationAdapter.swift`
- `rg -n "Argon2idMemoryGuard|parseS2kParams|parse_s2k_params|s2k" Sources/Services Sources/App Sources/Security/Argon2idMemoryGuard.swift`

## Tests

No tests were run. This task was an adversarial review/writeup only, with no repository code changes.
