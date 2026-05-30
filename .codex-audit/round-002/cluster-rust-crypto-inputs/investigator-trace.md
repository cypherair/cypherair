# Investigator Trace: cluster-rust-crypto-inputs

Current HEAD: `d075268f61154227b5ff8545bb53808cccfda66c`.

Apple docs lookup not available. I searched for an Apple/Xcode `DocumentationSearch`-style tool with `tool_search`; only general XcodeBuildMCP tools were exposed, not Apple documentation search.

## Finding Resolution

- `rg -n "CA-30|CA-34|CA-39|finding_url" docs/CODEX_SECURITY_REVIEW_INDEX.md codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - Index rows:
    - CA-30 -> `https://chatgpt.com/codex/cloud/security/findings/536baf654b288191b275f2c4d4b9d32a`
    - CA-34 -> `https://chatgpt.com/codex/cloud/security/findings/f1b869820c4c819195b018e0027298ba`
    - CA-39 -> `https://chatgpt.com/codex/cloud/security/findings/e7a2686e638c8191876364539797073c`
- `rg -n "536baf654b288191b275f2c4d4b9d32a|f1b869820c4c819195b018e0027298ba|e7a2686e638c8191876364539797073c" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - Matched CSV rows by `finding_url`, not by inferred line number.
  - CA-30 CSV title: "Predictable decrypt temp file enables plaintext and symlink attacks"; relevant path `pgp-mobile/src/streaming.rs`.
  - CA-34 CSV title: "Bad signatures no longer hard-fail verification"; relevant paths `pgp-mobile/src/verify.rs | pgp-mobile/src/decrypt.rs`.
  - CA-39 CSV title: "Unbounded SKESK S2K can exhaust memory"; relevant paths `Sources/Services/PasswordMessageService.swift | pgp-mobile/src/password.rs | Sources/Security/Argon2idMemoryGuard.swift`.

## Commands And Files Inspected

- Discovery:
  - `rg --files | rg "^(pgp-mobile/src/(streaming|verify|decrypt|password)\\.rs|Sources/Services/PasswordMessageService\\.swift|Sources/Security/Argon2idMemoryGuard\\.swift|...)$"`
  - `git rev-parse HEAD`
  - `git status --short`
- Rust streaming:
  - `rg -n "decrypt_file|tmp|temp|cleanup|OpenOptions|File::create|rename|create_new|stream" pgp-mobile/src/streaming.rs`
  - `nl -ba pgp-mobile/src/streaming.rs | sed -n '1,80p'`
  - `nl -ba pgp-mobile/src/streaming.rs | sed -n '230,460p'`
  - `nl -ba pgp-mobile/src/streaming.rs | sed -n '460,590p'`
- Verify/decrypt:
  - `rg -n "VerifyHelper|SignatureStatus|GoodChecksum|Bad|Missing|check\\(|verify_cleartext|verify_detached|VerifierBuilder|DetachedVerifierBuilder|BadSignature" pgp-mobile/src/verify.rs pgp-mobile/src/decrypt.rs`
  - `nl -ba pgp-mobile/src/verify.rs | sed -n '1,150p'`
  - `nl -ba pgp-mobile/src/decrypt.rs | sed -n '160,278p'`
  - `nl -ba pgp-mobile/src/decrypt.rs | sed -n '280,360p'`
  - `nl -ba pgp-mobile/src/decrypt.rs | sed -n '440,535p'`
  - `nl -ba pgp-mobile/src/signature_details.rs | sed -n '1,330p'`
- Password/SKESK:
  - `rg -n "SKESK|skesk|S2K|Argon2|decrypt\\(|decrypt_password|password|symmetric|AEAD|Argon2idMemoryGuard|memory" pgp-mobile/src/password.rs Sources/Services/PasswordMessageService.swift Sources/Security/Argon2idMemoryGuard.swift`
  - `nl -ba pgp-mobile/src/password.rs | sed -n '1,170p'`
  - `nl -ba pgp-mobile/src/password.rs | sed -n '170,370p'`
  - `nl -ba Sources/Services/PasswordMessageService.swift | sed -n '1,140p'`
  - `nl -ba Sources/Security/Argon2idMemoryGuard.swift | sed -n '1,120p'`
- FFI/Swift service reachability:
  - `rg -n "verify_cleartext_detailed|verify_cleartext|verify_detached|verify_file|decrypt_file_detailed|decrypt_file\\(|encrypt_file\\(|PasswordMessageService|decryptMessageDetailed|decrypt_message|decryptBinary|passwordMessageService|passwordService|Password" Sources pgp-mobile/src bindings PgpMobile Sources/PgpMobile`
  - `nl -ba pgp-mobile/src/lib.rs | sed -n '200,315p'`
  - `nl -ba pgp-mobile/src/lib.rs | sed -n '440,515p'`
  - `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '1,465p'`
  - `nl -ba Sources/Services/FFI/PGPMessageResultMapper.swift | sed -n '1,230p'`
  - `nl -ba Sources/Services/DecryptionService.swift | sed -n '1,260p'`
  - `nl -ba Sources/Services/SigningService.swift | sed -n '1,125p'`
  - `rg -n "@Environment\\(PasswordMessageService|passwordMessageService|PasswordMessageService" Sources/App Sources/Services Sources/Models`
- UI reachability:
  - `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '1,220p'`
  - `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '340,430p'`
  - `nl -ba Sources/App/Decrypt/DecryptView.swift | sed -n '240,315p'`
  - `nl -ba Sources/App/Sign/VerifyScreenModel.swift | sed -n '1,460p'`
  - `nl -ba Sources/App/Sign/VerifyView.swift | sed -n '1,260p'`
  - `nl -ba Sources/App/Common/DetailedSignatureSectionView.swift | sed -n '1,120p'`
  - `nl -ba Sources/App/Common/SignatureVerification+Presentation.swift | sed -n '1,80p'`
- Temporary artifact storage:
  - `rg -n "struct AppTemporaryArtifactStore|class AppTemporaryArtifactStore|makeDecryptedArtifact|applyAndVerifyCompleteProtection|AppTemporaryArtifact" Sources`
  - `nl -ba Sources/App/Common/AppTemporaryArtifactStore.swift | sed -n '1,220p'`
  - `nl -ba Sources/App/Common/AppTemporaryArtifact.swift | sed -n '1,80p'`
  - `nl -ba Sources/App/Common/TemporaryFileOutput.swift | sed -n '1,120p'`
- Docs:
  - `nl -ba docs/ARCHITECTURE.md | sed -n '80,135p'`
  - `nl -ba docs/ARCHITECTURE.md | sed -n '306,315p'`
  - `nl -ba docs/PRD.md | sed -n '108,116p'`
  - `nl -ba docs/PRD.md | sed -n '175,190p'`
  - `nl -ba docs/PRD.md | sed -n '270,285p'`
  - `nl -ba docs/PRD.md | sed -n '312,320p'`
  - `nl -ba docs/TDD.md | sed -n '266,276p'`
  - `nl -ba docs/CODEX_SECURITY_REVIEW.md | sed -n '118,125p'`
  - `nl -ba docs/SECURITY.md | sed -n '120,135p'`
  - `nl -ba docs/SECURITY.md | sed -n '374,390p'`
- Tests/evidence searches:
  - `rg -n "random suffix|M3 fix|tmp|decrypt_file_detailed|secure_delete|File::create|create_new|passwordRejected|SKESK|s2k|VerifyLike|bad signature|bad.*signature|tamper|verify_cleartext|verify_detached" pgp-mobile/tests pgp-mobile/src -g '*.rs'`
  - `rg -n "PasswordMessageService|decryptWithPassword|passwordRejected|SKESK|password-message|password message|verifyCleartextDetailed|verifyDetachedStreamingDetailed|decryptFileStreamingDetailed" Tests Sources -g '*.swift'`
  - `nl -ba pgp-mobile/tests/security_signature_policy_tests.rs | sed -n '1,95p'`
  - `nl -ba pgp-mobile/tests/security_signature_policy_tests.rs | sed -n '269,322p'`
  - `nl -ba pgp-mobile/tests/detailed_signature_tests.rs | sed -n '270,350p'`
  - `nl -ba pgp-mobile/tests/streaming_resilience_tests.rs | sed -n '60,190p'`
  - `nl -ba Tests/ServiceTests/DecryptionServiceTests.swift | sed -n '1030,1195p'`
  - `nl -ba pgp-mobile/tests/password_message_tests.rs | sed -n '500,630p'`
  - `nl -ba Tests/ServiceTests/PasswordMessageServiceTests.swift | sed -n '1,120p'`
  - `nl -ba Tests/ServiceTests/PasswordMessageServiceTests.swift | sed -n '170,250p'`
  - `nl -ba Tests/FFIIntegrationTests/FFIIntegrationTests.swift | sed -n '287,430p'`

## Evidence Snippets

- CA-30:
  - `pgp-mobile/src/streaming.rs:397-405`: random 8-byte suffix, temp path `"{output_path}.{hex_suffix}.tmp"`.
  - `pgp-mobile/src/streaming.rs:407-409`: temp opened with `File::create`.
  - `pgp-mobile/src/streaming.rs:238-258`: cleanup follows `fs::metadata` and `OpenOptions::new().write(true).open(path)`.
  - `Sources/App/Common/AppTemporaryArtifactStore.swift:159-168`: output artifact lives in `decrypted/op-<UUID>/...`.
  - `Sources/Services/DecryptionService.swift:161-173`: shipped file decrypt calls Rust with the artifact path, then applies complete protection.
- CA-34:
  - `pgp-mobile/src/verify.rs:92-95`: `VerifyHelper::check` observes structure and returns `Ok(())`.
  - `pgp-mobile/src/verify.rs:52-68`: cleartext verification reads content and returns `content: Some(content)`.
  - `pgp-mobile/src/streaming.rs:566-578`: detached verify runtime verification failure returns `FileVerifyDetailedResult { legacy_status: Bad, ... }`.
  - `docs/TDD.md:273`: crypto invalidity after successful parse should stay in family-specific result or graded-status types.
  - `pgp-mobile/tests/security_signature_policy_tests.rs:57-64` and `:287-294`: tampered cleartext expected to return a graded `Bad` result, not throw.
- CA-39:
  - `pgp-mobile/src/password.rs:213-260`: `collect_message_context` pushes every `Packet::SKESK(skesk)` into an unbounded vector before `SEIP`.
  - `pgp-mobile/src/password.rs:262-298`: `validate_skesk` checks packet version and algorithms; `derive_candidate` then calls `skesk.decrypt(password)`.
  - `Sources/Security/Argon2idMemoryGuard.swift:3-8`: guard is only for passphrase-protected key import/unlock, not message decrypt.
  - `docs/ARCHITECTURE.md:115-132` and `docs/PRD.md:183,279`: password/SKESK message handling is service-only and not exposed in shipped UI.
  - `pgp-mobile/tests/password_message_tests.rs:505-521` and `:575-589`: multiple SKESKs and fall-through to later candidates are intentional current behavior.

No tests were run for this investigation; this was a read-only code and documentation audit plus the two requested report files.
