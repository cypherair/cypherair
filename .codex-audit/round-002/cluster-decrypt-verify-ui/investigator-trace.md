# Investigator Trace: cluster-decrypt-verify-ui

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`
HEAD: `d075268f61154227b5ff8545bb53808cccfda66c`
Branch: `docs/codex-security-review-tracking`

## CA-ID and CSV resolution

- Read `docs/CODEX_SECURITY_REVIEW_INDEX.md` with:
  - `rg -n "CA-(20|29|33|42)|finding_url|cluster-decrypt-verify-ui" docs/CODEX_SECURITY_REVIEW_INDEX.md`
- Matched each index `finding_url` to the CSV by exact URL with:
  - `rg -n "4b57512bd5ec819194bff3e78091181a|a2a7f41bec048191b18443eaa38268e6|ffff6cd467088191ab32b29040dd40ab|3f03eebb98448191b26dbb3af9dcafa0" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- URL mapping:
  - CA-20: `https://chatgpt.com/codex/cloud/security/findings/4b57512bd5ec819194bff3e78091181a`
  - CA-29: `https://chatgpt.com/codex/cloud/security/findings/a2a7f41bec048191b18443eaa38268e6`
  - CA-33: `https://chatgpt.com/codex/cloud/security/findings/ffff6cd467088191ab32b29040dd40ab`
  - CA-42: `https://chatgpt.com/codex/cloud/security/findings/3f03eebb98448191b26dbb3af9dcafa0`

## Apple docs lookup

- Apple platform semantics matter for CA-42 because `.id` view identity and text-editor focus/selection behavior are SwiftUI concerns.
- Tool discovery command used: `tool_search` query `XcodeBuildMCP DocumentationSearch Apple developer documentation SwiftUI id view identity`.
- Result exposed XcodeBuildMCP simulator/UI tools only; no Apple/Xcode documentation lookup tool or `DocumentationSearch` was available.
- Apple docs lookup not available.

## Files and evidence inspected

- Repo state:
  - `git status --short` returned clean before writing audit artifacts.
  - `ls -la .codex-audit/round-002/cluster-decrypt-verify-ui` showed the output directory empty before writing.
- Broad code/docs searches:
  - `rg -n "DetailedSignatureSection|signatures|signatureVerification|decryptedFileURL|textInputSectionEpoch|invalidate|decryptText|decryptFile|removeDecrypted|cleanup|decrypted" Sources/App Sources/Services pgp-mobile/src/signature_details.rs`
  - `rg -n "decrypted file|temporary|cleanup|PRD|plaintext|signature" docs/PRD.md docs/SECURITY.md docs/ARCHITECTURE.md docs/TESTING.md`
  - `rg --files Sources/App Sources/Services pgp-mobile/src | rg "DetailedSignatureSectionView|VerifyView|DecryptView|VerifyScreenModel|DecryptScreenModel|DecryptionService|signature_details"`
  - `rg -n "textInputSectionEpoch|detailedSignatureVerification|decryptedFileOutput|handleDisappear|handleContentClearGenerationChange|activeDetailedVerification|signatureEntries|DetailedSignatureSectionView|cleanupTemporaryArtifacts" Tests Sources -g '*.swift'`

## CA-20 evidence

- `pgp-mobile/src/signature_details.rs:87-109`: `SignatureCollector` owns `signatures: Vec<DetailedSignatureEntry>` initialized as `Vec::new()`.
- `pgp-mobile/src/signature_details.rs:112-123`: `observe_structure` iterates every signature group/result.
- `pgp-mobile/src/signature_details.rs:163-166`: `observe_result` creates an entry and pushes it unconditionally.
- `pgp-mobile/src/signature_details.rs:140-151`: accessors clone/return the full `Vec`.
- `Sources/Services/FFI/PGPMessageResultMapper.swift:126-158`: `signatures.map` maps every FFI entry into app entries.
- `Sources/Models/DetailedSignatureVerification.swift:52-75`: app model stores `signatures: [Entry]` with no cap.
- `Sources/App/Common/DetailedSignatureSectionView.swift:44-56`: `verification.signatures.map(...)` and signer filtering are full-array operations.
- `Sources/App/Common/DetailedSignatureSectionView.swift:14` and `:30`: `ForEach(Array(...enumerated()))` eagerly copies enumerated collections for rendering.
- `Sources/App/Decrypt/DecryptView.swift:247-253` and `Sources/App/Sign/VerifyView.swift:123-129`: detailed signature section is rendered in shipped decrypt/verify routes.
- `docs/TESTING.md:464-468`: richer-signature validation expects preservation of every observed signature result.

## CA-29 evidence

- `Sources/App/Decrypt/DecryptView.swift:312-316`: `onDisappear` calls `model.handleDisappear()`, content-clear calls `model.handleContentClearGenerationChange()`.
- `Sources/App/Decrypt/DecryptScreenModel.swift:246-256`: `handleDisappear()` clears state and current temp output but does not cancel `operation`.
- `Sources/App/Decrypt/DecryptScreenModel.swift:258-266`: content clear records the event, calls `operation.cancelAndInvalidate()`, then clears transient input.
- `Sources/App/Common/OperationController.swift:63-81`: `cancel()` and `cancelAndInvalidate()` cancel current task/progress; only content clear uses the invalidate path here.
- `Sources/App/Decrypt/DecryptScreenModel.swift:394-423`: file decrypt awaits service result, sets `pendingOutput`, defers cleanup, checks cancellation, then adopts output and publishes verification.
- `Sources/App/Decrypt/DecryptScreenModel.swift:593-602`: temp output cleanup and adoption are explicit.
- `Sources/App/Common/TemporaryFileOutput.swift:24-34` and `Sources/App/Common/AppTemporaryArtifact.swift:12-18`: cleanup is method-based; no automatic destructor cleanup found.
- `Sources/Services/DecryptionService.swift:161-185`: streaming decrypt creates decrypted artifact, calls FFI, verifies complete protection, cleans artifact on thrown errors.
- `pgp-mobile/src/streaming.rs:338-343`: Rust comment states temp-first behavior and no partial plaintext on errors.
- `pgp-mobile/src/streaming.rs:397-430`: Rust writes to random `.tmp`, deletes it on copy/read/write/cancel error.
- `pgp-mobile/src/streaming.rs:445-461`: final output appears after rename and result construction.
- `Tests/ServiceTests/DecryptScreenModelTests.swift:613-724`: tests cover manual cancel and cancel-after-service-success cleanup.
- `Tests/ServiceTests/DecryptScreenModelTests.swift:727-787`: test distinguishes content-clear and disappear cleanup scopes but does not cover in-flight disappear cancellation.
- `docs/PERSISTED_STATE_INVENTORY.md:74`: `tmp/decrypted/op-<UUID>/...` classified as `ephemeral-with-cleanup`.
- `Sources/App/AppStartupCoordinator.swift:95-131`: startup invokes temporary artifact cleanup.

## CA-33 evidence

- `Sources/App/Decrypt/DecryptScreenModel.swift:48-57`: mode, text result, shared detailed verification, and file URL are independent fields.
- `Sources/App/Decrypt/DecryptScreenModel.swift:369-385`: `decryptText()` sets `decryptedText` and replaces shared detailed verification.
- `Sources/App/Decrypt/DecryptScreenModel.swift:394-423`: `decryptFile()` adopts file output and replaces the same shared detailed verification.
- `Sources/App/Decrypt/DecryptScreenModel.swift:565-585`: text/file invalidation clears shared verification, but there is no `decryptMode` didSet or mode-change invalidation.
- `Sources/App/Decrypt/DecryptView.swift:133-145`: picker binds directly to `$model.decryptMode`.
- `Sources/App/Decrypt/DecryptView.swift:220-253`: text/file outputs are mode-gated; detailed signature section is outside result-specific blocks and rendered whenever shared verification exists.
- Counterexample for Verify:
  - `Sources/App/Sign/VerifyScreenModel.swift:41-42`: separate cleartext and detached detailed verification.
  - `Sources/App/Sign/VerifyScreenModel.swift:123-129`: `activeDetailedVerification` selects by active mode.

## CA-42 evidence

- `Sources/App/Decrypt/DecryptView.swift:340-368`: text input section has `.id(model.textInputSectionEpoch)`.
- `Sources/App/Decrypt/DecryptScreenModel.swift:287-292`: `setCiphertextInput` runs on text edits and calls `invalidateTextInputState()`.
- `Sources/App/Decrypt/DecryptScreenModel.swift:565-570`: invalidation clears text result/signature/phase1 and increments `textInputSectionEpoch`.
- `Sources/App/Sign/VerifyView.swift:185-211`: cleartext signed input section has `.id(model.textInputSectionEpoch)`.
- `Sources/App/Sign/VerifyScreenModel.swift:167-175`: `setSignedInput` runs on text edits and calls `invalidateCleartextVerificationState()`.
- `Sources/App/Sign/VerifyScreenModel.swift:345-349`: cleartext invalidation increments `textInputSectionEpoch`.
- `Sources/App/Encrypt/EncryptInputSections.swift:22`, `Sources/App/Encrypt/EncryptScreenModel.swift:661`, `Sources/App/Sign/SignView.swift:288`, and `Sources/App/Sign/SignScreenModel.swift:334` were checked for comparison; the same per-edit invalidation pattern was not found there.

## Validation

- This was a read-only code investigation except for writing these two requested files.
- No tests were run.
