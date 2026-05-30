# Round 2 Adversary Trace: cluster-decrypt-verify-ui

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`
HEAD inspected: `d075268f61154227b5ff8545bb53808cccfda66c`

I did not read `.codex-audit/round-002/cluster-decrypt-verify-ui/investigator-trace.md`. I only observed that the file exists while listing the output directory.

## Commands Run

- `pwd && ls -la .codex-audit/round-002/cluster-decrypt-verify-ui`
- `sed -n '1,260p' docs/CODEX_SECURITY_REVIEW_INDEX.md`
- `rg -n "CA-(20|29|33|42)" codex-security-findings-2026-05-29T13-11-03.346Z.csv docs/CODEX_SECURITY_REVIEW_INDEX.md .codex-audit/round-002/cluster-decrypt-verify-ui/investigator.md`
- `sed -n '1,260p' .codex-audit/round-002/cluster-decrypt-verify-ui/investigator.md`
- `sed -n '1,80p' codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- `rg -n "4b57512bd5ec819194bff3e78091181a|a2a7f41bec048191b18443eaa38268e6|ffff6cd467088191ab32b29040dd40ab|3f03eebb98448191b26dbb3af9dcafa0|Unbounded detailed signature UI|Decrypted file can persist|stale signature|Text input section" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- `git status --short`
- `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '1,220p'`
- `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '220,480p'`
- `nl -ba Sources/App/Decrypt/DecryptScreenModel.swift | sed -n '480,700p'`
- `nl -ba Sources/App/Decrypt/DecryptView.swift | sed -n '1,430p'`
- `nl -ba Sources/App/Decrypt/DecryptView.swift | sed -n '428,470p'`
- `nl -ba Sources/App/Common/OperationController.swift | sed -n '1,180p'`
- `rg -n "struct FileOperationAction|final class FileOperationAction|FileOperationAction" Sources/App Sources/Services Sources/Models`
- `nl -ba Sources/App/Common/AppTemporaryArtifact.swift | sed -n '1,120p'`
- `nl -ba Sources/App/Common/AppTemporaryArtifactStore.swift | sed -n '1,240p'`
- `nl -ba Sources/App/Common/FileOperationAction.swift | sed -n '1,160p'`
- `nl -ba Sources/Services/DecryptionService.swift | sed -n '1,260p'`
- `nl -ba Sources/Services/DecryptionService.swift | sed -n '260,560p'`
- `rg -n "struct TemporaryFileOutput|class TemporaryFileOutput|TemporaryFileOutput" Sources pgp-mobile -g '*.swift' -g '*.rs'`
- `rg -n "decryptFileStreamingDetailed|decrypt.*stream|streaming" pgp-mobile/src Sources/Services -g '*.rs' -g '*.swift'`
- `nl -ba Sources/App/Common/TemporaryFileOutput.swift | sed -n '1,100p'`
- `nl -ba pgp-mobile/src/streaming.rs | sed -n '1,220p'`
- `nl -ba pgp-mobile/src/streaming.rs | sed -n '338,464p'`
- `rg -n "class PGPMessageOperationAdapter|struct PGPMessageOperationAdapter|PGPMessageOperationAdapter" Sources`
- `rg -n "mapDetailedSignatureVerification|DetailedSignatureEntry|DetailedSignatureVerification|signatureEntries|DetailedSignatureSectionView" Sources pgp-mobile/src -g '*.swift' -g '*.rs'`
- `nl -ba pgp-mobile/src/signature_details.rs | sed -n '1,240p'`
- `nl -ba pgp-mobile/src/signature_details.rs | sed -n '240,340p'`
- `nl -ba Sources/Services/FFI/PGPMessageOperationAdapter.swift | sed -n '1,300p'`
- `nl -ba Sources/Services/FFI/PGPMessageResultMapper.swift | sed -n '1,240p'`
- `nl -ba Sources/Models/DetailedSignatureVerification.swift | sed -n '1,160p'`
- `nl -ba Sources/App/Common/DetailedSignatureSectionView.swift | sed -n '1,150p'`
- `nl -ba Sources/App/Sign/VerifyScreenModel.swift | sed -n '1,230p'`
- `nl -ba Sources/App/Sign/VerifyScreenModel.swift | sed -n '230,430p'`
- `nl -ba Sources/App/Sign/VerifyView.swift | sed -n '1,300p'`
- `nl -ba Sources/App/Sign/VerifyView.swift | sed -n '300,520p'`
- `rg -n "cleanupTemporaryArtifacts|AppTemporaryArtifactStore|handleDisappear\\(\\)|contentClearGeneration|DecryptScreenModel|decryptFile\\(|deleteTemporaryDecryptedFile|TemporaryFileOutput" Sources Tests docs -g '*.swift' -g '*.md'`
- `rg -n "every observed signature|detailed signature|signature details|DetailedSignature" docs/TESTING.md docs/ARCHITECTURE.md docs/SECURITY.md docs/CONVENTIONS.md`
- `rg -n "DecryptView|VerifyView|DecryptScreenModel|VerifyScreenModel|DetailedSignatureSectionView|decrypted file|temporary" Tests Sources -g '*.swift'`
- `rg -n "appSessionOrchestrator|contentClearGeneration|clearTransientInput|handleContentClearGenerationChange" Sources/App Sources/Security -g '*.swift'`
- `nl -ba Tests/ServiceTests/DecryptScreenModelTests.swift | sed -n '1,220p'`
- `nl -ba Tests/ServiceTests/DecryptScreenModelTests.swift | sed -n '220,360p'`
- `nl -ba Tests/ServiceTests/DecryptScreenModelTests.swift | sed -n '360,540p'`
- `nl -ba Tests/ServiceTests/DecryptScreenModelTests.swift | sed -n '540,820p'`
- `nl -ba Tests/ServiceTests/DecryptScreenModelTests.swift | sed -n '812,900p'`
- `nl -ba Tests/ServiceTests/VerifyScreenModelTests.swift | sed -n '1,260p'`
- `nl -ba docs/TESTING.md | sed -n '450,480p'`
- `nl -ba Sources/App/AppStartupCoordinator.swift | sed -n '80,140p'`
- `nl -ba Sources/App/Settings/LocalDataResetService.swift | sed -n '520,555p'`
- `nl -ba docs/ARCHITECTURE.md | sed -n '80,130p'`
- `nl -ba docs/TDD.md | sed -n '280,292p' && nl -ba docs/TDD.md | sed -n '436,442p'`
- `nl -ba Sources/App/Common/AppTemporaryArtifactStore.swift | sed -n '240,330p'`
- `git rev-parse HEAD`
- `find .codex-audit/round-002/cluster-decrypt-verify-ui -maxdepth 1 -type f -print | sort`
- `nl -ba .codex-audit/round-002/cluster-decrypt-verify-ui/investigator.md | sed -n '1,140p'`

## Original Finding Sources

- `docs/CODEX_SECURITY_REVIEW_INDEX.md:58` maps CA-20 to decrypt/verify detailed signature UI and Rust signature details.
- `docs/CODEX_SECURITY_REVIEW_INDEX.md:67` maps CA-29 to decrypted file output persistence.
- `docs/CODEX_SECURITY_REVIEW_INDEX.md:71` maps CA-33 to stale decrypt signature UI.
- `docs/CODEX_SECURITY_REVIEW_INDEX.md:80` maps CA-42 to text input section recreation.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:21` contains the original CA-20 description.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:30` contains the original CA-29 description.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:34` contains the original CA-33 description.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:43` contains the original CA-42 description.
- `investigator.md:6-33` records the investigator CA-20 conclusion.
- `investigator.md:35-67` records the investigator CA-29 conclusion.
- `investigator.md:69-95` records the investigator CA-33 conclusion.
- `investigator.md:97-121` records the investigator CA-42 conclusion.

## CA-20 Evidence Trace

- `pgp-mobile/src/signature_details.rs:87-109` defines `SignatureCollector` with an unbounded `signatures: Vec<DetailedSignatureEntry>`.
- `pgp-mobile/src/signature_details.rs:112-124` iterates every `SignatureGroup` result observed in the parser structure.
- `pgp-mobile/src/signature_details.rs:163-167` pushes each entry and uses the current vector length as the entry index.
- `pgp-mobile/src/signature_details.rs:140-142` clones and returns the full signature vector.
- `pgp-mobile/src/signature_details.rs:144-160` returns the full vector from `into_parts()`.
- `Sources/Services/FFI/PGPMessageResultMapper.swift:108-158` maps every FFI signature entry into app `DetailedSignatureVerification.Entry` values.
- `Sources/Models/DetailedSignatureVerification.swift:52-75` stores the mapped entries in an unbounded `[Entry]`.
- `Sources/App/Common/DetailedSignatureSectionView.swift:8-21` renders all entries and eagerly builds `Array(signatureEntries.enumerated())`.
- `Sources/App/Common/DetailedSignatureSectionView.swift:44-56` maps every detailed entry into `SignatureVerification` and separately filters all signer entries.
- `Sources/App/Decrypt/DecryptView.swift:247-253` renders `DetailedSignatureSectionView` on the Decrypt shipped path.
- `Sources/App/Sign/VerifyView.swift:123-129` renders `DetailedSignatureSectionView` on the Verify shipped path.
- `docs/TESTING.md:462-475` says richer-signature validation includes preserving every observed signature result in parser order.

## CA-29 Evidence Trace

- `Sources/App/Decrypt/DecryptView.swift:312-316` calls `model.handleDisappear()` and `model.handleContentClearGenerationChange()` from lifecycle hooks.
- `Sources/App/Decrypt/DecryptScreenModel.swift:246-256` shows `handleDisappear()` clears displayed state but does not cancel the running operation.
- `Sources/App/Decrypt/DecryptScreenModel.swift:258-266` shows content-clear does call `operation.cancelAndInvalidate()` before clearing transient state.
- `Sources/App/Decrypt/DecryptScreenModel.swift:394-423` shows file decrypt awaits the service action, stores `pendingOutput`, checks cancellation, adopts the output, and then clears the pending cleanup guard.
- `Sources/App/Decrypt/DecryptScreenModel.swift:410-416` is the specific cancellation-after-service-success cleanup guard.
- `Sources/App/Decrypt/DecryptScreenModel.swift:593-602` shows explicit cleanup/adoption of decrypted file outputs.
- `Sources/App/Common/OperationController.swift:63-81` implements `cancel()` and `cancelAndInvalidate()`.
- `Sources/App/Common/OperationController.swift:123-145` runs operations in an unstructured `Task` and catches cancellation.
- `Sources/App/Common/TemporaryFileOutput.swift:7-26` defines explicit cleanup only; there is no deinit cleanup.
- `Sources/App/Common/AppTemporaryArtifact.swift:12-18` defines explicit owner/file cleanup only.
- `Sources/App/Common/AppTemporaryArtifactStore.swift:38-43` creates decrypted artifacts.
- `Sources/App/Common/AppTemporaryArtifactStore.swift:87-103` removes `decrypted` and `streaming` temporary roots during cleanup.
- `Sources/App/Common/AppTemporaryArtifactStore.swift:159-169` creates per-operation owner directories named `op-<UUID>`.
- `Sources/App/Common/AppTemporaryArtifactStore.swift:240-249` checks volume file-protection support before applying complete protection.
- `Sources/Services/DecryptionService.swift:141-185` creates the decrypted artifact, calls streaming decrypt, applies protection, cleans up on service errors, and returns the artifact only on success.
- `pgp-mobile/src/streaming.rs:7-13` documents the temp-file, cleanup, and AEAD hard-fail invariants.
- `pgp-mobile/src/streaming.rs:397-451` writes to a random `.tmp`, deletes on errors/cancellation, syncs, and only then renames to the final output path.
- `Tests/ServiceTests/DecryptScreenModelTests.swift:613-675` covers manual cancellation not publishing output.
- `Tests/ServiceTests/DecryptScreenModelTests.swift:677-725` covers cancellation after service success cleaning the unpublished output.
- `Tests/ServiceTests/DecryptScreenModelTests.swift:727-787` covers current content-clear/disappear cleanup scopes, including current output deletion on disappear.
- `Sources/App/AppStartupCoordinator.swift:95-100` runs temporary cleanup during startup.
- `Sources/App/AppStartupCoordinator.swift:123-131` delegates startup cleanup to `AppTemporaryArtifactStore`.
- `Sources/App/Settings/LocalDataResetService.swift:536-546` removes temporary artifacts during local data reset.
- `docs/TDD.md:436-439` classifies temporary/export/tutorial artifacts as centralized through `AppTemporaryArtifactStore` with startup/reset cleanup.

## CA-33 Evidence Trace

- `Sources/App/Decrypt/DecryptScreenModel.swift:48-57` stores mode, text output, shared detailed verification, selected file, and file output state.
- `Sources/App/Decrypt/DecryptScreenModel.swift:369-385` decrypts text, sets `decryptedText`, and replaces the shared detailed verification.
- `Sources/App/Decrypt/DecryptScreenModel.swift:394-423` decrypts file, adopts the file output, and replaces the same shared detailed verification.
- `Sources/App/Decrypt/DecryptScreenModel.swift:565-585` clears the shared detailed verification from input invalidation helpers, but there is no mode-change helper.
- `Sources/App/Decrypt/DecryptView.swift:133-150` binds the segmented mode picker directly to `$model.decryptMode`.
- `Sources/App/Decrypt/DecryptView.swift:220-245` renders text and file outputs in mode-specific blocks.
- `Sources/App/Decrypt/DecryptView.swift:247-253` renders the shared signature section outside the mode-specific result blocks.
- `Sources/App/Sign/VerifyScreenModel.swift:38-42` stores separate cleartext and detached detailed verification state.
- `Sources/App/Sign/VerifyScreenModel.swift:123-130` selects active verification by current verify mode.
- `Sources/App/Sign/VerifyView.swift:123-129` renders only `model.activeDetailedVerification`.
- `Tests/ServiceTests/VerifyScreenModelTests.swift:102-139` explicitly verifies per-mode result preservation for Verify.
- `Tests/ServiceTests/DecryptScreenModelTests.swift:789-838` covers clearing detailed verification before parse, but no Decrypt mode-switch stale-signature regression was found.

## CA-42 Evidence Trace

- `Sources/App/Decrypt/DecryptView.swift:330-368` places `CypherMultilineTextInput` inside a `Section` with `.id(model.textInputSectionEpoch)`.
- `Sources/App/Decrypt/DecryptView.swift:428-432` routes text binding writes to `model.setCiphertextInput`.
- `Sources/App/Decrypt/DecryptScreenModel.swift:287-292` calls `invalidateTextInputState()` on every changed text value.
- `Sources/App/Decrypt/DecryptScreenModel.swift:565-570` increments `textInputSectionEpoch` during text invalidation.
- `Sources/App/Sign/VerifyView.swift:170-211` places `CypherMultilineTextInput` inside a `Section` with `.id(model.textInputSectionEpoch)`.
- `Sources/App/Sign/VerifyView.swift:171-175` routes signed input binding writes to `model.setSignedInput`.
- `Sources/App/Sign/VerifyScreenModel.swift:167-175` calls `invalidateCleartextVerificationState()` on every changed signed input value.
- `Sources/App/Sign/VerifyScreenModel.swift:345-349` increments `textInputSectionEpoch` during cleartext verification invalidation.
- `Tests/ServiceTests/DecryptScreenModelTests.swift:340-365` asserts the Decrypt epoch increments after `setCiphertextInput`.
- `Tests/ServiceTests/VerifyScreenModelTests.swift:38-81` verifies edit invalidation of imported cleartext and result state, but does not measure focus/cursor/undo behavior.
