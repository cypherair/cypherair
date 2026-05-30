# Round 2 Investigator: cluster-decrypt-verify-ui

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`
HEAD: `d075268f61154227b5ff8545bb53808cccfda66c`

## CA-20 - Unbounded detailed signature UI enables DoS

- Title: Unbounded detailed signature UI enables DoS
- Relevant code locations:
  - `pgp-mobile/src/signature_details.rs:87-166`
  - `Sources/Services/FFI/PGPMessageResultMapper.swift:113-158`
  - `Sources/Models/DetailedSignatureVerification.swift:52-75`
  - `Sources/App/Common/DetailedSignatureSectionView.swift:8-56`
  - `Sources/App/Decrypt/DecryptView.swift:247-253`
  - `Sources/App/Sign/VerifyView.swift:123-129`
- Mechanism-present status: Present. Rust records every observed signature into an unbounded `Vec`; Swift maps the full `[DetailedSignatureEntry]` into a full `[DetailedSignatureVerification.Entry]`; `DetailedSignatureSectionView` maps all entries again and renders `ForEach(Array(signatureEntries.enumerated()))`.
- Shipped reachability: Reachable from shipped decrypt and verify UI when the user processes attacker-supplied signed, detached-signature, or encrypted-and-signed content. There is no network ingress, so this is local/user-mediated availability exposure.
- Mitigations:
  - Inputs are user-selected or user-pasted; no background network fetch path was found.
  - Impact appears limited to memory/CPU/UI availability. I found no path from this mechanism to plaintext disclosure, private-key disclosure, or code execution.
  - Legacy summary fields remain available, so a display/retention cap should be feasible without removing summary status.
- Evidence-real:
  - `SignatureCollector` initializes `signatures: Vec::new()` and `observe_result` pushes without a cap.
  - `PGPMessageResultMapper.mapDetailedSignatureVerification` maps every FFI signature entry.
  - `DetailedSignatureSectionView.signatureEntries` maps the full array, then the body makes another `Array(signatureEntries.enumerated())` copy for rendering.
  - `docs/TESTING.md` currently documents preservation of every observed signature result, which confirms this is an intentional behavior but also shows no bound.
- Evidence-false-positive:
  - No false-positive evidence for the mechanism. The security consequence should be scoped as local availability DoS, not confidentiality or remote exploit.
- Preliminary disposition: Real, shipped, local availability issue. Recommend a bounded retained/displayed signature count plus an explicit truncation indicator; consider whether the cap belongs in Rust, Swift mapping, UI, or more than one layer.
- Confidence: High.
- Open questions:
  - What product maximum is acceptable for detailed entries?
  - Should Rust preserve all entries for tests/debug builds while shipped UI receives a capped projection?

## CA-29 - Decrypted file can persist after cancelled/abandoned decrypt

- Title: Decrypted file can persist after cancelled/abandoned decrypt
- Relevant code locations:
  - `Sources/App/Decrypt/DecryptView.swift:312-316`
  - `Sources/App/Decrypt/DecryptScreenModel.swift:246-266`
  - `Sources/App/Decrypt/DecryptScreenModel.swift:394-423`
  - `Sources/App/Decrypt/DecryptScreenModel.swift:593-602`
  - `Sources/App/Common/OperationController.swift:63-81`
  - `Sources/App/Common/AppTemporaryArtifact.swift:12-18`
  - `Sources/App/Common/AppTemporaryArtifactStore.swift:38-43,87-103,159-169`
  - `Sources/Services/DecryptionService.swift:141-185`
- Mechanism-present status: Partially present. Current HEAD fixes important cancellation paths, but the abandoned-view path remains. `handleContentClearGenerationChange()` cancels and invalidates the operation before clearing state. `decryptFile()` holds `pendingOutput` and cleans it in `defer` if cancellation happens after the service returns but before the model adopts the output. However, `handleDisappear()` clears current state and deletes the current temp file without cancelling the in-flight operation.
- Shipped reachability: Reachable if a user starts a file decrypt and leaves the decrypt route while the operation is still running. The operation closure captures the model, can continue after `onDisappear`, and can later call `adoptDecryptedFileOutput(result.output)` because no cancellation was requested by `handleDisappear()`.
- Mitigations:
  - Content-clear/relock path calls `operation.cancelAndInvalidate()` and is mitigated.
  - Manual cancel path is mitigated by `operation.cancel()`, progress cancellation, `Task.checkCancellation()`, and `pendingOutput?.cleanup()`.
  - Rust streaming decrypt writes to a random `.tmp` path and only renames to the final output after successful full decryption/verification; errors/cancellation delete the temp file. This is not an AEAD partial-plaintext leak.
  - Output artifacts live under `tmp/decrypted/op-<UUID>/` with complete file protection and startup/reset cleanup removes temporary artifacts.
- Evidence-real:
  - `DecryptView.onDisappear` calls `model.handleDisappear()`.
  - `handleDisappear()` does not call `operation.cancel()` or `operation.cancelAndInvalidate()`.
  - `decryptFile()` adopts output after the service returns unless cancellation is observed.
  - `TemporaryFileOutput` and `AppTemporaryArtifact` have explicit cleanup methods but no automatic deinit cleanup.
- Evidence-false-positive:
  - The content-clear subclaim is false for current HEAD: `handleContentClearGenerationChange()` cancels before clearing.
  - The "cancel after Rust success before Swift stores URL" subclaim is false for current HEAD: `pendingOutput` is cleaned by `defer` if `Task.checkCancellation()` throws before adoption.
  - The Rust streaming path does not expose partial plaintext on authentication failure; it deletes `.tmp` output on errors before rename.
- Preliminary disposition: Real but narrowed. Shipped impact is local plaintext persistence for an abandoned in-flight file decrypt until later startup/reset/manual cleanup, not a general cancellation failure and not a payload-authentication bypass.
- Confidence: Medium-high.
- Open questions:
  - Is `handleDisappear()` intentionally non-cancelling to support transient SwiftUI presentations? If so, route-exit cleanup may need a more precise lifecycle hook.
  - Should `DecryptScreenModel` own a deinit cleanup/cancel fallback for temporary outputs and in-flight operations?

## CA-33 - Decrypt view can show stale signature for wrong content

- Title: Decrypt view can show stale signature for wrong content
- Relevant code locations:
  - `Sources/App/Decrypt/DecryptScreenModel.swift:48-57`
  - `Sources/App/Decrypt/DecryptScreenModel.swift:369-423`
  - `Sources/App/Decrypt/DecryptScreenModel.swift:565-585`
  - `Sources/App/Decrypt/DecryptView.swift:220-253`
- Mechanism-present status: Present. Decrypt has one shared `detailedSignatureVerification` for both text and file modes, while text result and file result are retained independently. Mode switching through `$model.decryptMode` has no invalidation hook.
- Shipped reachability: Reachable in shipped decrypt UI. Example: decrypt text, switch to file mode, decrypt a signed file, switch back to text mode. The old text plaintext remains mode-specific state and the shared signature section now reflects the file result.
- Mitigations:
  - Text edits, text import clearing, file selection, content clear, and disappear clear the shared signature state.
  - Verify UI uses separate cleartext and detached detailed verification state with `activeDetailedVerification`, so this specific stale cross-mode mechanism is confined to decrypt UI.
  - The cryptographic operation results themselves are not falsified; this is a trust-rendering/state association bug.
- Evidence-real:
  - `DecryptScreenModel` stores `decryptedText`, `decryptedFileURL`, and a single `detailedSignatureVerification`.
  - `decryptText()` sets `decryptedText` and replaces the shared verification.
  - `decryptFile()` adopts file output and replaces the same shared verification.
  - `DecryptView` renders text/file output by mode, then renders `DetailedSignatureSectionView` outside those mode-specific result blocks whenever shared verification is non-nil.
- Evidence-false-positive:
  - Not observed in `VerifyView`: that model separates cleartext and detached verification and chooses by active mode.
  - The stale signature clears on input edits and file selection; the unresolved reachable gap is mode switching after successful operations.
- Preliminary disposition: Real shipped trust UI issue. Recommend binding signature verification atomically to the displayed result/mode, or keeping separate text/file result objects that include both content URL/text and verification.
- Confidence: High.
- Open questions:
  - Should switching modes clear inactive results, or should inactive results be retained but hidden with their own signature state?
  - Should text decrypt clear stale file output and file decrypt clear stale text output?

## CA-42 - Text input section is recreated on every edit

- Title: Text input section is recreated on every edit
- Relevant code locations:
  - `Sources/App/Decrypt/DecryptView.swift:340-368`
  - `Sources/App/Decrypt/DecryptScreenModel.swift:287-292,565-570`
  - `Sources/App/Sign/VerifyView.swift:185-211`
  - `Sources/App/Sign/VerifyScreenModel.swift:167-175,345-349`
- Mechanism-present status: Present. Both Decrypt and Verify put the active text input `Section` under `.id(model.textInputSectionEpoch)`. Their text binding setters call invalidation helpers on every edit, and those helpers increment `textInputSectionEpoch`.
- Shipped reachability: Reachable during ordinary manual text entry in Decrypt text mode and Verify cleartext mode.
- Mitigations:
  - This is local UI state/availability only. I found no plaintext leakage, authentication bypass, or persisted-data impact.
  - Imported-file paths may only recreate once when the imported text is assigned, rather than on every keystroke.
  - Encrypt/Sign have similar epoch IDs but their edit invalidation paths were not found to increment on every keystroke in the same way.
- Evidence-real:
  - `DecryptScreenModel.setCiphertextInput` calls `invalidateTextInputState()`, which increments `textInputSectionEpoch`.
  - `VerifyScreenModel.setSignedInput` calls `invalidateCleartextVerificationState()`, which increments `textInputSectionEpoch`.
  - `DecryptView` and `VerifyView` apply `.id(model.textInputSectionEpoch)` to the text-input sections.
- Evidence-false-positive:
  - The reported recreation mechanism is real, but the security framing is false-positive/overstated. This should stay informational/cosmetic unless UI testing demonstrates a severe data-entry availability failure.
- Preliminary disposition: Real mechanism, informational shipped UX/state issue, not a security issue.
- Confidence: High for code mechanism; medium for exact user-visible severity because Apple documentation lookup was unavailable and I did not run UI instrumentation.
- Open questions:
  - Should edit-time invalidation avoid changing section identity and reserve epoch changes for import/reset/operation-completion paths?
  - Would a focused UI regression test catch focus, cursor, and undo preservation for multiline text inputs?
