# Round 2 Adversary: cluster-decrypt-verify-ui

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`
HEAD inspected: `d075268f61154227b5ff8545bb53808cccfda66c`

I did not read `investigator-trace.md`.

## CA-20 - Unbounded detailed signature UI enables DoS

### Challenge Summary

The investigator's mechanism is real, but the security impact should be narrowed. This is a user-mediated local availability issue in an offline app, not a remote exploit, confidentiality break, authentication bypass, or integrity failure. The evidence supports a cap/hardening follow-up, but not the original "medium security" framing unless the project treats hostile local file processing DoS as medium.

### Strongest Evidence Against Real Impact

- Shipped reachability requires the user to paste or select attacker-supplied signed/decryptable material. There is no automatic network ingress or background processing path.
- The impact observed in code is memory/CPU/UI availability. The detailed-signature list does not expose plaintext, private keys, or alter crypto verification results.
- The legacy/summary verification fields remain separate from the detailed array, so a display cap could preserve the normal trust result without changing cryptographic behavior.
- The UI rendering is only one layer of the problem. Rust and UniFFI have already accepted and transported the full list before SwiftUI rendering, so this is better framed as end-to-end unbounded result retention than as only a UI bug.

### Strongest Evidence Supporting Real Impact

- `SignatureCollector` stores `signatures: Vec<DetailedSignatureEntry>` and pushes every observed result without a limit.
- `PGPMessageResultMapper` maps the full FFI `[DetailedSignatureEntry]` into app entries.
- `DetailedSignatureSectionView` maps all entries again and eagerly renders `ForEach(Array(signatureEntries.enumerated()))`.
- Both Decrypt and Verify render this shared detailed section on shipped paths.

### Practical Shipped Scenario

An attacker gives the user a crafted OpenPGP file/message or detached signature with a very large number of signature results. When the user verifies or decrypts it, the app can spend excessive CPU/memory collecting, mapping, and rendering the detailed entries, potentially hanging or crashing.

### Final Recommendation

`real-low`

### Confidence

High.

### Questions For Main Codex/User Discussion

- What maximum detailed signature count is useful to users in the product UI?
- Should the production cap be enforced in Rust, in Swift mapping, in UI display, or in more than one layer?
- Should tests keep the "preserve every observed signature" contract behind a fixture/debug-only path while shipped UI gets a capped projection?

## CA-29 - Decrypted file can persist after cancelled/abandoned decrypt

### Challenge Summary

The original finding overstates current cancellation exposure. Current HEAD appears to mitigate manual cancel, content-clear/relock, Rust streaming errors, and cancellation after Rust success before Swift adoption. The remaining issue is narrower: if the user abandons the decrypt route while an in-flight file decrypt later succeeds, the final plaintext output can be adopted by an orphaned model and remain under app temporary storage until startup/reset/manual cleanup.

### Strongest Evidence Against Real Impact

- `handleContentClearGenerationChange()` calls `operation.cancelAndInvalidate()` before clearing transient state.
- Manual cancel calls `operation.cancel()`, which cancels progress and the current task.
- `decryptFile()` keeps the returned output in `pendingOutput` and cleans it in `defer` if `Task.checkCancellation()` throws before adoption.
- Tests cover cancellation without publishing output and cancellation after service success cleaning unpublished output.
- Rust streaming writes plaintext to a random-suffixed `.tmp` file and deletes it on read/write/cancellation/authentication errors before the final rename. This is not an AEAD partial-plaintext leak.
- The final output is app-owned temporary data under `tmp/decrypted/op-<UUID>/`, with startup and local reset cleanup, and the service applies verified complete file protection where supported.

### Strongest Evidence Supporting Real Impact

- `DecryptView.onDisappear` calls `model.handleDisappear()`.
- `handleDisappear()` clears current state and deletes any current output, but it does not call `operation.cancel()` or `operation.cancelAndInvalidate()`.
- `OperationController` uses an unstructured `Task`; it is not inherently tied to SwiftUI view lifetime.
- The decrypt operation closure captures the screen model, so it can continue after `onDisappear` and later call `adoptDecryptedFileOutput(result.output)`.
- `TemporaryFileOutput` and `AppTemporaryArtifact` only clean up through explicit `cleanup()` calls; no deinit cleanup path was found.

### Practical Shipped Scenario

A user starts a large file decrypt, then leaves the Decrypt route before completion. The view's disappear cleanup runs while `decryptedFileURL` is still nil. The background operation later succeeds, writes and adopts a plaintext output under the app temporary `decrypted/op-<UUID>/` directory, and the orphaned model is then released without deleting that file. The file is removed on a later startup/reset cleanup, but can persist in the interim.

### Final Recommendation

`real-low`

### Confidence

Medium-high.

### Questions For Main Codex/User Discussion

- Should route disappearance always cancel file decrypt, or are there transient SwiftUI disappear cases where the operation should continue?
- Should `DecryptScreenModel` have a deinit cancel/cleanup fallback for in-flight operations and owned temporary outputs?
- How should the project classify local, user-initiated plaintext residue inside app temporary storage with startup/reset cleanup?

## CA-33 - Decrypt view can show stale signature for wrong content

### Challenge Summary

This remains a real shipped trust-rendering issue. The adversarial narrowing is that the path requires multi-step user interaction across modes and does not falsify cryptographic results or persist trust state. Even so, a normal user can reasonably read the visible signature section as applying to the visible output, so the current state association is unsafe enough to fix.

### Strongest Evidence Against Real Impact

- The stale association is not created by a single decrypt action; it requires decrypting one mode, switching modes, decrypting the other, and switching back.
- Text edits, imported-text clearing, file selection, content-clear, and disappear cleanup clear the shared signature state.
- Verify's model already separates cleartext and detached detailed verification and selects by active mode, so the issue appears confined to Decrypt.
- The cryptographic operation result is not changed. This is UI state association, not signature validation bypass.

### Strongest Evidence Supporting Real Impact

- `DecryptScreenModel` has separate `decryptedText` and `decryptedFileURL` result state, but only one shared `detailedSignatureVerification`.
- `decryptText()` sets the text result and replaces the shared verification.
- `decryptFile()` adopts the file result and replaces the same shared verification.
- The mode picker binding has no invalidation hook that clears or swaps signature state on mode changes.
- `DecryptView` renders the text/file output inside mode-specific blocks, then renders `DetailedSignatureSectionView` outside those blocks whenever the shared verification is non-nil.

### Practical Shipped Scenario

A user decrypts an unsigned or unknown-signer text message, switches to File mode, decrypts a valid signed file, then switches back to Text mode. The old plaintext text result is visible, and the shared signature section below it can show the file's valid signature status. The reverse direction is also possible with a file output shown beside a text message's signature state.

### Final Recommendation

`real-needs-fix`

### Confidence

High.

### Questions For Main Codex/User Discussion

- Should switching modes clear inactive results, or should each mode retain an atomic result object containing both output and verification?
- Should file decrypt clear old text output and text decrypt clear old file output?
- Should the signature section include a source/mode binding in tests so this cannot regress silently?

## CA-42 - Text input section is recreated on every edit

### Challenge Summary

The code mechanism is real, but the security framing is weak. This is best treated as an informational/local UX availability issue unless UI instrumentation shows that ordinary typing is consistently broken. It should not be prioritized as a security fix merely because the text can contain encrypted/signed material.

### Strongest Evidence Against Real Impact

- The path is local manual text entry only. It does not leak plaintext, persist secrets, bypass authentication, or change verification/decryption semantics.
- File import paths avoid repeated per-keystroke recreation; they may increment the epoch once when imported text is assigned.
- The exact user-visible severity was not verified with UI instrumentation in this adversarial pass. `.id` changes strongly imply subtree replacement, but whether focus/cursor/undo loss is severe enough for a security queue remains an empirical question.
- Users can still import `.asc` files for these workflows, reducing the practical availability impact for larger payloads.

### Strongest Evidence Supporting Real Impact

- Decrypt's text binding setter calls `setCiphertextInput()`, which calls `invalidateTextInputState()`, which increments `textInputSectionEpoch`.
- Verify's text binding setter calls `setSignedInput()`, which calls `invalidateCleartextVerificationState()`, which increments `textInputSectionEpoch`.
- `DecryptView` and `VerifyView` apply `.id(model.textInputSectionEpoch)` to the active text-input `Section`.

### Practical Shipped Scenario

While typing or editing an armored encrypted message in Decrypt text mode, or a cleartext signed message in Verify cleartext mode, each edit changes the identity of the section containing the text editor. Depending on SwiftUI platform behavior, this can drop focus, reset selection/cursor/undo state, or make manual text entry feel unreliable.

### Final Recommendation

`real-low`

### Confidence

High for the code mechanism; medium for real user-visible severity.

### Questions For Main Codex/User Discussion

- Does a focused UI test reproduce focus, cursor, or undo loss on iOS, macOS, and visionOS?
- Should `textInputSectionEpoch` be reserved for import/reset/operation-completion paths instead of edit-time invalidation?
- Should this be closed as non-security after opening a UX regression ticket?
