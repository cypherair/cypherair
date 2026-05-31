# Codex Security Review Fix Plan

This document is the implementation planning record for accepted security-review follow-ups. Use the `SR-FIX-*` IDs in future issues, commits, and pull requests. Legacy `CA-*` IDs are included only for traceability to the original review discussion.

## Fix Queue

### SR-FIX-01: Spoofed duplicate contacts bypass key-update warning

- Legacy ID: `CA-01`
- Severity: `high`
- Area: `contact-import`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/3db1dd11b0548191993e920e471adfb2)
- Decision: Confirmed fix-worthy. Duplicate conflicting contact imports are stored as separate identities, but the import workflow drops the computed conflict warning before user confirmation.
- Impact: A spoofed duplicate contact can appear beside a legitimate contact with the expected name or email. Future encryption is affected only if the user selects that duplicate; no automatic key takeover occurs.
- Relevant paths: `Sources/Services/ContactService.swift`, `Sources/App/Contacts/Import/ContactImportWorkflow.swift`
- Fix plan: Preserve duplicate identities if that remains product policy, but surface the candidate conflict before or at import success and offer an explicit review or merge path. If product policy changes, stage or block conflicting imports until the user chooses how to handle the existing contact.
- Validation: Add import workflow tests for same-email/User-ID different-fingerprint candidates and UI/workflow checks that the conflict warning is preserved before success.

### SR-FIX-02: GH_TOKEN exposed to entire XCFramework build

- Legacy ID: `CA-02`
- Severity: `high`
- Area: `ci-supply-chain`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/b2db20bd745c8191856cc218daacb19d)
- Decision: Confirmed release supply-chain hardening. Release XCFramework builds expose GitHub tokens to broader build subprocesses than needed.
- Impact: Compromised release-time build code could read workflow tokens during artifact production. This is release infrastructure risk, not an app-runtime exploit.
- Relevant paths: `.github/workflows/pr-checks.yml`, `.github/workflows/stable-build-release.yml`, `.github/workflows/xcframework-edge-release.yml`, `scripts/build_apple_arm64e_xcframework.sh`
- Fix plan: Scope `GH_TOKEN` / `GITHUB_TOKEN` only to `gh` release operations that need GitHub API access. Clear token variables from Cargo, build-script, and helper subprocess environments.
- Validation: Inspect workflow environments and run release-workflow dry validation showing build subprocesses do not inherit GitHub tokens except for narrow `gh` calls.

### SR-FIX-03: Release workflow runs arbitrary refs with write token

- Legacy ID: `CA-05`
- Severity: `high`
- Area: `ci-supply-chain`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/893e12c4d22c8191afba18916328b86d)
- Decision: Confirmed release provenance issue. Formal stable publication can be dispatched from a source ref that is not proven to match the stable release tag commit.
- Impact: A stable release page could receive assets built from the wrong ref, weakening provenance for released XCFramework and source/compliance artifacts.
- Relevant paths: `.github/workflows/stable-build-release.yml`
- Fix plan: Make formal stable publication tag-push only, or guard dispatch so checked-out `HEAD` equals the peeled stable tag commit before any official release asset is created.
- Validation: Add workflow guard tests or script checks for tag/HEAD equality and verify dispatch cannot publish official assets from a mismatched ref.

### SR-FIX-04: Rust audit does not gate release publication

- Legacy ID: `CA-08`
- Severity: `medium`
- Area: `ci-supply-chain`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/9b57feaa6750819185da3adea4e4b205)
- Decision: Confirmed edge-release hardening. Edge publication is not currently blocked by a failed Rust dependency audit.
- Impact: Public edge or drill assets can be published even when Rust dependency audit fails, weakening prerelease supply-chain signals.
- Relevant paths: `.github/workflows/stable-build-release.yml`, `.github/workflows/xcframework-edge-release.yml`, `docs/TESTING.md`, `docs/APP_RELEASE_PROCESS.md`
- Fix plan: Make `publish-edge-release` depend on `rust-dependency-audit`, or run the audit inside the publish job before tag/release creation and asset upload.
- Validation: Verify the edge workflow graph requires Rust audit before publication and that a failing audit prevents tag/release asset creation.

### SR-FIX-05: Untrusted certifications can mark contacts certified

- Legacy ID: `CA-09`
- Severity: `medium`
- Area: `contact-certification`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/784c0115a134819188d3ebac0d5d8ac3)
- Decision: Confirmed trust-semantics issue. The UI can present cryptographically valid certifications as trusted contact certification without an explicit signer trust policy.
- Impact: Users may read neutral or untrusted certification artifacts as trusted endorsements. Recipient selection and manual fingerprint verification are not directly changed.
- Relevant paths: `Sources/Services/CertificateSignatureService.swift`, `Sources/Services/ContactSnapshotMutator.swift`, `Sources/App/Contacts/ContactKeySummaryView.swift`, `Sources/App/Contacts/ContactDetailView.swift`
- Fix plan: Separate cryptographic certification validity from trusted certification semantics. Use neutral UI for valid but untrusted certifications; reserve trusted labels for artifacts accepted under an explicit signer trust policy.
- Validation: Add service/UI tests for valid-untrusted certifications, trusted certifications, and self-certification-like artifacts so labels cannot overstate trust.

### SR-FIX-06: TOCTOU can delete active protected-data root secret

- Legacy ID: `CA-10`
- Severity: `medium`
- Area: `protected-data`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/9fd5a847678881918e0eea9cbdfc2e77)
- Decision: Confirmed low-probability ProtectedData availability risk. Root-secret orphan cleanup can act on stale registry state during first-domain creation.
- Impact: Failure mode is local ProtectedData availability or recovery loss. It is not disclosure, authentication bypass, or cryptographic breakage.
- Relevant paths: `Sources/Security/ProtectedData/ProtectedDataFirstDomainSharedRightCleaner.swift`, `Sources/Security/ProtectedData/PrivateKeyControlStore.swift`, `Sources/Security/ProtectedData/ProtectedDomainRecoveryCoordinator.swift`, `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift`, `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift`
- Fix plan: Before deleting a supposedly orphaned root secret, reload current registry state under the registry mutation gate or equivalent serialization. Abort cleanup if any current membership, pending mutation, or ready shared resource exists.
- Validation: Add concurrency/unit coverage around first-domain creation and orphan cleanup with stale snapshots; assert cleanup aborts under current registry membership or mutation.

### SR-FIX-07: Local reset fails open when authentication is unavailable

- Legacy ID: `CA-11`
- Severity: `medium`
- Area: `local-reset-auth`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/be6dc440a494819194638fde5dcd7663)
- Decision: Confirmed low-impact destructive-action risk. Local data reset should fail closed when app-session authentication cannot be evaluated.
- Impact: Failure mode is local destructive reset under narrow auth-unavailable conditions. It does not disclose data or bypass Secure Enclave private-key operations.
- Relevant paths: `Sources/App/Settings/SettingsScreenModel.swift`, `Sources/App/Settings/LocalDataResetService.swift`
- Fix plan: If app-session authentication cannot be evaluated, block local reset and surface an auth-unavailable error instead of treating the prompt as optional.
- Validation: Add settings/reset tests for auth unavailable, auth failure, and auth success; only success should proceed to destructive reset.

### SR-FIX-08: Stale operation prompt generation can disable privacy blur

- Legacy ID: `CA-15`
- Severity: `medium`
- Area: `privacy-lifecycle`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/daf3bd3399248191900565067b6785ae)
- Decision: Confirmed high-priority privacy lifecycle bug. Stale operation-prompt state can suppress real app-switch lifecycle handling.
- Impact: Can leave already-unlocked UI insufficiently blurred during real lifecycle transitions, especially on macOS, and can contribute to inconsistent auth recovery.
- Relevant paths: `Sources/Security/AuthenticationPromptCoordinator.swift`, `Sources/App/Common/PrivacyScreenLifecycleGate.swift`, `Sources/App/Common/PrivacyScreenModifier.swift`, `Sources/Security/ProtectedData/AppSessionOrchestrator.swift`
- Fix plan: Replace unbounded next-lifecycle suppression with bounded operation-prompt settle state. Background transitions must always clear prompt state and hard-blur; prompt-tail active transitions must not trigger resume auth or stale suppression after the settle window.
- Validation: Add lifecycle state-machine tests for prompt-induced inactive/active transitions, real background transitions, stale prompt state expiry, and macOS resume behavior.

### SR-FIX-09: Post-auth warm-up can clear background privacy blur

- Legacy ID: `CA-16`
- Severity: `medium`
- Area: `privacy-lifecycle`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/e2433b9357a48191b7ea3c939cad1a4d)
- Decision: Confirmed high-priority privacy lifecycle race. An in-flight resume task can clear a hard background privacy blur after the app leaves the active generation.
- Impact: Can overwrite a hard background blur after post-auth work completes. The risk is timing-sensitive but belongs with the same privacy lifecycle repair as SR-FIX-08.
- Relevant paths: `Sources/App/Common/PrivacyScreenModifier.swift`, `Sources/Security/ProtectedData/AppSessionOrchestrator.swift`, `Sources/App/CypherAirApp.swift`, `Sources/App/Settings/ProtectedSettingsHost.swift`
- Fix plan: Track scene/activity generation or equivalent foreground state. Resume completion may clear blur only if it still belongs to the current active generation; otherwise keep blur for the next active/resume path.
- Validation: Add generation/race tests where background occurs during post-auth work; completion must not clear blur for an obsolete generation.

### SR-FIX-10: Unescaped source ref in release verification command

- Legacy ID: `CA-18`
- Severity: `medium`
- Area: `ci-supply-chain`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/6d4198b21e5c8191a5d7d8339a3d6484)
- Decision: Confirmed low-impact release-note hardening. Drill release verification commands should render shell-safe source refs.
- Impact: A developer copying an unsafe verification command from drill release notes could trigger shell expansion. GitHub Actions and app users are not directly affected.
- Relevant paths: `.github/workflows/xcframework-edge-release.yml`
- Fix plan: Render shell-safe quoted source refs in drill release notes, or constrain accepted drill source refs to a safe character set before publishing notes.
- Validation: Validate generated release notes for refs containing shell metacharacters, or validate that unsafe refs are rejected before publication.

### SR-FIX-11: Production auth can be bypassed via UI-test defaults key

- Legacy ID: `CA-22`
- Severity: `medium`
- Area: `app-auth`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/85c8b620e92c8191ab484e11a5cf4143)
- Decision: Confirmed highest-priority app-auth issue. Production auth paths must not honor a UI-test bypass defaults key from the standard defaults domain.
- Impact: Can bypass app-session/privacy-lock and mode-switch authorization if the app standard defaults domain is manipulated. It does not bypass hardware-gated private-key unwrap/sign/decrypt/export.
- Relevant paths: `Sources/App/AppContainer.swift`, `Sources/Security/AuthenticationManager.swift`, `Sources/App/Common/PrivacyScreenModifier.swift`
- Fix plan: Make production `AuthenticationManager` unable to honor the UI-test bypass key: gate reads to debug/XCTest-only contexts or inject a non-standard defaults suite that production never uses.
- Validation: Add production-manager tests proving standard defaults cannot enable bypass, plus UI-test-path tests showing automation still uses the isolated test-only path.

### SR-FIX-12: Import confirmation can act on a replaced key request

- Legacy ID: `CA-23`
- Severity: `medium`
- Area: `contact-import`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/078f49939538819195ae18333d9d130b)
- Decision: Confirmed contact-import regression. Confirmation actions can dereference a later mutable request instead of the request displayed to the user.
- Impact: A second import delivered while a confirmation sheet is open can make the user action apply to the newer request, potentially marking an attacker contact as verified.
- Relevant paths: `Sources/App/Contacts/ImportConfirmationCoordinator.swift`, `Sources/App/CypherAirApp.swift`, `Sources/App/Contacts/AddContactView.swift`
- Fix plan: Make sheet button closures capture the displayed request callbacks, matching the cancellation path, and/or make `present()` refuse or queue while another request is pending.
- Validation: Add regression coverage for `present(A); present(B); confirm displayed A` semantics or for explicit pending-request refusal/queue behavior.

### SR-FIX-13: Secret key zeroization skipped on KMS helper failures

- Legacy ID: `CA-27`
- Severity: `medium`
- Area: `key-management-zeroization`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/2a18f490890c8191afc9b8775a8ff2b3)
- Decision: Confirmed zeroization gap. Key-operation adapter failure paths can skip explicit zeroization after secret key Data is produced.
- Impact: Best-effort Swift heap zeroization can be missed on failure paths. There is no disk write, logging, network exposure, or OpenPGP authentication bypass implied.
- Relevant paths: `Sources/Services/KeyManagementService.swift`
- Fix plan: Once secret key `Data` is produced inside the adapter, zeroize it before rethrowing any later failure. Do not zeroize the successful return inside the adapter because the caller owns success-path cleanup.
- Validation: Add failure-injection tests for adapter post-secret-key errors and assert best-effort zeroization is invoked before errors escape.

### SR-FIX-14: Decrypted file can persist after cancelled/abandoned decrypt

- Legacy ID: `CA-29`
- Severity: `medium`
- Area: `decrypt-file-output`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/a2a7f41bec048191b18443eaa38268e6)
- Decision: Confirmed low-impact temporary-output issue. Route abandonment can allow a late successful decrypt to adopt app-sandbox plaintext output.
- Impact: Temporary plaintext can remain in the app sandbox until normal startup/reset cleanup. Rust streaming cancellation still deletes partial output on cancellation or failure.
- Relevant paths: `Sources/App/Decrypt/DecryptView.swift`, `Sources/Services/DecryptionService.swift`
- Fix plan: Cancel and invalidate any in-flight file decrypt when the Decrypt route disappears, and prevent late adoption of outputs whose operation generation is no longer current.
- Validation: Add Decrypt route disappearance tests showing in-flight operations cancel/invalidate and cannot adopt outputs after disappearance.

### SR-FIX-15: Signing key not zeroized on no-default encrypt-to-self error

- Legacy ID: `CA-32`
- Severity: `medium`
- Area: `encryption-zeroization`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/8ef989997a7081919d767f560071a253)
- Decision: Confirmed informational hardening. Encryption should resolve public-only inputs before unwrapping the optional signing private key.
- Impact: Normal UI should not pass the inconsistent state, but service/API and corrupted metadata states should not unwrap private signing material before public validation succeeds.
- Relevant paths: `Sources/Services/EncryptionService.swift`
- Fix plan: Resolve all public-only inputs first, including encrypt-to-self/default public key selection. Only then unwrap the signing private key and immediately install a zeroization `defer` before later throwing work.
- Validation: Add service tests for missing default encrypt-to-self with signing requested; assert no signing private-key unwrap happens before public input failure.

### SR-FIX-16: Decrypt view can show stale signature for wrong content

- Legacy ID: `CA-33`
- Severity: `medium`
- Area: `decrypt-verify-ui`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/ffff6cd467088191ab32b29040dd40ab)
- Decision: Confirmed trust UI correctness issue. Decrypt text and file modes share one signature verification state that can mismatch the visible output.
- Impact: The visible signature section can appear to apply to output from another mode. This is a trust UI correctness problem, not a verification bypass.
- Relevant paths: `Sources/App/Decrypt/DecryptView.swift`
- Fix plan: Represent text and file decrypt results as separate atomic `output + DetailedSignatureVerification` values, and render only the verification owned by the currently visible result.
- Validation: Add text/file mode switching tests showing each visible output renders only its own signature verification state.

### SR-FIX-17: Selector discovery exposes unauthenticated User IDs

- Legacy ID: `CA-38`
- Severity: `low`
- Area: `selector-discovery`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/f6c9737226248191a651f043b8b6f146)
- Decision: Confirmed low-impact OpenPGP validity display issue. Selector discovery exposes unauthenticated User IDs without distinguishing them in data or UI.
- Impact: A user can be socially engineered into certifying an identity not self-bound by the key owner. Harm requires an external consumer of that certification.
- Relevant paths: `pgp-mobile/src/keys.rs`, `Sources/Services/FFI/PGPCertificateSelectionAdapter.swift`, `Sources/Models/UserIdSelectionOption.swift`
- Fix plan: Add an authenticated/self-binding flag to the Rust selector record and propagate it through UniFFI/Swift models. Surface unauthenticated User IDs in UI and consider gating certification.
- Validation: Add Rust selector tests for bare User ID packets plus Swift/UI tests for unauthenticated indicators or certification gating after UniFFI regeneration.

### SR-FIX-18: Production Xcode target compiles security test mocks

- Legacy ID: `CA-40`
- Severity: `low`
- Area: `build-integration`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/715f18cb62e48191abe332c39da5f2bd)
- Decision: Confirmed deferred architecture hardening. Security mocks are compiled into the app module even though production composition does not currently select them.
- Impact: No evidence shows production user keys are currently protected by mocks. The risk is future accidental mock selection because mocks share the app module.
- Relevant paths: `CypherAir.xcodeproj/project.pbxproj`, `Sources/Security/Mocks/MockAuthenticator.swift`, `Sources/Security/Mocks/MockKeychain.swift`, `Sources/Security/Mocks/MockSecureEnclave.swift`
- Fix plan: Handle during broader componentization: move test-only mocks outside the app target and scope tutorial software security implementations as tutorial-only simulation.
- Validation: During architecture work, add target membership/build checks proving test-only mocks are not compiled into production targets.

### SR-FIX-19: Concurrent tutorial contacts open can fail sandbox setup

- Legacy ID: `CA-41`
- Severity: `informational`
- Area: `tutorial-contacts`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/703d8b5d0ad48191abf6a936394d174e)
- Decision: Confirmed tutorial-only reliability issue. Repeated module opens can start concurrent contacts-domain opens in the disposable tutorial sandbox.
- Impact: Disposable tutorial sandbox setup can fail or clean up the active tutorial container. Production keys, contacts, settings, and protected data are isolated.
- Relevant paths: `Sources/App/Onboarding/TutorialSessionStore.swift`, `Sources/App/Onboarding/TutorialSandboxContainer.swift`, `Sources/Services/ContactService.swift`
- Fix plan: Make tutorial contacts opening idempotent by disabling repeated opens while opening or caching/reusing one in-flight contacts-open task in the tutorial sandbox container.
- Validation: Add tutorial sandbox tests or UI smoke coverage for rapid repeated module opens while contacts are opening.

### SR-FIX-20: Text input section is recreated on every edit

- Legacy ID: `CA-42`
- Severity: `informational`
- Area: `decrypt-verify-ui`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/3f03eebb98448191b26dbb3af9dcafa0)
- Decision: Confirmed UX/availability issue. Decrypt/Verify text input sections are recreated during ordinary edits, disrupting keyboard focus.
- Impact: Manual correction of ciphertext or signed text can lose focus, cursor, selection, or keyboard state. Decrypt/verify correctness and secrecy are not changed.
- Relevant paths: `Sources/App/Decrypt/DecryptView.swift`, `Sources/App/Sign/VerifyView.swift`
- Fix plan: Split edit invalidation from section refresh. Ordinary edit paths should clear stale result/phase state without bumping the text input section identity; import/reset/completion paths can still refresh when needed.
- Validation: Add SwiftUI model/view tests or targeted UI smoke coverage showing backspace/editing does not recreate the text editor section or dismiss keyboard focus.
