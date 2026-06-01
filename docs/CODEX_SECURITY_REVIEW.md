# Codex Security Review Fix Plan

This document is the implementation planning record for active accepted security-review follow-ups. Use the `SR-FIX-*` IDs in future issues, commits, and pull requests. Closed items are moved to `docs/CODEX_SECURITY_REVIEW_CLOSED.md` with a new `SR-CLOSED-*` ID while retaining their former `SR-FIX-*` and legacy `CA-*` references.

## Fix Queue

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

### SR-FIX-21: Public docs disclose unfixed security findings

- Legacy ID: none
- Severity: `medium`
- Area: `security-review-docs`
- Source: [finding](https://chatgpt.com/codex/cloud/security/findings/90434042d17c819187a2df545d7848e4)
- Decision: Confirmed documentation governance follow-up. The public security-review records currently describe unresolved findings in enough detail to lower attacker effort against issues that have not yet been fixed.
- Impact: Public documentation can expose exploit-relevant implementation details before the corresponding code or workflow hardening has landed. This is a documentation and disclosure-control issue, not an app-runtime vulnerability by itself.
- Relevant paths: `docs/CODEX_SECURITY_REVIEW.md`, `docs/CODEX_SECURITY_REVIEW_INDEX.md`
- Fix plan: Define and apply a public documentation policy for active security findings, including what can remain in the repository versus what should stay in Security Cloud or another restricted record until the finding is closed.
- Validation: Re-run the Security Cloud scan after the documentation policy is applied and confirm active public records no longer disclose unresolved exploit-relevant details beyond the chosen policy.
