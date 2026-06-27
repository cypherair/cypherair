# Codex Security Review Fix Plan

This document is the implementation planning record for active accepted security-review follow-ups. Use the `SR-FIX-*` IDs in future issues, commits, and pull requests. Closed items are moved to `docs/CODEX_SECURITY_REVIEW_CLOSED.md` with a new `SR-CLOSED-*` ID while retaining their former `SR-FIX-*` and legacy `CA-*` references.

## Pending Triage (2026-06-14 Scan)

The 2026-06-14 Codex scan recorded eleven newly detected findings, listed in `docs/CODEX_SECURITY_REVIEW_INDEX.md` as `SR-NEW-01`–`SR-NEW-11`. `SR-NEW-01`, `SR-NEW-02`, and `SR-NEW-03` have been fixed by the short operation-prompt window redesign and moved to the closed record. Per maintainer direction, triage (disposition) and fix planning for the remaining findings are deferred until the in-progress whole-codebase review completes — no `SR-FIX-*` IDs, dispositions, or fix plans are assigned here yet.

- `SR-NEW-04` — Local reset no longer removes legacy LARight root secrets (medium)
- `SR-NEW-05` — Legacy high-security mode can be silently downgraded (medium)
- `SR-NEW-06` — Local reset leaves retired key metadata rows behind (medium)
- `SR-NEW-07` — Legacy grace period reset weakens app relock timing (medium)
- `SR-NEW-08` — Foreground resume can briefly reveal locked content (medium)
- `SR-NEW-09` — Hidden recipients remain selected during encryption (medium)
- `SR-NEW-10` — GPG version check uses non-portable macOS sort option (informational)
- `SR-NEW-11` — Perl fixture scrubber allows path-based code injection (informational)

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
- Decision: Confirmed deferred architecture hardening. This remains open after the interim guardrail pass.
- Impact: No evidence shows production user keys are currently protected by mocks. The risk is future accidental mock selection because tutorial/UI-test mocks still share part of the app module.
- Relevant paths: `CypherAir.xcodeproj/project.pbxproj`, `Sources/Security/Mocks/MockAuthenticator.swift`, `Sources/Security/Mocks/MockKeychain.swift`, `Sources/Security/Mocks/MockSecureEnclave.swift`
- Interim guardrail: test-only mocks that do not serve tutorial/UI-test runtime are moved out of `Sources`; `Sources/Security/Mocks` is the only temporary production-source mock directory; ProtectedData production files must not embed mock implementations; non-mock production code must not directly reference `MockKeychainError`; Release and App Store Candidate builds ignore `UITEST_*` app-container launch overrides.
- Remaining fix plan: close SR-FIX-18 only after tutorial migrates away from mock security primitives to tutorial-specific isolated real Protected Data domains and hardware-backed processing that never touches user security assets, and after build/target-membership checks prove test-only mocks are not compiled into production targets.
- Validation: Maintain focused macOS unit tests, mandatory `CypherAir-MacUITests`, Release/App Store Candidate build probes, and human review of production target membership / mock wiring for this interim state.

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
