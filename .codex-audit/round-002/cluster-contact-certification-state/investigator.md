# Round 2 Investigator: cluster-contact-certification-state

## CA-06: Reset leaves legacy contact files behind

- Title: Reset leaves legacy contact files behind
- Relevant code locations:
  - `Sources/App/Settings/LocalDataResetService.swift:158-167`, `:212-217`, `:351-459`, `:536-552`
  - `Sources/Services/ContactService.swift:30-69`, `:71-73`
  - `docs/PERSISTED_STATE_INVENTORY.md:71-72`, `:96`
  - `docs/SECURITY.md:334-337`
- Mechanism-present status: Present for unsupported legacy files. Reset removes the ProtectedData root, legacy self-test directory, temporary artifacts, tutorial defaults, Keychain rows, and runtime state, but it does not enumerate or delete `Documents/contacts` or `Documents/contacts.quarantine`.
- Shipped reachability: Legacy/upgraded installs only. Current HEAD does not create, read, migrate, quarantine, or trust those flat contact files, but a user who still has them can run the shipped Reset All Local Data flow and leave them on disk.
- Mitigations:
  - Current Contacts runtime is the protected `contacts` domain, opened after post-auth unlock.
  - Fresh/current installs do not use the legacy flat paths.
  - Source-audit guardrails block reintroducing flat Contacts projection and legacy migration vocabulary.
  - Reset clears in-memory Contacts state and removes the protected Contacts payload through the ProtectedData root.
- Evidence-real:
  - `resetDirectories` contains only `protectedDataStorageRoot.rootURL` and `legacySelfTestReportsDirectory`.
  - Reset postcondition checks do not include the legacy contacts directories.
  - Current persisted-state docs explicitly say unsupported legacy contact files may remain and are not reset-cleaned.
- Evidence-false-positive:
  - The leftover files are not active shipped Contacts state in current HEAD.
  - They do not affect recipient resolution, contact search, certification projection, or trust state because production no longer reads them.
- Preliminary disposition: Real legacy-cleanup/privacy residual, not an active shipped contact-security mechanism. Impact is limited to old local files containing public certs/contact metadata/trust metadata remaining after a reset.
- Confidence: High.
- Open questions:
  - Does the product still promise Reset All Local Data covers unsupported legacy files, despite current docs classifying them outside app state?
  - Is there a supported installed population that could still carry `Documents/contacts` or `contacts.quarantine`?

## CA-09: Untrusted certifications can mark contacts certified

- Title: Untrusted certifications can mark contacts certified
- Relevant code locations:
  - `Sources/Services/CertificateSignatureService.swift:50-78`, `:130-187`, `:204-207`, `:219-254`, `:269-273`
  - `Sources/Models/Contacts/ContactsVerificationContext.swift:3-12`
  - `Sources/Services/ContactService.swift:377-397`, `:486-511`
  - `Sources/Services/ContactSnapshotMutator.swift:549-645`, `:681-723`, `:878-886`
  - `Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift:449-548`
  - `Sources/App/Contacts/ContactKeySummaryView.swift:63-75`, `:165-188`
  - `pgp-mobile/src/cert_signature.rs:45-92`, `:237-287`, `:304-358`, `:375-390`
- Mechanism-present status: Present. Certificate signature verification accepts any current contact key plus own keys as candidate signers. A cryptographically valid certification from any candidate signer becomes a `.valid` artifact; any `.valid` artifact projects the target key as `.certified`.
- Shipped reachability: Shipped production Contacts UI. A user can open Certification Details, import or paste a certification signature, verify it, and save it. This includes certifications from contacts that are not manually verified, and likely extracted self-certifications when the target key itself is in the candidate set.
- Mitigations:
  - Save is user-mediated and only appears after verification produces a valid artifact.
  - User ID selection is validated against exact selector data.
  - Persistence checks target key fingerprint and target certificate digest, and stale target digests are invalidated on recompute.
  - Saved certification artifacts do not mutate manual fingerprint verification state, preferred-key selection, or encryption recipient resolution.
  - Security docs state certificate-signature persistence is not web-of-trust policy.
- Evidence-real:
  - `candidateSignerCertificates()` returns `contactKeys + keyManagement.keys`; there is no manual-verification or trust-policy filter.
  - Rust verification returns `Valid` for any candidate signer whose primary or certification-capable subkey verifies the signature.
  - `validate*CertificationArtifact` creates a persistable artifact whenever `verification.status == .valid`.
  - Projection status becomes `.certified` if any artifact for the key has `validationStatus == .valid`, and the UI displays a green "Certified" badge.
- Evidence-false-positive:
  - This is misleading local metadata, not a direct cryptographic bypass.
  - Manual fingerprint verification remains separate and the UI still warns when the contact key is manually unverified.
  - No automatic recipient trust or preferred-key change follows from certification projection.
- Preliminary disposition: Real shipped trust-state confusion issue. The impact is persistent misleading OpenPGP certification metadata rather than direct confidentiality or authentication failure.
- Confidence: High.
- Open questions:
  - Should saved certification artifacts require an own key, a manually verified contact signer, or an explicit per-signer trust decision?
  - Should self-certifications from the target certificate be excluded from contact certification artifacts?
  - Should the UI distinguish "cryptographically valid certification" from "trusted certification" instead of using a single green Certified state?

## CA-17: Unbounded signature file import can exhaust app memory

- Title: Unbounded signature file import can exhaust app memory
- Relevant code locations:
  - `Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift:139-153`, `:185-191`, `:265-275`, `:489-499`
  - `Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift:190-204`, `:254-260`, `:416-426`, `:638-648`
  - `Sources/App/Contacts/ContactCertificateSignaturesView.swift:117-123`, `:269-324`
  - `Sources/App/Contacts/ContactCertificationDetailsView.swift:117-123`, `:401-485`
  - `Sources/App/Common/TextImport/ImportedTextInputState.swift:14-18`, `:35-42`
- Mechanism-present status: Present, and present in both the older Certificate Signatures screen model and the newer Certification Details screen model. The default import action reads the whole selected URL with `Data(contentsOf:)`, then attempts to construct a UTF-8 `String` from the same bytes.
- Shipped reachability: Shipped production Contacts UI. The user must select a local file through the file importer, but allowed types include `.asc`, `.sig`, `.plainText`, and generic `.data`, so attacker-supplied oversized detached-signature files are plausible.
- Mitigations:
  - Security-scoped access is used.
  - Only one file selection is accepted.
  - Verification/import preview is non-mutating until Save Signature.
  - Imported raw bytes are zeroized when cleared or invalidated.
  - Tutorial route blocklist disables certificate-signature workflows in the tutorial sandbox.
- Evidence-real:
  - No file-size preflight, streaming parser, or upper bound is visible before `Data(contentsOf:)`.
  - For UTF-8 armored input, memory can hold both `Data` and `String`, then store raw data plus visible text in model state.
  - Existing tests cover binary import behavior and stale picker-token handling, but not maximum file size.
- Evidence-false-positive:
  - This is user-mediated local file selection and affects availability, not confidentiality or integrity.
  - The file is not persisted unless a valid certification artifact is later saved.
- Preliminary disposition: Real shipped availability issue.
- Confidence: High.
- Open questions:
  - What maximum byte size should CypherAir accept for detached certification signatures?
  - Should import inspect `URLResourceValues.fileSize` before reading, and avoid creating visible text for oversized data?
  - Should generic `.data` remain allowed for this importer?

## CA-41: Concurrent tutorial contacts open can fail sandbox setup

- Title: Concurrent tutorial contacts open can fail sandbox setup
- Relevant code locations:
  - `Sources/App/Onboarding/TutorialSessionStore.swift:149-187`, `:493-545`, `:547-554`
  - `Sources/App/Onboarding/TutorialSandboxContainer.swift:155-176`
  - `Sources/Services/ContactService.swift:30-69`
  - `Sources/Security/ProtectedData/ContactsDomainStore.swift:49-104`, `:111-177`
  - `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift:142-198`, `:544-560`
  - `Sources/App/Onboarding/Tutorial/TutorialModels.swift:149-188`
  - `Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift:160-168`
- Mechanism-present status: Present. `openModule` is `@MainActor async` and awaits contact opening, allowing another UI task to re-enter before the first open completes. The container guard only skips when availability is already `.availableProtectedDomain`; it does not share or await an in-progress `.opening` operation.
- Shipped reachability: Tutorial-only shipped UI. A rapid double-open or two UI tasks opening modules in the same tutorial session can attempt two opens against the same sandbox `ContactService` and `ContactsDomainStore`.
- Mitigations:
  - The sandbox uses a fixed tutorial defaults suite and a temporary tutorial contacts directory, not real workspace storage.
  - Store-level session/container checks ignore late completions after reset, finish, or cancellation.
  - On failure, cleanup removes the active tutorial container only.
  - Tutorial blocks contact certification routes and disables launching certificate-signature workflows from contact detail.
  - Registry mutation gate serializes lower-level create-domain transactions, limiting corruption, but the second transaction can still fail and drive cleanup.
- Evidence-real:
  - `TutorialSandboxContainer.openContactsIfNeeded()` treats `.opening` as "not available" and starts another detached open.
  - `ContactService.openContactsAfterPostUnlock()` sets `.opening` then calls create/open without an in-progress-open guard.
  - `ProtectedDataRegistryStore.assertMutationPreconditions` rejects a second create when the target domain becomes committed.
  - `TutorialSessionStore.openContactsIfNeeded` catches the error, cleans up the active container, sets it to nil, and records an error.
- Evidence-false-positive:
  - This does not touch real contacts, keys, settings, files, exports, or private-key security assets.
  - It is an availability/data-loss issue for tutorial sandbox state, not production contact confidentiality or trust.
- Preliminary disposition: Real tutorial-only availability issue; informational severity is appropriate.
- Confidence: Medium-high.
- Open questions:
  - Can the current UI generate concurrent `openModule` calls through double-taps or task scheduling in normal use?
  - Should `TutorialSandboxContainer` cache an open task or should `ContactService` make contact-domain open idempotent while availability is `.opening`?
