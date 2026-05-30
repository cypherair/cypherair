# Adversary Trace: cluster-contact-certification-state

I did not read `.codex-audit/round-002/cluster-contact-certification-state/investigator-trace.md`.

No repository source files were edited. The only intended writes are this trace and `adversary.md`.

## Initial Orientation

- `pwd && rg -n "CA-06|CA-09|CA-17|CA-41" docs/CODEX_SECURITY_REVIEW_INDEX.md codex-security-findings-2026-05-29T13-11-03.346Z.csv .codex-audit/round-002/cluster-contact-certification-state/investigator.md`
  - Confirmed worktree path.
  - Index rows: `docs/CODEX_SECURITY_REVIEW_INDEX.md:44`, `:47`, `:55`, `:79`.
  - Investigator report sections: `investigator.md:3`, `:31`, `:66`, `:97`.
- `ls -la .codex-audit/round-002/cluster-contact-certification-state`
  - Directory initially contained only `investigator.md` and `investigator-trace.md`.
- `git status --short`
  - Clean at start.
- `nl -ba .codex-audit/round-002/cluster-contact-certification-state/investigator.md | sed -n '1,180p'`
  - Read investigator claims and line references: CA-06 `:3-30`, CA-09 `:31-64`, CA-17 `:66-95`, CA-41 `:97-128`.
- `sed -n '1,8p' codex-security-findings-2026-05-29T13-11-03.346Z.csv && rg -n "Reset leaves legacy|Untrusted certifications|Unbounded signature|Concurrent tutorial" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - CSV rows: CA-06 line `7`, CA-09 line `10`, CA-17 line `18`, CA-41 line `42`.
- One exploratory `rg` command with unescaped Markdown backticks produced `zsh:1: command not found: contacts`; it was read/search-only and made no filesystem changes.

## Shared Documentation Inspected

- `docs/SECURITY.md`
  - Certificate-signature workflow note: `:85`.
  - Contacts app-data security invariants and unsupported legacy flat Contacts classification: `:334-337`.
- `docs/PERSISTED_STATE_INVENTORY.md`
  - Contacts protected payload: `:69`.
  - Unsupported legacy contact files/metadata: `:71-72`.
  - Contacts legacy plaintext sources must remain inactive and are not reset-cleaned: `:96`.
- `docs/ARCHITECTURE.md`
  - Tutorial sandbox isolation: `:99-110`.
  - Current certification/binding workflow owner: `:121`.
  - Contacts protected-domain ownership and no legacy flat reads: `:263-276`.
- `docs/TESTING.md`
  - Source audit guardrails against legacy flat Contacts projection: `:116`.
  - TutorialSessionStoreTests canonical coverage: `:126`.
  - Contacts protected-domain validation requirements: `:155`, `:172-176`.
  - Certification/binding validation requirements: `:440-460`.
- `docs/CODE_REVIEW.md`
  - Contacts protected-domain and no legacy fallback checklist: `:51`.
- `docs/TDD.md`
  - Legacy flat Contacts outside supported app state and not reset-cleaned: `:440-443`.
- `docs/ARCHITECTURE_REFACTOR_ROADMAP.md`
  - PR3D completed support cutoff and reset no longer manages legacy flat Contacts: `:156-159`.
- `docs/LEGACY_COMPATIBILITY_AUDIT.md`
  - Contacts legacy runtime completed cleanup candidate and source-audit guardrails: `:75`.

## CA-06 Sources Inspected

- `Sources/App/Settings/LocalDataResetService.swift`
  - Reset workflow and directory deletion loop: `:92-186`.
  - `resetDirectories` includes only ProtectedData root and legacy self-test directory: `:212-217`.
  - Postcondition validation lacks legacy contacts directory checks: `:351-459`.
  - Temporary/tutorial cleanup only: `:536-552`.
- `Sources/Services/ContactService.swift`
  - Protected-domain-only open path and reset in-memory state: `:30-73`.
- `Sources/App/AppContainer.swift`
  - Production document directory only used for legacy self-test path, not legacy Contacts: `:405-408`, reset service wiring `:566-587`.
- `Sources/App/AppStartupCoordinator.swift`
  - Startup cleanup removes temporary/tutorial and legacy self-test only: `:123-150`.
- `Sources/Security/ProtectedData/ProtectedDataStorageRoot.swift`
  - ProtectedData root under Application Support and protected-artifact checks: `:23-45`, `:98-111`.
- Tests:
  - `Tests/ServiceTests/LocalDataResetServiceTests.swift:9-113` proves reset removes ProtectedData root, Keychain rows, legacy self-test, memory state.
  - `Tests/ServiceTests/LocalDataResetServiceTests.swift:335-405` proves remaining current protected/keychain data fails closed.
  - `Tests/ServiceTests/ProtectedDataFrameworkTests.swift:1617-1810` proves startup legacy self-test cleanup and protected-domain graph setup.
  - `Tests/ServiceTests/ArchitectureSourceAuditTests.swift:875-885` blocks legacy Contacts runtime vocabulary.
  - `Tests/ServiceTests/ContactServiceTests.swift:709-720` blocks selected Security-layer service dependencies.
- Search:
  - `rg -n "ContactRepository|ContactsLegacyMigrationSource|ContactsCompatibilityMapper|struct Contact\\b|class Contact\\b|contacts\\.quarantine|Documents/contacts" Sources Tests docs --glob '!docs/archive/**'`
  - Found no production legacy Contact repository/migration code; only docs/tests/audit guardrails.

## CA-09 Sources Inspected

- `Sources/Services/CertificateSignatureService.swift`
  - Direct/user-ID verification passes candidate signer set: `:50-78`.
  - Artifact validation saves any `.valid` verification: `:130-201`.
  - Candidate signer certificates are contact keys plus own keys: `:204-207`.
  - Persisted artifact metadata and `.valid` status: `:219-254`.
  - Verification context: `:269-273`.
- `Sources/Models/Contacts/ContactsVerificationContext.swift`
  - `verificationKeys` returns all contact key public data when available, no manual-verification filter: `:7-12`.
- `Sources/Services/ContactService.swift`
  - Save certification artifact path: `:377-397`.
  - Candidate signer public key data and verification context: `:486-511`.
  - Recipient public-key resolution call: `:491-500`.
- `Sources/Services/ContactSnapshotMutator.swift`
  - Save artifact validation/dedup/projection recompute: `:549-645`.
  - Projection recompute and stale target digest handling: `:681-723`.
  - Projection becomes `.certified` if any valid artifact exists: `:878-890`.
- `Sources/Models/Contacts/ContactCertificationArtifactReference.swift`
  - Artifact fields and validation status: `:83-103`.
  - Persistence validation for valid artifacts: `:178-215`.
- `Sources/Models/Contacts/ContactKeyRecord.swift`
  - Manual verification, usage state, certification projection, and public key are separate fields: `:19-23`.
- `Sources/Models/Contacts/ContactKeySummary.swift`
  - `isVerified` uses manual verification; `isOpenPGPCertified` uses certification projection: `:32-38`.
- `Sources/Services/ContactSummaryProjector.swift`
  - Recipient summaries use preferred key and manual/certification projections are simply copied from key record: `:30-45`, `:97-116`.
- `Sources/Services/ContactRecipientResolver.swift`
  - Encryption recipient keys are selected by contact ID, preferred usage, and encryptability only: `:3-26`.
- `Sources/Services/EncryptionService.swift`
  - Encrypt APIs use `ContactService.publicKeysForRecipientContactIDs`: `:74-89`, `:173-190`.
- `Sources/App/Encrypt/EncryptScreenModel.swift`
  - Unverified recipient warning derives from preferred key manual verification: `:182-184`, `:257-265`, `:397-402`, `:707-711`.
- `Sources/App/Encrypt/EncryptRecipientsSection.swift`
  - UI shows Unverified badge and warning from manual verification: `:85-90`, `:114-124`.
- `Sources/App/Encrypt/EncryptScreenPresentations.swift`
  - Confirmation dialog for unverified recipients: `:78-92`.
- `Sources/App/Contacts/ContactDetailView.swift`
  - Trust section separates manual verification and OpenPGP certification: `:266-335`.
  - Contact-level green Certified summary if any key certified: `:416-442`.
- `Sources/App/Contacts/ContactKeySummaryView.swift`
  - Unverified warning remains separate: `:52-61`.
  - Per-key OpenPGP Certification badge title/color maps `.certified` to green “Certified”: `:63-75`, `:165-188`.
- `Sources/Models/CertificateSignatureSignerIdentity.swift`
  - Signer identity knows whether a contact signer is manually verified: `:18-26`.
- `Sources/App/Contacts/ContactCertificateSignaturesView.swift`
  - Older signer identity UI shows Contact/Your Key/Unknown and only adds “Verified Contact” for verified contacts: `:620-679`.
- `Sources/App/Contacts/ContactCertificationDetailsView.swift`
  - Current details signer identity view shows name/fingerprint but no signer trust badge: `:646-669`.
- `Sources/Services/FFI/PGPCertificateOperationAdapter.swift`
  - FFI result mapped to crypto-only verification and signer identity: `:44-82`, `:170-181`, `:235-246`.
- `pgp-mobile/src/cert_signature.rs`
  - Verification result status is crypto-only: `:19-43`.
  - Direct-key and user-ID verification parse candidate signers: `:45-92`.
  - Candidate signer parse and eligible verification keys: `:181-220`.
  - Direct-key verification accepts any matching candidate signer: `:237-301`.
  - User-ID verification accepts any matching candidate signer: `:304-373`.
  - Valid result records signer fingerprints only after crypto success: `:375-390`.
- Tests:
  - `Tests/ServiceTests/ContactServiceTests.swift:2922-2980` saves valid artifact and persists `.certified`.
  - `Tests/ServiceTests/ContactServiceTests.swift:2982-3013` explicitly proves certification projection does not change manual verification.
  - `Tests/ServiceTests/ContactServiceTests.swift:3270-3308` proves valid digest projection remains `.certified`.
  - `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1346-1360` verifies a direct-key signature with the target certificate as candidate signer.

## CA-17 Sources Inspected

- `Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift`
  - Default file import closure uses security-scoped `Data(contentsOf:)` and `String(data:)`: `:139-153`.
  - Allowed content types include `.asc`, `.sig`, `.plainText`, `.data`: `:185-191`.
  - File importer result/handle path stores data and visible text: `:252-275`.
  - Current signature data uses raw imported bytes until edited, otherwise `Data(signatureInput.utf8)`: `:489-499`.
- `Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift`
  - Default file import closure uses security-scoped `Data(contentsOf:)` and `String(data:)`: `:190-204`.
  - Allowed content types include `.asc`, `.sig`, `.plainText`, `.data`: `:254-260`.
  - File importer result/handle path stores data and visible text: `:403-426`.
  - Current signature data uses raw imported bytes until edited, otherwise `Data(signatureInput.utf8)`: `:638-648`.
- `Sources/App/Common/TextImport/ImportedTextInputState.swift`
  - Stores `rawData`, `fileName`, `textSnapshot`; zeroizes raw bytes on clear: `:5-18`, `:35-42`.
- Views:
  - `Sources/App/Contacts/ContactCertificateSignaturesView.swift:117-123` SwiftUI file importer allows single selection.
  - `Sources/App/Contacts/ContactCertificateSignaturesView.swift:269-324` import button and footer.
  - `Sources/App/Contacts/ContactCertificationDetailsView.swift:117-123` SwiftUI file importer allows single selection.
  - `Sources/App/Contacts/ContactCertificationDetailsView.swift:401-487` import/verify/save UI.
- Tests:
  - `Tests/ServiceTests/ContactCertificateSignaturesScreenModelTests.swift:342-461` binary import/raw-data/stale token behavior for older model.
  - `Tests/ServiceTests/ContactCertificateSignaturesScreenModelTests.swift:1084-1111` stale token behavior for details model.
  - `Tests/ServiceTests/CommonHelpersTests.swift:1448-1500` imported text state raw-data persistence and clearing behavior.
- Search:
  - `rg -n "ContactCertificateSignaturesScreenModel|ContactCertificationDetailsScreenModel|signatureFileImportAction|allowedImportContentTypes|large|rawData|FileImportRequestGate|Save Signature|untrusted|unverified|certified" Tests Sources/App/Contacts Sources/Services pgp-mobile/tests`
  - Found no maximum-size coverage for certification signature import.

## CA-41 Sources Inspected

- `Sources/App/Onboarding/TutorialSessionStore.swift`
  - Default `openTutorialContacts` dependency: `:31-34`.
  - `openModule` awaits `openContactsIfNeeded`: `:149-187`.
  - `ensureSession`/container recreation: `:493-512`.
  - Tutorial contacts open error path cleans active container and records error: `:514-545`.
  - Current-session guard: `:547-554`.
- `Sources/App/Onboarding/TutorialSandboxContainer.swift`
  - Isolated sandbox graph and temporary contacts directory: `:20-49`, `:58-72`.
  - Mock security primitives and protected contacts store setup: `:74-153`.
  - `openContactsIfNeeded` only skips `.availableProtectedDomain`; detached open; throws unless available: `:155-176`.
  - Cleanup removes contacts directory and fixed defaults suite: `:178-185`.
  - Tutorial ContactsDomainStore setup: `:191-215`.
- `Sources/Services/ContactService.swift`
  - `openContactsAfterPostUnlock` sets `.opening` and has no in-progress-open guard: `:30-69`.
- `Sources/Security/ProtectedData/ContactsDomainStore.swift`
  - `ensureCommittedIfNeeded` creates Contacts domain only if not committed and no pending mutation: `:49-104`.
  - `openDomainIfNeeded` fails on pending mutation or missing committed domain: `:110-177`.
- `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift`
  - Create-domain transaction serialized by mutation gate: `:142-199`.
  - Mutation preconditions reject pending mutation or already-committed create target: `:544-560`.
- Tutorial isolation/routing:
  - `Sources/App/Onboarding/OnboardingView.swift:155` says tutorial actions never touch real keys/contacts/settings/files/exports/private-key assets.
  - `Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift:160-168` disables certificate-signature launch in tutorial contact detail.
  - `Sources/App/Onboarding/Tutorial/TutorialModels.swift:149-190` blocks certificate signature routes in tutorial.
  - `Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift:15-22`, `:95-110`, `:120-128` applies blocklist and disabled contact detail configuration.
  - `Sources/App/Onboarding/TutorialView.swift:197-204` module launch button starts `Task { await tutorialStore.openModule(module) }`.
  - `Sources/App/Onboarding/Tutorial/TutorialShellTabsView.swift:105-108` macOS module list starts the same task.
- Tests:
  - `Tests/ServiceTests/TutorialSessionStoreTests.swift:39-57` verifies sandbox storage/mocks and not `/Documents/contacts`.
  - `Tests/ServiceTests/TutorialSessionStoreTests.swift:81-151` covers openModule and late completion after reset/finish/cancel.
  - `Tests/ServiceTests/TutorialSessionStoreTests.swift:483-494` route blocklist includes certificate-signature routes.
  - `Tests/ServiceTests/TutorialSessionStoreTests.swift:574-581` contact detail configuration shows but disables certificate-signature entry.
