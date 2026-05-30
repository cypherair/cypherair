# Investigator Trace

## Scope Resolution

- Read `docs/CODEX_SECURITY_REVIEW_INDEX.md` with `rg -n -C 3 'CA-0?6|CA-0?9|CA-17|CA-41|CA-06|CA-09'`.
- Matched each CA-ID to the CSV by `finding_url`, not by inferred line number, using `rg` on these URL suffixes in `codex-security-findings-2026-05-29T13-11-03.346Z.csv`:
  - CA-06: `1a2f54d7f6dc8191a7a7bba0fc3e3204`
  - CA-09: `784c0115a134819188d3ebac0d5d8ac3`
  - CA-17: `eddd21469998819181bbf2a643064c09`
  - CA-41: `703d8b5d0ad48191abf6a936394d174e`
- CSV titles/descriptions confirmed:
  - CA-06: `Reset leaves legacy contact files behind`
  - CA-09: `Untrusted certifications can mark contacts certified`
  - CA-17: `Unbounded signature file import can exhaust app memory`
  - CA-41: `Concurrent tutorial contacts open can fail sandbox setup`

## Apple Docs Lookup

- Searched available tools with `tool_search` for `DocumentationSearch Apple developer documentation lookup Xcode` and `Apple Developer DocumentationSearch DocumentationSearch`.
- XcodeBuildMCP tools were available, but no Apple documentation lookup / `DocumentationSearch` tool was exposed.
- Apple docs lookup not available.

## Commands And Files Inspected

- Repository orientation:
  - `pwd`
  - `ls -la .codex-audit/round-002/cluster-contact-certification-state`
  - `git status --short`
  - `wc -l docs/CODEX_SECURITY_REVIEW_INDEX.md codex-security-findings-2026-05-29T13-11-03.346Z.csv`
- Documentation searches:
  - `rg -n 'Contact|contact|certif|signature|tutorial|reset|quarantine|legacy' docs/ARCHITECTURE.md docs/SECURITY.md docs/TESTING.md docs/CONVENTIONS.md`
  - `rg -n 'contacts\\.quarantine|Documents/contacts|...|legacy.*Contacts' Sources Tests docs`
  - Key docs inspected: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/TESTING.md`, `docs/PERSISTED_STATE_INVENTORY.md`, `docs/LEGACY_COMPATIBILITY_AUDIT.md`, `docs/TDD.md`.
- Code searches:
  - `rg -n 'legacy|quarantine|contacts|ContactsDomain|reset|certif|Signature|openContacts|TutorialSandbox' Sources/Services Sources/App/Contacts Sources/App/Onboarding Sources/App/Settings`
  - `rg -n 'struct Contact|class Contact|enum Contact|ContactCertification|Certification|CertificateSignature|validationStatus|verification\\.status|Data\\(contentsOf:|openContactsIfNeeded|openModule|LocalDataResetService|reset' Sources Tests`
  - `rg -n 'candidateSignerCertificates|candidateSignerPublicKeyData|contactsVerificationContext\\(\\)|verificationContext\\(' Sources Tests`
  - `rg -n 'importContact\\(|verificationState:' Sources/App Sources/Services Tests/ServiceTests`

## Evidence Notes

### CA-06

- `Sources/App/Settings/LocalDataResetService.swift:158-167`: iterates `resetDirectories`, then temporary reset targets.
- `Sources/App/Settings/LocalDataResetService.swift:212-217`: `resetDirectories` is only `protectedDataStorageRoot.rootURL` and `legacySelfTestReportsDirectory`.
- `Sources/App/Settings/LocalDataResetService.swift:351-459`: postconditions cover protected data, root secret/device-binding/format-floor/legacy-cleanup Keychain rows, self-test directory, keychain services, Secure Enclave handles, temp targets, key/contact runtime counts. No `Documents/contacts` or `contacts.quarantine`.
- `Sources/App/Settings/LocalDataResetService.swift:536-552`: temp cleanup covers `temporaryArtifactStore.cleanupTemporaryArtifacts()` and `cleanupTutorialDefaultsSuites()`.
- `Sources/Services/ContactService.swift:30-69`: contacts open through `ContactsDomainStore`; first creation uses `ContactsDomainSnapshot.empty()`.
- `docs/PERSISTED_STATE_INVENTORY.md:71-72`: unsupported legacy contacts files/metadata are not read, migrated, quarantined, reset-cleaned, or proactively deleted.
- `docs/PERSISTED_STATE_INVENTORY.md:96`: current production code does not read/migrate/quarantine/reset-clean/proactively delete unsupported legacy Contacts files.
- `docs/SECURITY.md:334-337`: legacy flat Contacts files are outside the supported app-state model.

### CA-09

- `Sources/Services/CertificateSignatureService.swift:204-207`: candidate signers are `contactKeys + keyManagement.keys`.
- `Sources/Models/Contacts/ContactsVerificationContext.swift:7-12`: verification keys include all contact key public data when contacts are available.
- `Sources/Services/CertificateSignatureService.swift:130-187`: valid verification creates `ContactCertificationArtifactValidation` with a persistable artifact.
- `Sources/Services/CertificateSignatureService.swift:230-247`: artifact is created with `validationStatus: .valid`.
- `Sources/Services/ContactService.swift:377-397`: saving valid artifact persists through protected runtime rollback.
- `Sources/Services/ContactSnapshotMutator.swift:549-602`: save path checks valid status, target key fingerprint, target digest, and persistence payload, but no signer trust state.
- `Sources/Services/ContactSnapshotMutator.swift:681-723`: recomputes per-key certification projections.
- `Sources/Services/ContactSnapshotMutator.swift:878-886`: any `.valid` artifact yields projection `.certified`.
- `Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift:496-548`: imported signature verification can create `pendingArtifact`, then `savePendingSignature()` persists it.
- `Sources/App/Contacts/ContactKeySummaryView.swift:63-75`, `:165-188`: UI displays OpenPGP Certification and green Certified badge for `.certified`.
- `pgp-mobile/src/cert_signature.rs:237-287`, `:304-358`: Rust returns valid for any candidate signer key that verifies direct-key or User ID binding signature.
- `Tests/ServiceTests/CertificateSignatureServiceTests.swift:520-533`: test intentionally preserves contact-then-own candidate multiplicity, showing no trust filtering.

### CA-17

- `Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift:139-153`: default import reads `Data(contentsOf:)` under security-scoped access, then `String(data:encoding:)`.
- `Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift:185-191`: allowed import types are `.asc`, `.sig`, `.plainText`, `.data`.
- `Sources/App/Contacts/ContactCertificateSignaturesScreenModel.swift:265-275`: imported data and visible text are stored in model state.
- `Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift:190-204`: same unbounded import pattern in Certification Details.
- `Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift:254-260`: same broad content types.
- `Sources/App/Contacts/ContactCertificationDetailsScreenModel.swift:416-426`: imported data/text are assigned to `ImportedTextInputState` and `signatureInput`.
- `Sources/App/Common/TextImport/ImportedTextInputState.swift:14-18`, `:35-42`: raw data is stored and zeroized on clear.
- `Sources/App/Contacts/ContactCertificateSignaturesView.swift:117-123` and `Sources/App/Contacts/ContactCertificationDetailsView.swift:117-123`: SwiftUI file importers route selected URL(s) into the model.
- `Tests/ServiceTests/ContactCertificateSignaturesScreenModelTests.swift:343-461`, `:1084-1111`: tests cover binary import and stale picker-token behavior, but no file-size limit was found.

### CA-41

- `Sources/App/Onboarding/TutorialSessionStore.swift:149-187`: `openModule` is async on the main actor and awaits contact opening before routing.
- `Sources/App/Onboarding/TutorialSessionStore.swift:514-545`: open failure cleans up the active container and sets `container = nil`.
- `Sources/App/Onboarding/TutorialSandboxContainer.swift:155-176`: `openContactsIfNeeded` returns only if availability is `.availableProtectedDomain`; `.opening` starts another detached open.
- `Sources/Services/ContactService.swift:44-68`: opening sets availability `.opening`, then performs ensure/open; failures clear runtime state to `.recoveryNeeded`.
- `Sources/Security/ProtectedData/ContactsDomainStore.swift:49-104`: `ensureCommittedIfNeeded` can start domain creation.
- `Sources/Security/ProtectedData/ContactsDomainStore.swift:111-177`: open rejects pending mutation and can mark recovery.
- `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift:142-198`: create-domain transaction journals pending mutation and commits membership.
- `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift:544-560`: second create fails if pending mutation exists or target is already committed.
- `Tests/ServiceTests/TutorialSessionStoreTests.swift:92-151`: tests cover reset/finish/cancellation races, but `rg` found no concurrent same-session open test.
- Tutorial isolation/mitigation evidence: `docs/SECURITY.md:360-370`, `Sources/App/Onboarding/Tutorial/TutorialModels.swift:149-188`, `Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift:160-168`.

## Validation

- No build or test suite was run; this was a read-only investigation plus writing the requested audit artifacts.
- `git status --short` was clean before writing the two `.codex-audit` files.
