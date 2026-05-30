# Round 2 Adversary: cluster-contact-certification-state

Scope: CA-06, CA-09, CA-17, CA-41.

Position: the investigator generally found real mechanisms, but the shipped security impact is lower than the original severities imply. The strongest cross-cutting mitigation is that current Contacts state is protected-domain-only, certification artifacts are explicitly documented as non-WOT policy, recipient encryption still keys off preferred contact keys and manual verification warnings, signature file imports are user-mediated, and the tutorial issue is isolated to disposable sandbox state.

## CA-06: Reset leaves legacy contact files behind

### Challenge Summary

This is not an active current Contacts security mechanism. Current HEAD deliberately cut off legacy flat Contacts support: the app does not read, migrate, quarantine, reset-clean, or trust `Documents/contacts` or `Documents/contacts.quarantine`. The remaining concern is a product/privacy expectation mismatch for upgraded installs that still have unsupported historical files.

### Strongest Evidence Against Real Impact

- Current production Contacts state is the ProtectedData `contacts` domain opened after post-auth unlock; first creation starts from `ContactsDomainSnapshot.empty()`, not legacy files.
- `ContactService.openContactsAfterPostUnlock` only opens `ContactsDomainStore`; it has no legacy flat-file source or fallback.
- Current docs classify old flat files as unsupported legacy state and explicitly say they are not read, migrated, quarantined, reset-cleaned, or proactively deleted.
- Source-audit guardrails block reintroducing flat `Contact`, `ContactRepository`, `ContactsLegacyMigrationSource`, and `ContactsCompatibilityMapper` vocabulary in production Swift sources.
- The leftover files do not influence recipient resolution, contact search, certification projection, import/update decisions, or manual verification state in current HEAD.

### Strongest Evidence Supporting Real Impact

- `LocalDataResetService.resetDirectories` only removes the ProtectedData root and legacy self-test directory; there is no enumeration of `Documents/contacts` or `Documents/contacts.quarantine`.
- Reset postconditions validate ProtectedData, Keychain rows, temporary artifacts, key memory, and ContactService runtime count, but not those old Documents paths.
- The UI/product phrase “Reset All Local Data” and warning copy can reasonably be read as including historical app-created contacts data.
- Legacy contact files can contain public certificates, contact graph/name/email metadata, and manual verification/trust metadata. That is not private key material, but it is still user-local privacy state.

### Practical Shipped Scenario

An old install created flat contact files, the user upgrades to current HEAD, then runs Reset All Local Data before selling/handing off a device or relying on reset for local privacy cleanup. Current app state is wiped, but historical `Documents/contacts` data remains in the app sandbox/backups.

### Final Recommendation

`real-low`

Treat as low-severity privacy cleanup debt, not a medium contact-security issue. If the product explicitly accepts the documented support cutoff for old flat Contacts files, this could be closed as `wont-fix`; the main discussion should decide whether Reset All Local Data promises to clean unsupported legacy app-created data.

### Confidence

High.

### Questions for Main Codex/User Discussion

- Does the user-facing Reset All Local Data contract intentionally include unsupported historical app-created files, or do the docs’ support-cutoff rules govern?
- Is there a supported installed population that can still carry `Documents/contacts` or `Documents/contacts.quarantine` from pre-cutoff releases?
- If fixed, should cleanup be narrow deletion of those two legacy directories only, with no migration/read path reintroduced?

## CA-09: Untrusted certifications can mark contacts certified

### Challenge Summary

The mechanism is present, but the strongest security claim is trust-state confusion, not cryptographic bypass. Current code treats “valid” as cryptographic validity from any known candidate signer, and current docs say certification persistence does not introduce web-of-trust policy. The concern is that the UI projects that crypto-only state as green “Certified” in a Trust section even when the signer is an unverified contact or the target key itself.

### Strongest Evidence Against Real Impact

- Saving a certification artifact does not change manual fingerprint verification state. Existing tests explicitly prove an unverified key can remain `.unverified` while its certification projection becomes `.certified`.
- Recipient encryption does not consult certification projection. It resolves the preferred encryptable key for selected contact IDs, and the Encrypt UI warns/blocks for confirmation based on `preferredKey.isVerified`, not certification state.
- Certification artifacts are stored separately as canonical signature bytes and metadata; they are not inserted into the stored contact certificate and do not alter preferred-key selection.
- Save is user-mediated: the user must import/paste or generate a signature, verify it, and then choose Save Signature for imported artifacts.
- The security documentation explicitly states saved certification artifacts are not web-of-trust policy semantics.

### Strongest Evidence Supporting Real Impact

- `candidateSignerCertificates()` returns all current contact keys plus own public keys; `ContactsVerificationContext.verificationKeys` maps all contact key records with no manual-verification/trust filter.
- The Rust verifier returns `Valid` for any candidate certificate whose primary key or explicit certification subkey verifies the detached certification.
- `validate*CertificationArtifact` turns any `.valid` verification into a persistable artifact, and `saveCertificationArtifact` projects a key as `.certified` when any artifact for that key is valid.
- The UI shows a green “Certified” badge in both the contact-level Trust section and per-key OpenPGP Certification row. That can read as a trust assertion even though the underlying semantics are crypto-only.
- Because the target key is included among contact candidate signers, detached self-certification/direct-key signatures can likely satisfy the same projection path if supplied as standalone artifacts.

### Practical Shipped Scenario

Mallory is already in Contacts but not manually verified. Mallory sends Alice a detached certification over Bob’s key/User ID. Alice imports it in Bob’s Certification Details flow, sees it verify, saves it, and Bob now displays green “Certified.” Encrypting to Bob still shows manual verification warnings if Bob’s key is unverified, but Alice may interpret the green certification state as a trusted endorsement.

### Final Recommendation

`real-low`

Fix-worthy as UI/trust semantics hardening if “Certified” is intended to mean trusted certification. I would not rate it as a medium recipient-security bug unless product requirements say untrusted contact certifications must never be persisted/projected.

### Confidence

Medium-high.

### Questions for Main Codex/User Discussion

- Should “OpenPGP Certification: Certified” mean “cryptographically valid certification exists” or “trusted certification exists”?
- Should imported certifications require signer trust: own key, manually verified contact signer, or explicit per-signer approval?
- Should the UI rename the state to “Signature Verified” or display signer trust next to the projection, especially for unverified contact signers and self-certifications?
- Should target self-certifications be excluded from saved contact certification artifacts?

## CA-17: Unbounded signature file import can exhaust app memory

### Challenge Summary

The mechanism is real but local, user-mediated, and availability-only. The importer reads the selected file fully into `Data`, then may allocate a full UTF-8 `String`, then stores raw bytes and visible text in model state. That is a credible crash path for huge attacker-supplied files, but it requires the user to select the file through a local file importer.

### Strongest Evidence Against Real Impact

- The path is not automatic or network-driven; the user must choose one local file through SwiftUI `fileImporter`.
- Security-scoped access is used, only one file selection is accepted, and no data is persisted unless a later valid certification artifact is saved.
- Raw imported bytes are zeroized when the imported state is cleared or invalidated.
- The blast radius is app availability/UI responsiveness. It does not expose plaintext, private keys, contacts, or certification state by itself.
- Detached certification signatures should normally be small; very large `.sig` files are suspicious user inputs rather than normal operational data.

### Strongest Evidence Supporting Real Impact

- Both the older and newer certification screen models use default `signatureFileImportAction` closures that call `Data(contentsOf:)` before any file-size preflight.
- Both models attempt `String(data: data, encoding: .utf8)` after the full read, so ASCII-armored oversized inputs can duplicate memory pressure.
- The model then stores the raw data and visible text (`ImportedTextInputState.rawData`, `textSnapshot`, and `signatureInput`) until edited or cleared.
- Allowed content types include `.asc`, `.sig`, `.plainText`, and generic `.data`; this does not constrain input to plausible OpenPGP signature sizes.
- Existing tests cover binary import behavior and stale file-picker tokens, but not maximum size rejection.

### Practical Shipped Scenario

An attacker gives the user a very large file named like a certification signature, e.g. `bob-certification.asc` or `bob.sig`. The user selects it from Files in Certification Details. The app reads the entire file on the main-actor import path and may allocate both bytes and text, causing a hang or memory-pressure termination before verification.

### Final Recommendation

`real-low`

This is real availability hardening. It should share the same import-size policy as other armored/signature import DoS fixes, but it is not a confidentiality/integrity issue.

### Confidence

High.

### Questions for Main Codex/User Discussion

- What maximum byte size is acceptable for detached certification signatures and armored signature text?
- Should `.data` remain an accepted content type, or should the importer restrict to `.asc`, `.sig`, and text with size preflight?
- Should the importer use `URLResourceValues.fileSize` and reject large files before security-scoped read/string decoding?

## CA-41: Concurrent tutorial contacts open can fail sandbox setup

### Challenge Summary

The race shape is plausible, but the impact is tutorial-only availability in disposable sandbox state. It does not touch production contacts, real keys, settings, files, private-key security assets, or certification workflows.

### Strongest Evidence Against Real Impact

- `TutorialSandboxContainer` creates an isolated dependency graph using mock Keychain/Secure Enclave primitives, fixed tutorial defaults, and a temporary tutorial contacts directory.
- Tutorial onboarding/user-facing copy says tutorial actions never touch real keys, contacts, settings, files, exports, or private-key security assets.
- Tutorial contact certification routes are blocked by `TutorialUnsafeRouteBlocklist`, and contact detail configuration shows the certificate-signature entry disabled inside the tutorial.
- On failure, `TutorialSessionStore.openContactsIfNeeded` cleans up only the active tutorial container and sets `container = nil`.
- Existing tests cover late completion after reset, finish/cleanup, and task cancellation, reducing stale-result damage even though they do not cover concurrent opens.

### Strongest Evidence Supporting Real Impact

- `openModule` is `@MainActor async` and awaits contacts opening. SwiftUI buttons spawn `Task { await tutorialStore.openModule(...) }`, so another tap/task can re-enter while the first call is suspended.
- `TutorialSandboxContainer.openContactsIfNeeded` only returns early for `.availableProtectedDomain`; it treats `.opening` as not-yet-open and starts another detached open.
- `ContactService.openContactsAfterPostUnlock` clears runtime state to `.opening` and performs create/open without an in-progress task guard.
- `ProtectedDataRegistryStore.performCreateDomainTransaction` serializes mutation, but a second create can fail once the target domain is already committed or while a pending mutation is present.
- `TutorialSessionStore` catches that failure by cleaning up and dropping the active sandbox, so a double-open can lose current tutorial progress/state for that sandbox session.

### Practical Shipped Scenario

A user rapidly double-clicks a tutorial module launch button or uses the macOS module list while the initial tutorial Contacts domain is still opening. Two `openModule` tasks race against the same sandbox `ContactService`. One open succeeds or is in progress; the other sees an unavailable/recovery outcome and causes the active tutorial container to be cleaned up, returning the tutorial to an error/hub state.

### Final Recommendation

`real-low`

Keep as informational/tutorial reliability hardening. An idempotent cached open task would be cleaner, but this should not be treated as a production data-security vulnerability.

### Confidence

Medium.

### Questions for Main Codex/User Discussion

- Can the current visible buttons be double-triggered in normal SwiftUI/macOS use before the first open completes?
- Should idempotence live in `TutorialSandboxContainer` as a cached open task, or in `ContactService` as “await existing open while `.opening`” behavior?
- Is losing tutorial sandbox progress on a rare double-open acceptable, or should the tutorial host suppress repeated module opens while contacts are opening?
