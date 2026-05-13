# Legacy Cleanup Implementation Reference

> Status: Draft implementation reference / active roadmap.
> Purpose: Convert the legacy compatibility audit into a staged, reviewable
> cleanup roadmap that can guide later implementation plans and PR sequencing.
> Audience: CypherAir maintainers, reviewers, QA, and AI coding agents planning
> legacy, migration, compatibility, and cleanup work.
> Companion audit: [LEGACY_COMPATIBILITY_AUDIT](LEGACY_COMPATIBILITY_AUDIT.md).
> Primary authorities: [AGENTS](../AGENTS.md), [ARCHITECTURE](ARCHITECTURE.md),
> [SECURITY](SECURITY.md), [TESTING](TESTING.md),
> [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md),
> [CONVENTIONS](CONVENTIONS.md), and [CODE_REVIEW](CODE_REVIEW.md).
> Last reviewed: 2026-05-13.
> Update triggers: Any completed cleanup wave, changed old-install support
> policy, removed public Swift or UniFFI compatibility surface, ProtectedData
> migration boundary change, validation workflow change, or audit replacement.

Current code and active canonical docs outrank this roadmap whenever they
disagree. This document is not a statement of current shipped behavior. It is a
future-facing implementation reference for turning the point-in-time audit into
small, reviewable cleanup PRs.

## 1. Role And Source-Of-Truth Rules

[LEGACY_COMPATIBILITY_AUDIT](LEGACY_COMPATIBILITY_AUDIT.md) is the evidence
snapshot. This document is the execution reference that orders that evidence
into cleanup phases.

Use this document to decide:

- which cleanup work can safely happen early
- which tests must move to current APIs before removal
- which migration and recovery paths must first be isolated
- how to split PRs so review risk stays bounded
- what validation each cleanup family needs before merge

Do not use this document to override current behavior or security policy. When
there is a conflict:

- current code wins for observed behavior
- [AGENTS](../AGENTS.md) wins for non-negotiable agent safety constraints
- [ARCHITECTURE](ARCHITECTURE.md) wins for current ownership
- [SECURITY](SECURITY.md) wins for security invariants and sensitive boundaries
- [TESTING](TESTING.md) wins for required validation commands
- [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md) wins for persisted
  state classification
- [CONVENTIONS](CONVENTIONS.md) wins for source organization and PR style
- [CODE_REVIEW](CODE_REVIEW.md) wins for review gates

## 2. Global Cleanup Rules

Every cleanup PR in this program must follow these rules.

- Move valuable tests to current APIs before deleting compatibility APIs.
- Before editing code, re-read the current [AGENTS](../AGENTS.md),
  [SECURITY](SECURITY.md), and [TESTING](TESTING.md) requirements for the
  touched boundary.
- Do not delete migration, recovery, reset, or old-install protection code based
  on keyword matches alone.
- Keep one PR focused on one domain or boundary. Do not bundle Contacts,
  ProtectedData, Rust/UniFFI, and script cleanup into one review.
- Treat ProtectedData, Keychain, authentication, Contacts cutover, decryption,
  QR input parsing, and Rust crypto/FFI changes as sensitive boundaries.
- Do not hand-edit generated UniFFI Swift or headers, including
  `Sources/PgpMobile/pgp_mobile.swift`, `bindings/pgp_mobile.swift`, and FFI
  header/modulemap outputs.
- Do not modify release metadata, entitlements, permission strings, build
  numbers, or app versions as incidental cleanup.
- Preserve zero network access, minimal permissions, AEAD hard-fail behavior,
  secure randomness, secret zeroization, MIE/Enhanced Security capability,
  profile-correct message format selection, and no plaintext or private-key
  logging. Cleanup must not weaken v4 -> SEIPDv1, v6 -> SEIPDv2, and mixed
  recipient -> SEIPDv1 message selection.
- Keep retained migrations fail-closed: source state must not be removed until
  destination state is verified readable.
- Update canonical docs only when a cleanup PR changes current behavior,
  storage classification, security boundaries, or validation expectations.

## 3. Cleanup Strategy

The roadmap is intentionally split into three cleanup classes.

**Early isolated cleanup**

Remove surfaces with no direct callers or active runtime role, provided the PR
stays within one domain and carries focused validation. These PRs should happen
first because they reduce noise without changing migration policy.

**Test migration before deletion**

For compatibility APIs that are still used mostly by tests, first rewrite useful
coverage to current APIs. Delete the compatibility surface only after production
and test references are gone.

**Retain, isolate, then remove after support cutoff**

For old-install migration, recovery, ProtectedData, Contacts cutover, root-secret
migration, and local-data reset paths, do not delete early. First isolate the
legacy logic behind clear owners. Production use of the new protected domains
does not by itself authorize deleting old-install protection. Remove retained
migration or recovery code only after a human maintainer/user explicitly approves
a support cutoff in the specific cleanup issue or PR. Do not use telemetry,
network checks, or ambiguous migration signals as the deletion trigger.

## 4. Phased Roadmap

### Phase 1: Low-Risk Isolated Cleanup

Goal: remove or settle the clearest cleanup candidates without touching multiple
domains in one PR.

Recommended PRs:

- PR 1A, Contacts-only helper cleanup: remove
  `ContactService.availableContacts(matchingKeyIds:)`,
  `ContactService.publicKeys(for:)`, and the deprecated
  `ContactService.publicKeysForRecipientFingerprints(_:)` after one final caller
  check. As of the 2026-05-13 review, these helpers had no production callers.
  Do not remove `legacyPublicKeysForRecipientFingerprints(_:)` or the
  fingerprint recipient compatibility layer in this PR.
  Status: completed in Phase 1A after a final caller check; only the no-caller
  helpers were removed.
- PR 1B, arm64e experiment script decision: either retain
  `scripts/experiments/*` as explicit historical diagnostics, archive it out of
  active script paths, or delete it after maintainers confirm the diagnostics are
  no longer useful. If script posture changes, update
  [ARM64E_STATUS](ARM64E_STATUS.md) in the same PR.

Entry conditions:

- Focused `rg` checks confirm the target helpers or scripts are not required by
  current production paths.
- The PR scope is limited to Contacts helpers or script/docs cleanup, not both.

Exit conditions:

- No current call sites reference the removed Contacts helpers.
- The historical script posture is explicit and no longer ambiguous.
- Phase 1A leaves `legacyPublicKeysForRecipientFingerprints(_:)`,
  `publicKeysForRecipientContactIDs(_:)`, and the broader fingerprint-recipient
  compatibility layer in place for Phase 2.

Validation:

- Contacts PR: focused Swift unit coverage for Contacts and any affected service
  tests.
- Script/docs PR: documentation link checks where relevant and `git diff
  --check`.

### Phase 2: Fingerprint Recipient Compatibility Retirement

Goal: retire recipient-fingerprint encryption compatibility only after tests and
callers move to contact identity IDs.

Recommended PRs:

- PR 2A, Encryption service tests: rewrite valuable
  `recipientFingerprints` coverage in `EncryptionServiceTests` to contact-ID
  recipient APIs.
- PR 2B, Decryption and streaming tests: rewrite ciphertext generation helpers
  in `DecryptionServiceTests` and `StreamingServiceTests` to contact-ID APIs.
- PR 2C, Password and tutorial tests: rewrite
  `PasswordMessageServiceTests` and `TutorialSessionStoreTests` away from
  fingerprint recipient overloads where the behavior remains valuable.
- PR 2D, `EncryptionService` compatibility deletion: remove the
  `recipientFingerprints` text, file, and streaming overloads after all tests and
  production references are gone.
- PR 2E, Contacts resolver deletion: remove
  `ContactService.legacyPublicKeysForRecipientFingerprints(_:)` and the legacy
  fingerprint resolver in `ContactRecipientResolver` only after PR 2D lands.
- PR 2F, route and tutorial preselection cleanup: remove
  `EncryptView.Configuration.initialRecipientFingerprints` and tutorial
  preselection fallback only after tutorial sandbox, UI-test containers, and
  route-driven preselection can reliably provide contact identity IDs.

Entry conditions:

- Current UI and screen models already use contact-ID recipient selection.
- Tests still using fingerprint recipients are classified as valuable behavior
  coverage or compatibility-only coverage.

Exit conditions:

- Production and tests no longer call recipient-fingerprint overloads.
- Contacts recipient resolution has one current path: contact identity IDs to
  preferred encryptable key records.
- Route and tutorial preselection no longer needs fingerprint fallback.

Validation:

- Swift unit tests for encryption, decryption, streaming, password-message, and
  tutorial flows.
- Add targeted macOS UI smoke coverage if tutorial route ownership or visible
  navigation behavior changes.

### Phase 3: Detailed Verification API Adoption

Goal: make detailed signature and decryption verification the default test and
self-test surface before retiring legacy folded-summary compatibility.

Recommended PRs:

- PR 3A, SelfTest detailed API adoption: move `SelfTestService` from simple
  `engine.decrypt` and `engine.verifyCleartext` calls to detailed APIs while
  preserving current self-test semantics.
- PR 3B, signing verification tests: rewrite useful
  `SigningServiceTests` and `SigningServiceDetailedResultTests` coverage to
  assert detailed verification directly.
- PR 3C, decryption and streaming verification tests: rewrite useful
  `DecryptionServiceTests` and `StreamingServiceTests` folded-summary checks to
  detailed verification assertions.
- PR 3D, interop and device tests: rewrite valuable `GnuPGInteropTests`,
  `DeviceMIETests`, and `FFIIntegrationTests` coverage to detailed APIs where
  the test is not explicitly preserving compatibility behavior.
- PR 3E, Swift facade decision: after tests migrate, decide whether legacy
  `SignatureVerification` returning facades should be removed, retained with
  explicit compatibility tests, or marked for a later public API cutoff.

Entry conditions:

- UI screen models already consume detailed verification for current user-facing
  verify/decrypt flows.
- Simple API tests are separated into valuable behavior coverage and explicit
  compatibility coverage.

Exit conditions:

- Self-test and service tests no longer depend on simple APIs except where the
  compatibility contract is explicitly retained.
- Any remaining legacy folded-summary tests are named and scoped as
  compatibility tests.

Validation:

- Swift unit tests for signing, decryption, streaming, password-message, and
  self-test behavior.
- Device MIE coverage when message integrity behavior or device-only security
  expectations are affected.

### Phase 4: Rust And UniFFI API Surface Cleanup

Goal: remove raw first-match User ID FFI APIs only after selector-based APIs are
confirmed as the production contract. Swift service methods that take
`selectedUserId` and internally call selector-backed FFI remain current APIs even
when their Swift names do not include `BySelector`.

Recommended PRs:

- PR 4A, selector contract review: confirm `CertificateSignatureService` and
  `SelectiveRevocationService` call selector-backed FFI for User ID
  certification, verification, and revocation. Do not remove these service-layer
  methods when their signatures require `selectedUserId`.
- PR 4B, selector coverage guardrails: make sure duplicate User ID selection,
  out-of-range selectors, selector byte mismatch, signer-missing behavior, and
  Swift service behavior are covered before deleting raw first-match surfaces.
- PR 4C, Swift FFI raw-call migration: rewrite valuable
  `FFIIntegrationTests` coverage that directly calls `generateUserIdRevocation`,
  `generateUserIdCertification`, or `verifyUserIdBindingSignature` to the
  selector APIs. Delete tests only when they prove first-match compatibility and
  no current behavior.
- PR 4D, Rust raw-helper test migration: rewrite valuable
  `certification_binding_tests`, `revocation_construction_tests`, and
  `selector_discovery_tests` coverage from raw helper calls to selector helper
  calls. Delete tests whose only assertion is legacy first-match duplicate
  behavior.
- PR 4E, UniFFI export and helper deletion: remove raw first-match exports from
  Rust source:
  `verify_user_id_binding_signature`, `generate_user_id_certification`, and
  `generate_user_id_revocation`. Also remove their internal raw helper
  functions and `find_user_id_first_match`. Regenerate bindings through the
  normal workflow. Do not hand-edit generated Swift.

Entry conditions:

- Selector-based APIs cover duplicate User ID selection, out-of-range selectors,
  byte mismatch rejection, and Swift service behavior.
- Downstream or public FFI compatibility expectations have been reviewed.
- Swift and Rust tests have no direct raw first-match calls except explicitly
  retained compatibility tests.

Exit conditions:

- Raw first-match User ID exports and internal raw helpers are gone or
  explicitly retained as deprecated compatibility APIs with named tests.
- Selector-backed Swift service APIs remain available and covered.
- Generated bindings match Rust exports.

Validation:

- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- If Swift-visible FFI changes occur, refresh the XCFramework and generated
  bindings with `./build-xcframework.sh --release`, then run macOS Swift unit
  tests.

### Phase 5: Migration Boundary Isolation Only

Goal: make migration and compatibility ownership explicit without deleting
old-install protection. This phase is behavior-preserving extraction and
isolation only.

Recommended PRs:

- PR 5A, Contacts migration boundary: isolate legacy runtime loading,
  quarantine, cutover, and flat-runtime compatibility away from primary
  `ContactService` business operations.
- PR 5B, protected settings migration boundary: isolate legacy ordinary settings
  import, source removal, and schema v1 to v2 upgrade from current protected
  settings persistence.
- PR 5C, private-key control migration boundary: isolate legacy `UserDefaults`
  auth-mode import and cleanup from current recovery journal behavior.
- PR 5D, key metadata migration boundary: isolate Keychain migration source
  enumeration and cleanup retry behavior from current `key-metadata` domain
  persistence.
- PR 5E, root-secret migration boundary: isolate v1/raw root-secret migration
  and legacy right-store migration from current v2 envelope, format floor, and
  device-binding behavior.
- PR 5F, local cleanup registry: centralize historical self-test, tutorial,
  temporary artifact, and reset cleanup rules so startup and Reset All Local
  Data do not duplicate legacy path knowledge.

Out of scope:

- Do not delete old-install migration, recovery, reset, cleanup retry, or
  fail-closed behavior in Phase 5.
- Do not remove legacy source-state handling merely because production already
  opens protected domains by default.
- Do not weaken current recovery journals, root-secret format floor,
  ProtectedData recovery, current temporary-artifact cleanup, or reset
  validation.

Entry conditions:

- Each PR identifies whether it touches a sensitive boundary before editing.
- Tests already prove the behavior that will be moved.
- The PR describes the exact behavior being moved and the focused owner that
  will hold it after isolation.

Exit conditions:

- Main service files read as current facades or current stores while retained
  migration code lives behind focused owners.
- Legacy, migration, cleanup, and recovery responsibilities have focused owners
  and focused tests.
- Old installs retain the same migration, fallback, cleanup retry, reset, and
  fail-closed semantics.

Validation:

- Contacts: Contacts cutover, quarantine, relock, reset, import, and recipient
  tests.
- ProtectedData and Keychain: `ProtectedDataFrameworkTests`, settings, private
  key control, key metadata, authentication, and reset tests as applicable.
- Root-secret changes: device-binding, v1 to v2 migration, format-floor,
  downgrade rejection, and reset cleanup tests.

### Phase 6: Human-Approved Future Deletion Waves

Goal: delete retained migration code only after a human maintainer/user approves
the support cutoff in the specific cleanup issue or PR. This phase is not
authorized by Phase 5 isolation or by the fact that production paths already use
new protected storage.

Recommended deletion waves:

- Contacts: remove the legacy flat runtime, `openLegacyCompatibilityForTests`
  dependence where possible, `.keyUpdateDetected`, and legacy contact ID
  projection only after supported installs no longer need flat Contacts
  migration or fallback and after tutorial sandbox and UI-test containers no
  longer depend on legacy runtime loading.
- Protected settings: remove legacy ordinary-settings defaults import and schema
  v1 upgrade only after supported installs are expected to hold schema v2.
- Private-key control: remove legacy auth-mode defaults import after old-install
  migration support ends. Do not remove current private-key recovery journals.
- Key metadata: remove legacy Keychain metadata source rows and cleanup retries
  after all supported installs have migrated to ProtectedData.
- Root secret: remove legacy raw/right-store migration only after a formal
  support cutoff for v1/raw and legacy right-store root secrets.
- Local cleanup: remove historical self-test, tutorial, and temporary cleanup
  rules only after those paths can no longer exist on supported installs.

Entry conditions:

- A maintainer/user explicitly approves the support cutoff in the cleanup issue
  or PR.
- The PR records the old source state being abandoned, why it is no longer
  supported, and how old-install failure, recovery, reset, and cleanup behavior
  changes.
- The PR does not rely on telemetry, network checks, or an ambiguous migration
  signal.
- Reset behavior, recovery behavior, and old-install failure modes are reviewed.

Exit conditions:

- Removed migration paths have no supported source state left to protect.
- Canonical persisted-state and testing docs reflect the new cleanup baseline.
- Tests and docs no longer describe the removed old source as supported.

Validation:

- Full affected Swift unit suites for the domain.
- Device or platform validation where Keychain, Secure Enclave, file protection,
  or device-binding behavior is involved.
- Rust tests only when Rust or Swift-visible Rust behavior changes.

Do not delete current security behavior in this phase. The root-secret v2 format
floor, private-key recovery journals, ProtectedData recovery, current temporary
artifact cleanup, AEAD hard-fail behavior, and detailed verification semantics
remain current behavior unless a separate reviewed design changes them.

### Phase 7: Closure And Canonical Sync

Goal: keep the documentation stack synchronized after each cleanup wave.

Recommended PRs:

- PR 7A, wave closure updates: after each completed cleanup wave, update this
  roadmap with completed status, changed sequencing, or newly discovered gates.
- PR 7B, canonical sync: update canonical docs only when shipped behavior,
  persisted-state classification, security invariants, or validation
  expectations changed.
- PR 7C, archive or supersede: when this roadmap is no longer actively consumed,
  archive it or mark it superseded according to
  [DOCUMENTATION_GOVERNANCE](DOCUMENTATION_GOVERNANCE.md).

Validation:

- Docs-only validation, link checks where relevant, and `git diff --check`.
- No Rust or Xcode tests are required for docs-only closure PRs unless they also
  touch code, generated files, project files, entitlements, build settings, or
  release metadata.

## 5. Public Surface Review Gates

Before removing any public Swift or UniFFI compatibility surface, the PR must
answer these questions in its description.

- What current API replaces this surface?
- Which production call sites were checked?
- Which tests were migrated, removed, or retained as explicit compatibility
  tests?
- Does this affect generated UniFFI bindings?
- Does this affect downstream callers or fixture compatibility?
- If this removes migration, recovery, reset, or old-install protection, which
  issue or PR contains the human-approved support cutoff?
- Which canonical docs need updates, if any?

Known surfaces that require this gate:

- recipient-fingerprint encryption overloads
- `EncryptView.Configuration.initialRecipientFingerprints` and route/tutorial
  fingerprint preselection fallback
- legacy `SignatureVerification` returning Swift facades
- simple FFI APIs that expose detailed-fold compatibility
- raw first-match User ID FFI exports
- Contacts legacy flat-runtime APIs, `.keyUpdateDetected`, and legacy contact ID
  projection

## 6. Validation Matrix

| Cleanup family | Minimum validation |
| --- | --- |
| Contacts helpers and recipient cleanup | Focused Swift unit tests for Contacts and affected encryption/decryption service tests. Add macOS UI smoke tests if route or tutorial behavior changes. |
| Swift service API cleanup | Service tests for the touched area, plus screen-model tests when UI-facing model behavior changes. |
| Detailed verification adoption | Signing, verify, decryption, streaming, password-message, self-test, and interop tests as applicable. Device MIE tests when integrity behavior changes. |
| Rust and UniFFI API cleanup | `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`; run `./build-xcframework.sh --release` to refresh XCFramework/generated bindings and run macOS unit tests when Swift-visible behavior changes. |
| ProtectedData, Keychain, authentication, and root-secret migration | `ProtectedDataFrameworkTests` plus affected settings, private-key control, key metadata, authentication, local reset, and device-binding tests. |
| Temporary, tutorial, self-test, and reset cleanup | Startup cleanup, owner cleanup, reset cleanup, file-protection, and local data reset tests. |
| Script or docs-only cleanup | Documentation link checks where relevant and `git diff --check`. |

## 7. Assumptions And Defaults

- This roadmap does not set a calendar date for old-install support cutoff.
  Deletion waves require a human-approved support cutoff in the specific issue
  or PR instead of fixed dates, telemetry, network checks, or ambiguous
  migration signals.
- Early PRs should prefer no-caller, low-coupling cleanup with narrow tests.
- Complex migration and security cleanup defaults to isolate first, delete later.
- Production cutover to a new protected domain is not by itself approval to
  delete old-install migration, recovery, reset, cleanup retry, or fail-closed
  behavior.
- Active documentation remains English.
- Generated files remain generated-only.
