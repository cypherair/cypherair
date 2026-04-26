# App Data Validation And Review Guide

> **Version:** Draft v1.0
> **Status:** Draft future validation guide. This document does not describe current shipped behavior.
> **Purpose:** Define the validation matrix, review checks, and implementation-readiness criteria for the protected app-data proposal.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Primary authority:** [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) for architecture and security rules, and [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) for rollout intent.
> **Companion documents:** [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md)
> **Related documents:** [TESTING](TESTING.md) · [CONTACTS_TDD](CONTACTS_TDD.md)

## 1. Scope And Relationship

This guide centralizes the validation and review material that supports the app-data protection proposal.

It specifies:

- the cross-cutting validation matrix
- failure-path checks that must remain explicit
- implementation-readiness expectations
- review questions and document-level acceptance criteria

This document is a downstream review aid. It does not change the architecture or security model defined in [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md).

## 2. Validation Matrix

### 2.1 Registry Authority

- `ProtectedDataRegistry` is the only authority for committed domain membership
- committed membership stores only `active` or domain-scoped `recoveryNeeded`
- `pendingMutation` is the sole authority for uncommitted create/delete work
- shared-resource lifecycle state never doubles as mutation execution phase
- `cleanupPending` appears only when committed membership is empty
- directory enumeration never drives normal root-secret deletion
- fresh-install/reset validation treats a missing `ProtectedData` root as clean only when no protected-data artifacts remain and the storage contract passes
- a committed domain in domain-scoped `recoveryNeeded` still counts as a member
- orphaned directories or wrapped-DMK artifacts do not implicitly become committed members

### 2.2 Unlock / Relock

- one shared Keychain-protected root-secret record is the single normative app-data authorization boundary
- root-secret retrieval uses `kSecUseAuthenticationContext` with an authenticated `LAContext`
- v2 root-secret payloads add a Secure Enclave device-bound envelope under that same boundary; this must not add a second Face ID / Touch ID prompt
- v2 root-secret authorization fails closed if the SE device-binding key or envelope is missing, corrupted, or unavailable
- v2 `CAPDSEV2` envelope validation fails closed for unsupported envelope/AAD versions, unsupported algorithms, wrong public-key representation, wrong salt/nonce/tag/ciphertext lengths, HKDF sharedInfo mismatch, AAD mismatch, ephemeral public-key binding mismatch, tampering, and downgrade from v2 markers to v1 raw payload
- v2 migration writes both registry state and a ThisDeviceOnly Keychain `format-floor` marker; these markers are part of validation because they prevent accepting old root-secret payloads after migration
- v2 AuthTrace records stage/version/status/error metadata only, never root secrets, ECDH shared secrets, HKDF output, private key dataRepresentation, or plaintext payloads
- handoff-only protected-settings auto-open must fail locked without displaying a second prompt if the authenticated `LAContext` is no longer available at consumption time
- launch/resume authentication and root-secret retrieval use the dedicated `AppSessionAuthenticationPolicy`, not private-key `AuthenticationMode`
- the raw root secret is fetched only after app-session authentication succeeds
- if launch/resume immediately enters a route that needs protected-domain content, that same orchestrated flow may activate the shared app-data session without surfacing a later second prompt
- launch/resume authentication alone does not imply that the shared app-data session is already active unless root-secret retrieval and wrapping-root-key derivation also succeed
- a second or third protected domain does not require another prompt in the same active app-data session
- `AppSessionOrchestrator` is the only grace-window owner
- `ProtectedDataSessionCoordinator` does not run an independent grace timer
- relock closes new protected-domain access before cleanup begins
- relock participant fan-out is non-short-circuit
- relock discards or invalidates any session-local `LAContext` retained only for the unlock transaction
- relock clears the derived wrapping root key and all unwrapped domain DMKs
- relock clears decrypted payloads and derived indexes
- relock failure enters `restartRequired`
- `restartRequired` blocks all in-process re-auth and is not persisted to the registry
- backgrounding within the active grace window does not tear down app-data access

### 2.3 Crash Recovery

- startup recovery classifies registry rows through documented invariants plus the consistency matrix before inspecting evidence
- interrupted create/delete operations recover deterministically from registry plus pending mutation state
- orphan shared-resource evidence with empty membership may authorize post-classification `cleanupOnly` under the empty steady-state row without changing row classification or final disposition
- invariant violations or unclassifiable rows enter `frameworkRecoveryNeeded`
- valid `current` and `previous` generations are selected consistently
- no unreadable local state silently resets to empty domain content
- `frameworkRecoveryNeeded` and domain-scoped `recoveryNeeded` are explicit and stable

### 2.4 File Protection

- iOS / iPadOS / visionOS protected-domain files are created with explicit `complete` file protection
- `ProtectedDataRegistry` follows the same explicit file-protection rule
- macOS protected-domain files fail closed unless the storage root is inside the app-owned `Application Support` area and the target volume reports file-protection support
- macOS protected-domain files, registry files, bootstrap metadata files, and staged protected writes explicitly verify `complete` file protection after creation or promotion
- on macOS, `ProtectedDataRegistry` and bootstrap metadata stay inside the same app-owned container boundary
- on macOS, protected-domain payloads are not stored in user-managed document locations by default
- macOS validation verifies containment, ownership, and absence of fallback to broader storage locations
- bootstrap metadata and temporary scratch files follow the same platform-specific protection policy as their host platform

### 2.5 Zeroization

- plaintext serialization buffers are zeroized after use
- raw root-secret bytes are zeroized immediately after wrapping-root-key derivation
- the derived wrapping root key is zeroized on relock
- unlocked domain DMKs are zeroized on relock
- decrypted domain snapshots or derived sensitive indexes are zeroized on relock

### 2.6 Failure Paths

- wrong auth does not unlock the shared app-data session
- pre-auth attempts must not fetch the root-secret Keychain item
- pre-auth key-metadata loading must use only the dedicated non-sensitive metadata account and must not enumerate private-key Keychain rows
- an unauthenticated `LAContext` does not release the root secret
- an interaction-disallowed context that is not already authenticated fails without displaying a second prompt and does not release the root secret
- invariant violation or unclassifiable registry row enters `frameworkRecoveryNeeded`
- orphan shared-resource evidence with empty membership must only authorize post-classification `cleanupOnly` under the empty steady-state row; it must not split registry classification or final disposition
- missing root-secret Keychain record or unreadable root secret for a row that expects `ready` enters `frameworkRecoveryNeeded` before protected-domain access proceeds
- user-cancelled or denied app-session authentication remains a normal access outcome rather than an automatic framework-recovery state
- unreadable wrapped-DMK state enters only that domain's `recoveryNeeded`
- corrupted envelope hard-fails on authentication or structural validation
- interrupted migration does not destroy readable source state
- `ProtectedDataRelockParticipant` failure enters `restartRequired`
- `ProtectedSettingsStore` reset requires explicit destructive confirmation
- Contacts recovery remains import-based
- anti-rollback is not implied by `current / previous / pending`

### 2.7 Repository Validation Ownership

This draft proposal must map its validation buckets onto the repository's existing test layers and commands. This section assigns that ownership for draft-phase implementation work only; `TESTING.md` remains the later synchronization target after approval and implementation maturity.

- registry authority, state-machine, consistency-matrix, and invariant checks belong to Swift unit coverage in `CypherAir-UnitTests` using `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- startup recovery, relock orchestration, and route-handoff integration belong to macOS-local validation using `CypherAir-UnitTests`, with `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'` added whenever launch, routing, or protected-content smoke coverage is part of the change
- unit coverage must verify that pre-auth bootstrap never touches the root-secret store or any root-secret retrieval adapter
- unit coverage must verify that metadata cold-load uses only the dedicated metadata account, and that authenticated legacy metadata migration is retried after app-session unlock without introducing a new prompt
- Keychain root-secret behavior, `kSecUseAuthenticationContext`, real LocalAuthentication prompt semantics, and device-only authorization guarantees belong to `CypherAir-DeviceTests` using `xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests -destination 'platform=iOS,name=<DEVICE_NAME>'`, plus explicit manual device validation whenever automation cannot prove platform prompt timing or system UX behavior
- device coverage should verify that one authenticated `LAContext` can unlock the root-secret Keychain record without a second prompt
- device tests for root-secret storage must use test-only service/account identifiers of the form `com.cypherair.tests.protected-data.<TestCase>.<UUID>`
- device tests must never use the production root-secret identifier
- device tests must perform per-identifier cleanup before and after each test
- legacy `LAPersistedRight` / `LASecret` device coverage belongs only to migration tests if legacy state has already shipped or been provisioned locally
- bootstrap outcome and access-gate coverage belong to Swift unit tests, including explicit assertions that `continuePendingMutation` is preserved and that post-bootstrap validation can distinguish authorization-required vs already-authorized vs framework-recovery paths
- Phase 4 framework-hardening coverage must prove recovery dispatch is keyed by `ProtectedDataDomainID`, that mismatched handlers do not run, that second-domain create/delete/recovery paths are covered, and that shared-resource cleanup for abandoned first-domain creates is derived from post-removal membership
- Phase 4 post-unlock orchestration coverage must prove that app unlock can open registered committed domains with the authenticated `LAContext`, while missing context, no committed domain, or pending mutation states do not read the root secret
- file-protection strength, container containment, fail-closed capability checks, empty-root parent probing, and absence of fallback to broader storage locations belong to Swift unit coverage plus platform-targeted macOS-local verification, with manual verification retained for lock-state semantics that repository automation cannot prove
- Reset All Local Data coverage must prove default-account and metadata-account CypherAir Keychain deletion, missing-item success semantics, in-memory state clearing, retired legacy preference cleanup such as `requireAuthOnLaunch`, and clean empty ProtectedData postconditions
- protected-after-unlock setting migration must prove that pre-auth startup does not read protected payloads, does not fetch the root-secret Keychain item, and does not weaken or change the selected app-session authentication policy
- the `appSessionAuthenticationPolicy` boot authentication profile must stay early-readable unless a future testable design provides a protected value plus boot cache without changing launch authentication strength
- `private-key-control` migration tests must prove that `authMode` and private-key recovery journal data are unavailable pre-auth, that app unlock opens the domain through post-unlock orchestration without a second prompt, and that rewrap / modify-expiry recovery detection runs only after this domain opens
- private-key bundle tests must prove that permanent and pending SE-wrapped private-key rows remain in the existing Keychain / Secure Enclave material domain and are not copied into ProtectedData payloads
- key metadata migration tests must prove that `PGPKeyIdentity` data can load from the future `key metadata` domain after app unlock, that the transitional metadata Keychain account is cleaned only after verified migration, and that startup does not regress to a double-authentication flow or a visible empty-key-list flash
- protected settings route tests must cover the already-on-Settings background/foreground path: after app privacy unlock, `contentClearGeneration` invalidation should non-interactively auto-open protected settings when the session is already authorized or handoff is available
- Phase 8 Contacts migration tests must cover `Documents/contacts/*.gpg` and `Documents/contacts/contact-metadata.json` source preservation, protected-domain readability, and no-silent-reset failure behavior
- self-test persistence tests must prove either protected diagnostics storage or short-lived/export-only cleanup semantics for `Documents/self-test`
- temporary-file tests must cover `tmp/decrypted`, `tmp/streaming`, `tmp/export-*`, and tutorial sandbox cleanup, including relock/reset/startup cleanup where each surface applies
- migration survivability, startup adoption, and no-silent-reset guarantees belong to Swift unit coverage in `CypherAir-UnitTests` plus targeted macOS-local integration validation, adding the `CypherAir-MacUITests` macOS smoke path when startup routing or user-visible recovery flows are part of the scenario

## 3. Implementation Readiness Expectations

This proposal is only acceptable if an implementer can proceed without making hidden architectural decisions.

At minimum, an implementer must be able to tell:

- that the current private-key material domain should remain semantically unchanged
- that private-key control state is a future protected domain target, not an ordinary protected-settings payload
- that protected app data uses one shared Keychain-protected root secret plus per-domain DMKs
- that `ProtectedDataRegistry` is the only membership authority
- that shared-resource lifecycle state and mutation execution phase are distinct concepts
- that `AppSessionOrchestrator` is the app-wide session owner
- that `ProtectedDataSessionCoordinator` is the app-data subsystem coordinator under that owner
- that Keychain / `SecAccessControl` / authenticated `LAContext` root-secret retrieval remains the primary app-data authorization gate
- that the Secure Enclave device-binding layer is an additional root-secret envelope factor, not a second user-authentication prompt or a replacement gate
- that v2 ProtectedData fails closed if the SE device-binding key or envelope is missing, corrupted, or unavailable
- that macOS `CypherAir-UnitTests` cover the v2 envelope and migration state machine through mock device-binding providers, while real Secure Enclave behavior remains limited to guarded DeviceTests
- that any `legacy-cleanup` v1 safety row is deleted after the next successful v2 open and is never used as a fallback authorization source
- that app-data domains are recoverable rather than private-key-style invalidating
- that framework-level and domain-level recovery are distinct
- that startup recovery is registry-first and matrix-driven
- that `restartRequired` is distinct from `frameworkRecoveryNeeded`
- that file protection must be explicit
- that startup is split into pre-auth bootstrap and post-auth unlock phases
- that the generation model does not promise anti-rollback semantics
- that Contacts is a later independent protected domain that depends on the framework rather than inventing its own vault base layer

## 4. Review Questions For Future Implementation

Any implementation derived from this proposal should be reviewable against these questions:

- does it preserve the existing private-key domain without semantic drift?
- does it introduce a reusable protected app-data substrate rather than a one-off vault?
- does it treat one shared Keychain-protected root secret as the first gate for app-data unlock secret access?
- does it use authenticated `LAContext` handoff through `kSecUseAuthenticationContext` rather than undocumented prompt coalescing?
- does it avoid making `AuthenticationMode` the normative gate for future app-data authorization?
- does it fully specify `ProtectedDataRegistry` as the only membership authority?
- does it keep shared-resource lifecycle state distinct from mutation execution phase?
- does it define registry consistency invariants plus a deterministic recovery matrix?
- does it keep recovery registry-first and evidence-second?
- does it fully specify the shared-resource create/delete lifecycle and last-domain rule?
- does it fully specify the DMK persistence and wrapped-DMK model?
- does it make `AppSessionOrchestrator` the only grace-window owner?
- does it keep app-data domains recoverable rather than private-key-style invalidating?
- does it keep framework-level and domain-level recovery separate?
- does it define fail-closed relock semantics and `restartRequired` clearly?
- does it keep bootstrap metadata minimal and non-sensitive?
- does it harden file protection explicitly instead of relying on platform defaults?
- does it classify all existing persisted app-owned state in app-data migration scope into a reviewed target class and migration-readiness state, while recording reviewed private-key-domain exclusions explicitly?
- does it make Contacts a consumer of the framework rather than the owner of a separate architecture?
- does it keep anti-rollback explicitly out of scope in v1 rather than implying freshness guarantees?

## 5. Documentation Acceptance Criteria

Before treating this proposal stack as implementation-ready:

- `APP_DATA_PROTECTION_TDD.md` must stand alone as the architecture and security source for protected app data
- `APP_DATA_FRAMEWORK_SPEC.md` must stand alone as the concrete framework mechanics reference
- `APP_DATA_MIGRATION_GUIDE.md` must stand alone as the rollout and inventory reference
- this validation guide must stand alone as the review and checklist reference
- `APP_DATA_PROTECTION_PLAN.md` must remain concise and phase-oriented rather than duplicating the detailed specs
- archived bridge documents must point readers to the right successor documents without adding a third architecture
