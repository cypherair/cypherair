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
- directory enumeration never drives normal shared-right deletion
- a committed domain in domain-scoped `recoveryNeeded` still counts as a member
- orphaned directories or wrapped-DMK artifacts do not implicitly become committed members

### 2.2 Unlock / Relock

- one shared `LAPersistedRight.authorize(...)` is the single normative app-data authorization boundary
- the shared app-data secret is fetched only after authorization
- if launch/resume immediately enters a route that needs protected-domain content, that same orchestrated flow may activate the shared app-data session without surfacing a later second prompt
- launch/resume authentication alone does not imply that the shared app-data session is already active
- a second or third protected domain does not require another prompt in the same active app-data session
- `AppSessionOrchestrator` is the only grace-window owner
- `ProtectedDataSessionCoordinator` does not run an independent grace timer
- relock closes new protected-domain access before cleanup begins
- relock participant fan-out is non-short-circuit
- relock deauthorizes the shared right
- relock clears the shared secret and all unwrapped domain DMKs
- relock clears decrypted payloads and derived indexes
- relock failure enters `restartRequired`
- `restartRequired` blocks all in-process re-auth and is not persisted to the registry
- backgrounding within the active grace window does not deauthorize app-data access

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
- macOS protected-domain files live inside the app's sandbox/container `Application Support` area and use the strongest platform-supported local static protection defined by the implementation
- on macOS, `ProtectedDataRegistry` and bootstrap metadata stay inside the same app-owned container boundary
- on macOS, protected-domain payloads are not stored in user-managed document locations by default
- macOS validation verifies containment, ownership, and absence of fallback to broader storage locations
- bootstrap metadata and temporary scratch files follow the same platform-specific protection policy as their host platform

### 2.5 Zeroization

- plaintext serialization buffers are zeroized after use
- the shared app-data secret is zeroized on relock
- unlocked domain DMKs are zeroized on relock
- decrypted domain snapshots or derived sensitive indexes are zeroized on relock

### 2.6 Failure Paths

- wrong auth does not unlock the shared app-data session
- pre-auth attempts must not fetch `LASecret`
- invariant violation or unclassifiable registry row enters `frameworkRecoveryNeeded`
- orphan shared-resource evidence with empty membership must only authorize post-classification `cleanupOnly` under the empty steady-state row; it must not split registry classification or final disposition
- missing shared right or unreadable shared secret for a row that expects `ready` enters `frameworkRecoveryNeeded`
- unreadable wrapped-DMK state enters only that domain's `recoveryNeeded`
- corrupted envelope hard-fails on authentication or structural validation
- interrupted migration does not destroy readable source state
- `ProtectedDataRelockParticipant` failure enters `restartRequired`
- shared-right deauthorize failure enters `restartRequired`
- `ProtectedSettingsStore` reset requires explicit destructive confirmation
- Contacts recovery remains import-based
- anti-rollback is not implied by `current / previous / pending`

### 2.7 Repository Validation Ownership

This draft proposal must map its validation buckets onto the repository's existing test layers and commands. This section assigns that ownership for draft-phase implementation work only; `TESTING.md` remains the later synchronization target after approval and implementation maturity.

- registry authority, state-machine, consistency-matrix, and invariant checks belong to Swift unit coverage in `CypherAir-UnitTests` using `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- startup recovery, relock orchestration, and route-handoff integration belong to macOS-local validation using `CypherAir-UnitTests`, with `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'` added whenever launch, routing, or protected-content smoke coverage is part of the change
- `LAPersistedRight` behavior, real LocalAuthentication prompt semantics, and device-only authorization guarantees belong to `CypherAir-DeviceTests` using `xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests -destination 'platform=iOS,name=<DEVICE_NAME>'`, plus explicit manual device validation whenever automation cannot prove platform prompt timing or system UX behavior
- file-protection strength, container containment, and absence of fallback to broader storage locations belong to platform-targeted macOS-local integration/manual verification, with automated macOS-local test coverage added where feasible and manual verification retained where the current repository does not yet have a dedicated protected-data file-metadata lane
- migration survivability, startup adoption, and no-silent-reset guarantees belong to Swift unit coverage in `CypherAir-UnitTests` plus targeted macOS-local integration validation, adding the `CypherAir-MacUITests` macOS smoke path when startup routing or user-visible recovery flows are part of the scenario

## 3. Implementation Readiness Expectations

This proposal is only acceptable if an implementer can proceed without making hidden architectural decisions.

At minimum, an implementer must be able to tell:

- that the current private-key domain should remain semantically unchanged
- that protected app data uses one shared app-data right plus per-domain DMKs
- that `ProtectedDataRegistry` is the only membership authority
- that shared-resource lifecycle state and mutation execution phase are distinct concepts
- that `AppSessionOrchestrator` is the app-wide session owner
- that `ProtectedDataSessionCoordinator` is the app-data subsystem coordinator under that owner
- that `LAPersistedRight` is the primary app-data authorization gate in v1
- that app-data domains are recoverable rather than private-key-style invalidating
- that framework-level and domain-level recovery are distinct
- that startup recovery is registry-first and matrix-driven
- that `restartRequired` is distinct from `frameworkRecoveryNeeded`
- that file protection must be explicit
- that startup is split into pre-auth bootstrap and post-auth unlock phases
- that the generation model does not promise anti-rollback semantics
- that Contacts later depends on the framework rather than inventing its own vault base layer

## 4. Review Questions For Future Implementation

Any implementation derived from this proposal should be reviewable against these questions:

- does it preserve the existing private-key domain without semantic drift?
- does it introduce a reusable protected app-data substrate rather than a one-off vault?
- does it treat one shared `LAPersistedRight` as the first gate for app-data unlock secret access?
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
