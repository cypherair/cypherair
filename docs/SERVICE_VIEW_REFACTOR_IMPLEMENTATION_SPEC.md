# Service / View Refactor Implementation Specification

> Purpose: Define the implementation baseline for a future Service and View refactor without changing user-visible behavior or current security semantics.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [CONVENTIONS](CONVENTIONS.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)
> Spec posture: This document is an execution baseline for future refactor work. It is intentionally more specific than the assessment, but it does not authorize implementation before the assessment is reviewed and accepted.
> Important framing: This specification is intentionally grounded in the repository's real starting point. That grounding does **not** reduce the need for refactor; it prevents the plan from depending on abstractions or ownership seams that the codebase does not yet have.

## 1. Intent

This refactor exists to solve a structural problem, not a product problem.

CypherAir already has working behavior across the current production app and the guided tutorial. The problem is that several services and screens now mix rendering, coordination, state machines, persistence decisions, and integration seams in ways that increase review cost and slow safe iteration.

The refactor must:

- keep every current user-visible behavior intact
- keep every current security semantic intact
- reduce overloaded service and view ownership
- preserve tutorial compatibility while production pages are restructured
- make future feature work cheaper to review and less likely to regress adjacent flows

This specification assumes the assessment in [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) has already been reviewed and accepted. No implementation phase should start before that review gate is passed.

## 2. Stability Contract

The refactor is architecture-preserving. Unless a later, separately reviewed document says otherwise, this specification does **not** authorize:

- renaming or removing the existing App-layer environment-injected facades
- changing public service entry points used by the App layer
- changing `Configuration` source compatibility for current production pages
- changing strings, routes, ready markers, tutorial module order, import/export naming, or output-interception semantics
- changing behavior in `Sources/Security/`, `AuthenticationManager`, or Rust code as part of this structural work

The document also does **not** imply that every named collaborator must become a public or user-visible type. Internal helper and collaborator names may be private. What matters is stable ownership boundaries, not type visibility.

## 3. Architecture Contract

### 3.1 Definitions

- `Facade`: an existing public service type that remains the stable entry point for its current callers. In the App layer that means `KeyManagementService`, `ContactService`, `EncryptionService`, `DecryptionService`, `SigningService`, `QRService`, and `SelfTestService`. `PasswordMessageService` remains a current public service facade for service-level callers and tests, but it is not presently an environment-injected App-layer entry point.
- `Screen model`: an `@Observable` owner for one production screen's workflow state, async actions, transient results, importer/exporter state, and confirmation/error state.
- `Coordinator`: an owner for app-flow or cross-screen presentation state that does not belong inside a single production page.

### 3.2 Required Screen-Model Ownership Pattern

The repository already defines the recommended screen-model ownership pattern in [CONVENTIONS](CONVENTIONS.md), but it does not yet have a mature, repo-validated implementation example in `Sources/App/`. This refactor should therefore adopt one explicit pattern consistently and turn it into the first validated baseline.

The required pattern is:

1. the public top-level production page remains the route/call-site type and may keep its existing `Configuration`
2. that top-level view reads `@Environment` dependencies and passes concrete dependencies plus `Configuration` into a private owning host view
3. the private owning host view initializes `@State private var model` in its initializer from those explicit dependencies
4. the screen model itself does **not** read `@Environment` directly and does **not** construct its own facade instances
5. the view binds to the model via `@Bindable` or direct property access and keeps only layout, binding glue, and presentation modifiers

This two-step route-view and owning-host pattern is required because the current views rely on `@Environment`, while SwiftUI still requires stable ownership semantics for `@State` reference types.

### 3.3 Lifecycle And Cleanup Contract

The current overloaded screens contain significant lifecycle-owned behavior. That ownership must move deliberately.

Rules:

- one-time prefill or initial setup moves into an explicit model method such as `prepareIfNeeded()`
- cleanup and invalidation that currently lives in `onDisappear` / `onChange` moves into explicit model methods such as `handleDisappear()` or `invalidateFor...(...)`
- the view may still trigger lifecycle hooks via `.task`, `.onAppear`, `.onDisappear`, or `.onChange`, but it must not continue to implement the cleanup logic inline
- the screen model owns long-running operation state, importer/exporter state, transient files, confirmation state, and error state

The view remains responsible for:

- layout
- control bindings
- local rendering-only derivations
- wiring toolbar, sheet, alert, and navigation modifiers to model state

### 3.4 Helper Reuse Contract

The refactor must treat the following App-layer helpers as reuse points, not as default rewrite targets:

- `OperationController`
- `FileExportController`
- `SecurityScopedFileAccess`
- `ImportedTextInputState`
- `PublicKeyImportLoader`
- `ContactImportWorkflow`
- `ImportConfirmationCoordinator`

Preferred rule: relocate ownership before replacing implementation. For example, a screen model may own an `OperationController`, but the helper itself should remain reusable unless a later phase explicitly proves it is no longer fit for purpose.

### 3.5 Facade And Internal Collaborator Contract

#### `KeyManagementService`

`KeyManagementService` remains the public facade exposed to views and other services. Its internal ownership should be split into collaborators with the following stable boundaries:

- `KeyCatalogStore`
  - owns loading, in-memory key collection updates, default-key state, and metadata persistence coordination
- `KeyProvisioningService`
  - owns generate/import workflows and the transition from raw engine output into stored identities
- `KeyExportService`
  - owns secret-key export, public-key export, and revocation export workflows
- `KeyMutationService`
  - owns expiry mutation, deletion, and related transactional mutation flows
- `PrivateKeyAccessService`
  - owns Secure Enclave unwrap access and raw private-key retrieval for downstream crypto flows

Rules:

- `KeyManagementService` keeps the current public methods
- `keys` and `defaultKey` remain observable through the facade
- security-sensitive sequencing remains unchanged even if internal ownership moves
- no refactor phase may alter current `AuthenticationManager`, Secure Enclave, Keychain access-control, or crash-recovery semantics

#### `ContactService`

`ContactService` remains the public facade exposed to the App layer. The only collaborator boundary that is mandatory at the start of contact refactor work is persistence:

- `ContactRepository`
  - owns contact file persistence, metadata manifest persistence, load/save operations, and file-layout conventions

Rules:

- `ContactService` public methods remain compatible
- file naming, metadata format, duplicate/update/replacement semantics, and verification-state persistence remain unchanged
- `ContactImportWorkflow` remains the App-layer confirmation/orchestration helper
- an additional internal import-policy collaborator is optional, not mandatory; it may be introduced only if its boundary is narrower than the current `ContactService` logic and does not duplicate responsibility already held by `ContactImportWorkflow`

#### Other Services

- `EncryptionService`: keep public API unchanged; internal helper extraction is allowed only to support cleaner screen-model integration.
- `DecryptionService`: keep public API unchanged and preserve the Phase 1 / Phase 2 boundary exactly.
- `SigningService`: keep public API unchanged; internal helper extraction is allowed but not required.
- `PasswordMessageService` and `SelfTestService`: no structural refactor required as part of this work.

### 3.6 Coordinator Contract

`CypherAirApp` should end the refactor as a composition root plus top-level scene declaration, not as a multi-flow coordinator.

Target coordinator boundaries:

- `AppPresentationCoordinator`
  - owns cross-platform presentation state, handoff rules, and top-level presentation decisions for onboarding, tutorial, and other app-owned presentation flows
  - reuses the current `TutorialOnboardingHandoffState` as the iOS-specific handoff mechanism inside a broader coordinator design, rather than treating that state as the whole coordinator
  - is the long-term owner of presentation decisions currently split across `CypherAirApp`, `MacSettingsRootView`, and related presentation entry points
- `IncomingURLImportCoordinator`
  - owns `cypherair://` public-key import coordination, import confirmation presentation, and related alert state
  - wraps and reuses the current import loader/workflow/coordinator seams rather than replacing them wholesale

Rules:

- startup behavior currently performed by `AppStartupCoordinator` remains intact
- tutorial launch semantics and onboarding dismissal rules remain unchanged
- global alert content and timing remain unchanged
- `MacPresentationHost`, `MacPresentationController`, and comparable host wrappers may remain as rendering/bridging adapters; the coordinator contract is about centralizing state and decision ownership, not about eliminating every host type

## 4. Front-Loaded Design Gates

Before any broad implementation phase starts, the following must be locked explicitly:

1. the route-view and owning-host screen-model pattern described above
2. the lifecycle contract for current `onAppear` / `onDisappear` / `onChange` behavior on target screens
3. the `ContactService` boundary against existing App-layer import helpers
4. the exact compatibility expectations for tutorial `Configuration` callbacks
5. the validation plan for launch, settings, and tutorial smoke coverage through `CypherAir-MacUITests`, including the presentation-ownership assumptions that span iOS and macOS paths

No phase may proceed on the assumption that these are "local implementation details." They are repo-wide architecture decisions.

## 5. Phased Rollout

Implementation is fixed to five phases. Do not collapse them into one rewrite branch.

### 5.1 Phase 1: Architecture Baseline And Compatibility Gates

**Why this phase exists**

The repository already has guidance for a screen-model pattern, but it does not yet have a proven in-repo implementation baseline. Starting with surface migrations would force each screen to interpret that guidance independently.

**Scope**

- establish the shared route-view and owning-host screen-model pattern
- establish the lifecycle forwarding contract for setup, invalidation, and cleanup
- prove that existing `Configuration` types remain source-compatible with tutorial and production call sites
- pin helper reuse rules so later phases default to ownership relocation rather than helper replacement
- implement `SignView` as the first in-repo pilot of that pattern without changing its external call sites or behavior

**Required outputs**

- a single, documented screen-model ownership pattern that later phases must reuse
- explicit lifecycle method conventions for preparation, cleanup, and invalidation
- compatibility tests or assertions that protect current `Configuration` seams and launch/smoke wiring
- `SignScreenModel` as the reference implementation for a route-view plus private-owning-host slice

**Completion definition**

- subsequent phases can introduce screen models without reopening ownership, dependency-injection, or cleanup design
- tutorial production-page hosting still compiles and routes without changing existing `Configuration` call sites
- `SignView` remains source-compatible at all current production and tutorial call sites while no longer directly owning operation/export workflow state

**Out of scope**

- service collaborator splits
- production workflow migrations beyond the `SignView` pilot and what is strictly needed to lock the pattern
- app-root coordinator extraction

### 5.2 Phase 2: Key Lifecycle + Settings / Key Detail

**Why this phase exists**

`KeyManagementService` is the broadest service, while `SettingsView` and `KeyDetailView` are already coordination-heavy and tightly coupled to it.

**Scope**

- internal split of `KeyManagementService`
- `SettingsScreenModel`
- `KeyDetailScreenModel`
- auth-mode confirmation request shaping and the settings-owned presentation compatibility needed to keep the full settings/auth-mode flow coherent across iOS, macOS, and fallback presentation paths
- minimal adapter work needed to keep key-detail and settings flows compatible with the new internals

**Required outputs**

- `KeyManagementService` facade preserved
- internal collaborator boundaries established behind the facade
- `SettingsView` no longer directly coordinates auth-mode switching or presentation fallback state
- the settings/auth-mode surface is treated as one refactor target, including the state and decision flow that feeds confirmation requests, confirmation presentation, and launch-triggered macOS settings presentation
- `KeyDetailView` no longer directly owns export/delete/revocation/expiry workflow state

**Completion definition**

- callers still use `KeyManagementService`
- key detail and settings retain current behavior
- completing Phase 2 means the auth-mode flow's state and decisions are no longer scattered across multiple settings-related UI entry points, even if dedicated confirmation views and host adapters still exist
- no behavior change to auth-mode warnings, mode switching, revocation export, default-key changes, delete flow, or modify-expiry flow

**What this phase proves for later phases**

- the screen-model pattern works for sheet/alert/export coordination
- the facade-splitting pattern works without changing App-layer callers

**Out of scope**

- `AuthenticationManager` behavior changes
- removing `SettingsAuthModeConfirmationSheetView`, `MacSettingsRootView`, or `MacPresentationHost` as UI host/adaptation types
- `KeyGenerationView`, `ImportKeyView`, `BackupKeyView`, and `ModifyExpirySheetView` full screen-model conversion

### 5.3 Phase 3: Encrypt / Decrypt Reference Slice

**Why this phase exists**

`EncryptView` and `DecryptView` are the most overloaded workflow screens. They are the right place to define the reference pattern for long-running tool screens, importer/exporter state, cleanup, and output interception.

**Scope**

- `EncryptScreenModel`
- `DecryptScreenModel`
- thin host/content restructuring for the two production screens
- helper extraction in `EncryptionService` and `DecryptionService` only when needed to support the screen-model split

**Required outputs**

- workflow state moves out of both views
- current `Configuration` structs remain usable by both production and tutorial hosts
- export/import/cancel/error/presentation behavior remains unchanged
- file inspection, invalidation, and cleanup logic move behind model methods instead of remaining inline in the views

**Completion definition**

- `EncryptView` and `DecryptView` primarily bind to screen-model state
- `DecryptView` cleanup semantics remain intact without leaving temp-file deletion and invalidation inline in the view
- `DecryptionService` Phase 1 / Phase 2 semantics are unchanged

**What this phase proves for later phases**

- the screen-model pattern works for long-running file operations, import/export helpers, and output-interception callbacks
- tutorial `Configuration` compatibility still holds for the heaviest tool screens

**Out of scope**

- service facade renaming
- password-message UI activation

### 5.4 Phase 4: Verify / Add Contact + Contact Persistence Boundary

**Why this phase exists**

Once the long-running tool-screen pattern is proven, the remaining workflow-heavy screens can follow it. `SignView` already serves as the initial in-repo baseline from Phase 1, so this phase continues from that baseline rather than re-migrating sign. Contact persistence should be split in the same phase only after the App-layer import-helper boundary is explicit.

**Scope**

- `VerifyScreenModel`
- `AddContactScreenModel`
- `ContactRepository`
- explicit disposition for `QRPhotoImportView` as a deprecated standalone page with no current production navigation entry point
- compatibility updates for Add Contact QR-photo mode, confirmation-host flows, and tutorial add-contact wiring

**Required outputs**

- workflow state moves out of `VerifyView` and `AddContactView`, while `SignView` remains the already-migrated reference slice
- `ContactService` facade preserved
- contact file/manifest persistence moves behind `ContactRepository`
- `ContactImportWorkflow` remains the App-layer confirmation/orchestration helper
- `AddContactView` remains the primary production contact-import surface, including QR-photo import through its existing mode picker
- `QRPhotoImportView` is documented as a deprecated standalone page; Phase 4 does not require a dedicated screen-model migration for it
- no duplicate import state machines are introduced across App and Service layers

**Completion definition**

- duplicate/update/replacement semantics remain unchanged
- current confirmation coordinator and import-confirmation UI remain intact
- tutorial add-contact flow still works through `TutorialConfigurationFactory`
- the current system-camera `cypherair://` handoff path remains the formal QR entry point
- if the `.qrPhotoImport` route remains in code, it stays outside the primary contact-import architecture and must not drive Phase 4 screen-model design
- any additional internal contact import-policy collaborator is either clearly narrower than the existing App helper boundary or is deferred

**What this phase proves for later phases**

- the same screen-model pattern works for smaller tool screens and partially extracted screens
- contact persistence can be split without destabilizing confirmation and replacement flows

**Out of scope**

- redesign of the contact-import user experience
- revitalizing `QRPhotoImportView` as a first-class product entry point
- tutorial-specific contact flow rewrite

### 5.5 Phase 5: App Root Coordination + Tutorial Host Finalization

**Why this phase exists**

`CypherAirApp` is still overloaded, but the repository already has partial seams. This phase is cleanup and relocation work after service and screen ownership patterns are already stable.

**Scope**

- `AppPresentationCoordinator`
- `IncomingURLImportCoordinator`
- relocation of remaining app-root coordination into those coordinators
- consolidation of presentation-state and presentation-decision ownership currently split across iOS app-root flows and macOS presentation entry points
- adaptation of tutorial host layers to the final screen-model-backed production pages

**Required outputs**

- `CypherAirApp` is reduced to composition and top-level scene wiring
- onboarding/tutorial handoff logic moves behind a dedicated coordinator that reuses the current handoff state machinery where appropriate
- URL import coordination moves out of the app root and reuses the current import loader/workflow/coordinator seams
- cross-platform presentation ownership is centralized even if platform-specific hosts such as `MacPresentationHost` remain in place as rendering adapters
- tutorial host wrappers remain compatible with production-page configuration

**Completion definition**

- tutorial launch, replay, and dismissal behavior are unchanged
- startup warnings and import alerts are unchanged
- iOS sheet/fullScreenCover/alert/onOpenURL coordination is no longer primarily owned by `CypherAirApp`
- macOS onboarding/tutorial/auth/import presentation state is also driven by the shared coordination layer rather than by isolated per-entry-point decision logic
- host modifiers and wrappers remain responsible for rendering and environment bridging, not for owning the main presentation decisions
- production pages still render correctly in tutorial and onboarding-connected contexts
- `CypherAirApp` no longer owns the main presentation-state and URL-import coordination logic directly

**Out of scope**

- rewriting `TutorialSessionStore`
- merging tutorial and production containers
- redesigning tutorial host UX

## 6. Compatibility Rules

The following are non-negotiable across all phases:

- No user-visible behavior changes.
- No string changes, route changes, tutorial module-order changes, or export filename changes.
- No changes to current import/export semantics, clipboard behavior, or output-interception behavior.
- No changes to current ready markers used by UI tests.
- No changes to `UITEST_*` launch-environment semantics.
- No Rust changes.
- No behavior changes under `Sources/Security/`.
- No behavioral changes to `AuthenticationManager`.
- `Configuration` types for existing production pages remain source-compatible.
- Existing environment-injected facade types remain the primary entry points for the App layer.
- Helper migration takes priority over helper replacement.
- Existing seams should be reused before new parallel abstractions are introduced.

Specific compatibility rules by area:

- `DecryptionService` Phase 1 / Phase 2 behavior must remain byte-for-byte compatible from the caller perspective.
- `KeyManagementService` recovery and unwrap behavior must remain externally identical.
- `ContactService` duplicate/update/replacement semantics must remain externally identical.
- `AddContactView` remains the primary production contact-import surface, including the active QR-photo import mode.
- `QRPhotoImportView`, if retained, is treated as a deprecated standalone route rather than as a primary production workflow.
- `cypherair://` URL import remains the formal system-camera QR handoff path.
- `TutorialConfigurationFactory` must remain capable of expressing current tutorial restrictions and callbacks without requiring tutorial-only forks of production pages.

## 7. Testing And Validation Gates

### 7.1 Baseline Gate Before Any Code Phase

Before starting any implementation phase, confirm the branch baseline with the current repository commands:

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'
```

If baseline is not green, fix or isolate baseline breakage before beginning refactor work.

### 7.2 Mandatory Validation For Every Phase

Every phase must end with:

- `cargo test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'` whenever launch flow, screen ownership, ready markers, or tutorial/settings routing could be affected
- targeted review against [CODE_REVIEW](CODE_REVIEW.md)

### 7.3 Phase-Specific Test Expectations

#### Phase 1

- add or update tests that pin the screen-model ownership pattern and `Configuration` compatibility expectations
- keep `TutorialSessionStoreTests` green
- keep `MacUISmokeTests` settings and tutorial launch flows green

#### Phase 2

- keep `KeyManagementServiceTests` green
- keep `MacUISmokeTests` key-detail and settings/auth-mode flows green
- add screen-model tests for settings and key-detail state transitions, export state, delete flow, and modify-expiry presentation
- cover auth-mode confirmation flow across the macOS presentation path and the launch-triggered macOS settings path, not just the in-view picker interaction

#### Phase 3

- keep `EncryptionServiceTests`, `DecryptionServiceTests`, and relevant `StreamingServiceTests` coverage green
- add screen-model tests for:
  - import/export state transitions
  - cancellation behavior
  - invalidation and cleanup behavior
  - warning and confirmation state transitions
- extend macOS smoke coverage only if ready-state ownership changes require it

#### Phase 4

- keep `SigningServiceTests`, `StreamingServiceTests`, `ContactServiceTests`, and `TutorialSessionStoreTests` green
- add screen-model tests for add-contact mode switching, including the built-in QR-photo mode, file import, and replacement confirmation flow
- if the `.qrPhotoImport` route is retained, verify it does not reintroduce a parallel primary contact-import state machine or a new required screen-model target
- explicitly verify that contact persistence extraction did not duplicate or bypass App-layer confirmation workflow behavior

#### Phase 5

- keep `TutorialSessionStoreTests` green
- keep `MacUISmokeTests` tutorial and settings launch flows green
- add coordinator tests for onboarding/tutorial handoff and URL import coordination
- cover both reuse of iOS handoff state and macOS presentation-state routing, rather than testing only the iOS tutorial handoff path

### 7.4 Device-Test Rule

Device-only test plans are required only if a phase unexpectedly changes behavior close to device-auth or Secure Enclave semantics. The intended structural refactor should avoid that by keeping security behavior unchanged.

## 8. Review Checkpoints

### 8.1 Documentation Gate

No code implementation starts until:

- [SERVICE_VIEW_REFACTOR_ASSESSMENT](SERVICE_VIEW_REFACTOR_ASSESSMENT.md) is reviewed
- this implementation specification is reviewed
- the five-phase order is accepted without reopening the architecture scope

### 8.2 Per-Phase Design Review

Before each phase starts, confirm:

- the target files and collaborators for the phase
- the explicit non-goals for the phase
- the tests that must be updated or added
- whether any sensitive boundary is being approached

### 8.3 Sensitive-Boundary Review

If a phase touches or risks touching any of the following, human review is mandatory before merge:

- `Sources/Security/`
- `Sources/Services/DecryptionService.swift`
- `Sources/Services/QRService.swift`
- `CypherAir.xcodeproj/project.pbxproj`
- onboarding/tutorial launch and auth-mode confirmation behavior

### 8.4 Behavior-Parity Review

At the end of each phase, perform a behavior-parity review against current production expectations:

- no visible navigation changes
- no alert sequencing changes
- no tutorial capability changes
- no import/export naming changes
- no changed settings semantics

## 9. Deferred Items

The following are explicitly deferred beyond this structural refactor:

- rewriting the tutorial state machine in `TutorialSessionStore`
- unifying tutorial and production containers
- narrowing or renaming public service facades
- activating new product surfaces for `PasswordMessageService`
- broad conversion of every key-related screen into a mandatory screen-model target
- redesigning tutorial hub, onboarding copy, or tutorial host UX
- changing Rust, Secure Enclave, Keychain, or auth-mode behavior semantics

These deferments are intentional. They keep the refactor focused on ownership boundaries, workflow relocation, and compatibility flow.
