# Service / View Refactor Assessment

> Purpose: Assess the current Service and App-layer boundaries in CypherAir before any structural refactor work begins.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [SERVICE_VIEW_REFACTOR_IMPLEMENTATION_SPEC](SERVICE_VIEW_REFACTOR_IMPLEMENTATION_SPEC.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [CONVENTIONS](CONVENTIONS.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)
> Assessment posture: This document records verified current-state facts plus cautious architectural inferences. It does not prescribe implementation steps beyond what the current code shape clearly justifies.
> Important framing: Grounding the assessment in the real current code does **not** mean the current structure is sufficient. It means the refactor baseline must start from verified repository truth rather than from assumed future seams that do not yet exist.

## 1. Scope And Assessment Method

This assessment reviews three related surfaces together:

1. production services under `Sources/Services/`
2. production views and app hosts under `Sources/App/`
3. tutorial and onboarding host layers that adapt production pages into the guided tutorial sandbox

The goal is not to label every large file as a problem. The goal is to distinguish:

- what is currently working as an intentional boundary
- what has grown into a coordination hotspot
- what is already broad enough that future changes will be risky to review
- what prerequisite seams are still missing before a large refactor can be specified safely

This assessment uses the following labels consistently:

- `Within boundary`: the file is doing the job expected of its layer, even if it is not tiny.
- `Large but coherent`: the file is big, but the responsibilities still align to one domain or product surface.
- `Boundary overflow`: the file mixes responsibilities that belong in different abstractions or ownership layers.
- `Coordination hotspot`: the file is where too many flows converge, even if each individual flow is understandable.
- `Sensitive / constrained`: the file sits near a security, launch, or product-compatibility boundary where structural change needs extra caution.

Boundary judgments are based on current code shape, current integration seams, and current project rules. They are not based on line count alone. The relevant UI rule already exists in [CONVENTIONS](CONVENTIONS.md): views stay thin and avoid business logic, Keychain access, and crypto operations in views. The same expectation appears in [CODE_REVIEW](CODE_REVIEW.md).

## 2. Verified Current-State Matrix

| Surface | Current role | Approx. size | Classification | Evidence summary | Immediate implication |
|---|---|---:|---|---|---|
| [`KeyManagementService`](../Sources/Services/KeyManagementService.swift) | Key lifecycle facade plus SE unwrap, export, mutation, metadata, and recovery | 679 lines | `Boundary overflow`, `Sensitive / constrained` | One type owns generation, import, export, revocation export, expiry mutation, deletion, default-key logic, crash recovery, and private-key unwrap | This is the clearest god service candidate and the riskiest refactor surface in the Service layer |
| [`ContactService`](../Sources/Services/ContactService.swift) | Public-key persistence, merge/update handling, replacement detection, verification-state storage | 385 lines | `Large but coherent` with mixed persistence/import-policy ownership | The file still orbits one domain, but it combines validation handoff, merge decisions, file I/O, metadata manifest persistence, and in-memory list maintenance | Persistence extraction is justified; any deeper import split needs a clearer boundary first |
| [`EncryptionService`](../Sources/Services/EncryptionService.swift) | Text/file encryption orchestration | 334 lines | `Large but coherent` | The service stays focused on encryption, but both text and streaming paths repeat key gathering, self-encrypt resolution, and unwrap handling | Helper extraction is plausible; a facade split is not urgent |
| [`DecryptionService`](../Sources/Services/DecryptionService.swift) | Two-phase decrypt orchestration, streaming file decrypt, signature resolution | 356 lines | `Large but coherent`, `Sensitive / constrained` | The Phase 1 / Phase 2 boundary is explicit and security-critical, but multiple orchestration paths live together | Preserve the current public contract while App-layer logic is thinned |
| [`SigningService`](../Sources/Services/SigningService.swift) | Sign/verify orchestration for text and files | 290 lines | `Large but coherent` | Clear responsibility, mostly transport/orchestration over engine calls | Not an early service split target |
| [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift) | Encrypt form, recipient selection, export UX, file import/export, task orchestration | 614 lines | `Boundary overflow` | 4 environment dependencies, 16 local state properties, long `body`, file-export wiring, output interception, warning flow, and async orchestration all live in one view | This screen has already outgrown the "thin view" expectation |
| [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift) | Two-phase decrypt screen, import heuristics, temp-file cleanup, export UX | 754 lines | `Boundary overflow` | 17 local state properties, long `body`, invalidation logic, armored-text inspection, temp-file deletion, and async orchestration are interleaved with rendering | This is the most overloaded page in the App layer and the clearest screen-model candidate |
| [`SignView`](../Sources/App/Sign/SignView.swift) | Cleartext/detached signing screen | 414 lines | `Large but coherent` | Still mostly one workflow, but it owns both rendering and task/export orchestration | Worth moving to the same screen architecture once the pattern is proven elsewhere |
| [`VerifyView`](../Sources/App/Sign/VerifyView.swift) | Cleartext/detached verify screen | 475 lines | `Large but coherent` | Shares the same pattern as `SignView`, with additional file-import and streaming-verify coordination | Similar treatment to `SignView`; lower urgency than decrypt/encrypt |
| [`SettingsView`](../Sources/App/Settings/SettingsView.swift) | Settings UI plus auth-mode switching and onboarding/tutorial launch coordination | 433 lines | `Coordination hotspot`, `Sensitive / constrained` | The view coordinates auth-mode confirmation, backup-aware risk messaging, async mode switching, and cross-platform presentation fallbacks | This is already a coordinator hidden inside a view |
| [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift) | Key detail UI plus export, default-key, delete, revocation, and modify-expiry coordination | 418 lines | `Coordination hotspot` | The view drives async revocation export, clipboard writes, default-key updates, destructive delete, and modal presentation | Clear candidate for screen-model extraction |
| [`AddContactView`](../Sources/App/Contacts/AddContactView.swift) | Primary contact import UI with paste/QR/file modes | 349 lines | `Coordination hotspot` | Better factored than other screens because it already uses `PublicKeyImportLoader` and `ContactImportWorkflow`, but the remaining import-mode, QR, fallback-host, and alert coordination is still view-owned | This is the active production contact-import surface and a good reuse baseline, not yet a fully thin view |
| [`CypherAirApp`](../Sources/App/CypherAirApp.swift) | App composition root plus startup, onboarding/tutorial handoff, URL import coordination, and global alerts | 380 lines | `Coordination hotspot`, `Sensitive / constrained` | The app root still builds the container, wires startup, owns iOS presentation state, handles URL import, and owns global alert presentation, even though some seams have already been extracted | Still overloaded, but not starting from zero: existing seams should be reused rather than replaced wholesale |
| [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift) | Tutorial session state machine and sandbox-flow owner | 432 lines | `Large but coherent`, `Coordination hotspot` | Central state owner for tutorial lifecycle, sandbox artifacts, navigation, modal routing, and task progression | This is intentionally central and should be preserved, not rewritten, in the first structural refactor |
| [`TutorialView`](../Sources/App/Onboarding/TutorialView.swift) | Tutorial host UI and hub/completion presentation | 382 lines | `Large but coherent` | Large host view, but the responsibilities still align with the tutorial experience rather than leaking into unrelated domains | Lower priority than production screens; keep stable while adapting integrations around it |
| [`TutorialConfigurationFactory`](../Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift) | Adapter from tutorial state to production-page configuration | 195 lines | `Within boundary` | It is a focused compatibility seam that feeds configuration into production pages without rewriting them | Keep this seam; it is the main reason a production-page refactor can stay tutorial-compatible |
| [`TutorialRouteDestinationView`](../Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift) | Tutorial-specific route adapter for production pages | 150 lines | `Within boundary` | Its job is route adaptation and host wrapping | Keep stable; update only as production pages change shape |
| [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift) | Tutorial host wrapper and inline-header integration | 237 lines | `Large but coherent` | It centralizes tutorial host chrome and visible-surface reporting | Integration-heavy but structurally healthy |
| [`TutorialShellDefinitionsBuilder`](../Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift) | Tutorial tab/root composition | 106 lines | `Within boundary` | Purpose is narrow and clear | No current boundary issue |
| [`TutorialSandboxContainer`](../Sources/App/Onboarding/TutorialSandboxContainer.swift) | Isolated tutorial dependency graph and sandbox storage | 118 lines | `Within boundary`, `Sensitive / constrained` | Focused tutorial-only composition root backed by sandbox storage and mock security primitives | Preserve this isolation boundary; do not fold it into the main app container in the first structural refactor |

## 3. Verified Findings

### 3.1 Service Layer

#### [`KeyManagementService`](../Sources/Services/KeyManagementService.swift)

**Classification**

- `Boundary overflow`
- `Sensitive / constrained`

**Verified evidence**

- It is the largest service in the repository at 679 lines.
- It owns 9 injected collaborators or stores:
  - engine
  - Secure Enclave
  - Keychain
  - authenticator
  - memory-info provider
  - defaults
  - bundle store
  - metadata store
  - migration coordinator
- It directly implements five distinct responsibility families:
  - key enumeration and metadata loading
  - generation and import
  - export and revocation export
  - expiry mutation, deletion, and default-key mutation
  - crash recovery and raw private-key access
- Multiple downstream services depend on its observable `keys` / `defaultKey` state or `unwrapPrivateKey(...)`, including [`EncryptionService`](../Sources/Services/EncryptionService.swift), [`DecryptionService`](../Sources/Services/DecryptionService.swift), [`SigningService`](../Sources/Services/SigningService.swift), and [`PasswordMessageService`](../Sources/Services/PasswordMessageService.swift).

**Assessment**

This is the only service in the repository that is clearly acting as both a public facade and several internal owners at once. The file is not merely "big"; it combines routine app flows with crash recovery and Secure Enclave adjacency, which increases review cost and regression risk.

**Implication**

The current facade should stay visible to the App layer, but internal ownership should stop living in one source file.

#### [`ContactService`](../Sources/Services/ContactService.swift)

**Classification**

- `Large but coherent`

**Verified evidence**

- The file is 385 lines and still mostly about one domain: imported public contacts.
- `addContact(...)` currently spans validation, same-fingerprint merge, same-user replacement detection, file persistence, verification-state persistence, and in-memory updates.
- The service also owns the verification-state manifest format and the file-layout convention.
- At the same time, the App layer already has extracted import helpers:
  - [`PublicKeyImportLoader`](../Sources/App/Contacts/Import/PublicKeyImportLoader.swift)
  - [`ContactImportWorkflow`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift)

**Assessment**

This service is not yet a god service. The main issue is mixed persistence and import-policy ownership inside one type. The codebase already has App-layer helpers around inspection, confirmation, and replacement flow, so any future `ContactImportService` concept is not decision-complete yet. A repository/persistence split is justified today. A second internal import-policy split is only justified if it removes duplication without colliding with the existing App-layer workflow helpers.

**Implication**

Treat persistence extraction as the current architectural need. Treat deeper import splitting as conditional, not pre-approved.

#### Other Services

The remaining services are not the current primary split targets:

- [`EncryptionService`](../Sources/Services/EncryptionService.swift): `Large but coherent`. Internal helper extraction is fine if screen-model migration needs it.
- [`DecryptionService`](../Sources/Services/DecryptionService.swift): `Large but coherent`, `Sensitive / constrained`. Preserve the existing Phase 1 / Phase 2 contract exactly.
- [`SigningService`](../Sources/Services/SigningService.swift): `Large but coherent`. Helper extraction is fine; a facade split is not urgent.
- [`PasswordMessageService`](../Sources/Services/PasswordMessageService.swift): `Within boundary`. Small and purpose-built.
- [`SelfTestService`](../Sources/Services/SelfTestService.swift): `Large but coherent`. Intentionally diagnostic, not a production workflow owner.

### 3.2 Production Screens

#### [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift) and [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift)

**Classification**

- `EncryptView`: `Boundary overflow`
- `DecryptView`: `Boundary overflow`

**Verified evidence**

- Both views own `OperationController` and `FileExportController` state directly.
- Both views combine rendering with importer/exporter state, async orchestration, and output-interception decisions.
- [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift) additionally owns:
  - text/file invalidation
  - `onDisappear` cleanup
  - temporary file deletion
  - armored text-message file inspection
  - pending-import suggestion state
- Both views still rely on `Configuration` callbacks for tutorial compatibility.

**Assessment**

These screens are the best candidates for moving workflow state out of views. They are also the place where any future screen-model pattern will be stress-tested by long-running operations, cleanup, and tutorial callback compatibility.

#### [`SignView`](../Sources/App/Sign/SignView.swift) and [`VerifyView`](../Sources/App/Sign/VerifyView.swift)

**Classification**

- `Large but coherent`

**Verified evidence**

- Both screens follow the same architectural pattern as encrypt/decrypt:
  - render form controls
  - manage importer state
  - run async work
  - own error and export presentation
- [`VerifyView`](../Sources/App/Sign/VerifyView.swift) also owns cleartext import invalidation and detached-file verification setup.

**Assessment**

These are not the first pattern-definition targets, but they should follow the same architecture once that pattern is established.

#### [`SettingsView`](../Sources/App/Settings/SettingsView.swift)

**Classification**

- `Coordination hotspot`
- `Sensitive / constrained`

**Verified evidence**

- It directly coordinates auth-mode interception, warning generation, async mode switching, and onboarding/tutorial launch routing.
- It branches across `iosPresentationController`, `macPresentationController`, and local fallback sheet state.
- It computes risk messaging based on backup presence from [`KeyManagementService`](../Sources/Services/KeyManagementService.swift).
- The auth-mode flow is not fully local to the main list view. Related ownership also passes through auth-mode confirmation request shaping, the dedicated confirmation sheet view, the macOS settings-root launch path, and the macOS presentation host.

**Assessment**

The problem is not visual complexity. The problem is that UI concerns, security-adjacent intent handling, and cross-platform presentation routing all live together in what still behaves like one Settings surface. The refactor boundary here should include the auth-mode confirmation and presentation path, not just the visible list page.

#### [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift)

**Classification**

- `Coordination hotspot`

**Verified evidence**

- The view directly triggers revocation export, public-key copy/save, default-key mutation, delete confirmation, and modify-expiry presentation.
- It owns alert, sheet, export, and transient async state directly.

**Assessment**

This is already a mini workflow surface rather than a passive detail page.

#### [`AddContactView`](../Sources/App/Contacts/AddContactView.swift)

**Classification**

- `Coordination hotspot`

**Verified evidence**

- The view already depends on two extracted helpers:
  - [`PublicKeyImportLoader`](../Sources/App/Contacts/Import/PublicKeyImportLoader.swift)
  - [`ContactImportWorkflow`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift)
- That is a good sign, but the view still owns:
  - import-mode switching
  - QR task lifecycle
  - fallback confirmation-host coordination
  - key-update alert state
  - file-load branching

**Assessment**

This screen proves that helper extraction is already paying off, but it also shows the limit of helper-only factoring. The remaining coordination logic is still view-owned. It is also the active production entry point for QR-photo import, file import, and paste import.

### 3.3 App Root And Tutorial Compatibility

#### [`CypherAirApp`](../Sources/App/CypherAirApp.swift)

**Classification**

- `Coordination hotspot`
- `Sensitive / constrained`

**Verified evidence**

- The app root still does all of the following:
  - builds the dependency container
  - runs startup recovery
  - owns iOS onboarding/tutorial presentation state
  - coordinates onboarding-to-tutorial handoff
  - handles URL-driven contact import
  - presents global alerts for import and startup conditions
- It is not a fully monolithic app root anymore. The repository already has real extracted seams:
  - [`AppStartupCoordinator`](../Sources/App/AppStartupCoordinator.swift) for persisted-state loading and recovery
  - [`TutorialOnboardingHandoffState`](../Sources/App/Shell/IOSPresentation.swift) for iOS onboarding/tutorial handoff state
  - [`ImportConfirmationCoordinator`](../Sources/App/Contacts/ImportConfirmationCoordinator.swift) for import confirmation hosting
  - [`PublicKeyImportLoader`](../Sources/App/Contacts/Import/PublicKeyImportLoader.swift) and [`ContactImportWorkflow`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift) reused in URL import handling

**Assessment**

The right takeaway is not "CypherAirApp has no seams." The right takeaway is "CypherAirApp is still overloaded even though some coordination seams already exist." Any future coordinator work should wrap and relocate those seams rather than rebuilding them from scratch.

#### [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift)

**Classification**

- `Large but coherent`
- `Coordination hotspot`

**Verified evidence**

- It is the central tutorial state owner by design.
- It owns lifecycle state, sandbox container lifecycle, navigation state, visible-surface reporting, module progression, and tutorial artifacts.
- Existing tests in [`TutorialSessionStoreTests`](../Tests/ServiceTests/TutorialSessionStoreTests.swift) explicitly treat it as the source of truth for tutorial behavior, including full-flow artifact recording, replay/reset semantics, and tutorial-sandbox container lifecycle.

**Assessment**

This is not the kind of "large" file that should be broken up immediately. It is large because it is the intentional state machine for the tutorial product.

#### [`TutorialConfigurationFactory`](../Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift)

**Classification**

- `Within boundary`

**Verified evidence**

- The factory is the compatibility seam between tutorial state and production pages.
- It injects restrictions and callbacks without forking the production screens.
- Existing tests in [`TutorialSessionStoreTests`](../Tests/ServiceTests/TutorialSessionStoreTests.swift) verify key configuration behavior for tool pages, key detail, backup, and settings restrictions.

**Assessment**

This file is strategically important because it makes a production-screen refactor possible without forcing a tutorial rewrite.

#### [`TutorialRouteDestinationView`](../Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift), [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift), and [`TutorialShellDefinitionsBuilder`](../Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift)

**Classification**

- `Within boundary` to `Large but coherent`

**Verified evidence**

- These files are host adapters:
  - route-to-view adaptation
  - tutorial host wrapping
  - tab/root definition building
- They are integration-dense, but the responsibilities are still clear.

**Assessment**

These are not the first structural rewrite targets. They should evolve only as much as needed to keep tutorial routing compatible with production-page changes.

#### [`TutorialSandboxContainer`](../Sources/App/Onboarding/TutorialSandboxContainer.swift)

**Classification**

- `Within boundary`
- `Sensitive / constrained`

**Verified evidence**

- The file is a focused tutorial-only composition root backed by sandbox storage and mock security primitives.
- Existing tests in [`TutorialSessionStoreTests`](../Tests/ServiceTests/TutorialSessionStoreTests.swift) verify:
  - isolated contacts storage
  - isolated defaults suite naming
  - mock-backed auth/security stack wiring
  - fresh-container lifecycle during reset/replay flows

**Assessment**

This boundary is working for the current product. The current tests support concrete sandbox-storage and lifecycle claims; they do not justify broader, undocumented isolation claims beyond those verified behaviors.

## 4. Missing Architectural Prerequisites

The current repository has real reusable seams, but it is still missing several refactor prerequisites that the previous implementation spec treated as if they already existed.

### 4.1 The Repo Now Has An Initial Screen-Model Example, But Reuse Coverage Is Still Limited

The repository already defines the recommended screen-model ownership pattern in [CONVENTIONS](CONVENTIONS.md), and `SignView` / `SignScreenModel` now establish the first in-repo baseline for it. What the repository still lacks in `Sources/App/` is broader, repeated reuse of that pattern across the remaining workflow-heavy screens, including one canonical approach for:

- a top-level route view reading `@Environment`
- a view owning an `@Observable` reference type via `@State`
- explicit dependency passing from the view layer into that model
- one-time preparation versus repeated appearance
- model-owned cleanup for current `onDisappear` / `onChange` logic

That limited reuse coverage still matters because the current overloaded views depend heavily on direct `@State`, `@Environment`, and lifecycle modifiers.

### 4.2 Cleanup Ownership Is Still View-Centric

Several refactor targets contain cleanup or invalidation logic that is currently inseparable from view lifecycle:

- [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift): `onDisappear`, `onChange`, temp-file cleanup, text/file invalidation
- [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift): `onAppear` prefill and callback initialization
- [`VerifyView`](../Sources/App/Sign/VerifyView.swift): cleartext invalidation and imported-file cleanup
- [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift): export bootstrapping and sheet/export transient state

Any future screen-model plan must define how that ownership moves, not merely state that it should move.

### 4.3 Contact Import Ownership Is Only Partially Decided Today

The current code already has App-layer import helpers and a Service-layer facade. That means the architecture boundary for "contact import workflow" is not yet singular. A future spec must decide, explicitly:

- what remains inside [`ContactService`](../Sources/Services/ContactService.swift)
- what belongs in repository/persistence collaborators
- what remains in App-layer confirmation and import helpers

Without that decision, a new internal `ContactImportService` risks duplicating the responsibility already held by [`ContactImportWorkflow`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift).

## 5. Existing Reusable Seams

The repository is not starting from zero. Several already-existing seams should be treated as reuse points for any future refactor.

### 5.1 App-Level Workflow Helpers

- [`OperationController`](../Sources/App/Common/OperationController.swift): shared async task lifecycle, cancellation, progress, error mapping, clipboard notice handling
- [`FileExportController`](../Sources/App/Common/FileExportController.swift): shared exporter payload state for data and file export
- [`ImportedTextInputState`](../Sources/App/Common/TextImport/ImportedTextInputState.swift): current imported-text tracking and invalidation helper
- [`SecurityScopedFileAccess`](../Sources/App/Common/SecurityScopedFileAccess.swift): reusable file-access boundary for App-layer file operations

### 5.2 Contact Import Helpers

- [`PublicKeyImportLoader`](../Sources/App/Contacts/Import/PublicKeyImportLoader.swift): URL, photo, file, and inspection helper
- [`ContactImportWorkflow`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift): confirmation and replacement request shaping
- [`ImportConfirmationCoordinator`](../Sources/App/Contacts/ImportConfirmationCoordinator.swift): presentation host for import confirmation

These helpers already separate some concerns from [`AddContactView`](../Sources/App/Contacts/AddContactView.swift) and URL import handling in [`CypherAirApp`](../Sources/App/CypherAirApp.swift).

### 5.3 Tutorial Compatibility Seams

- `Configuration` structs on the current production pages
- [`TutorialConfigurationFactory`](../Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift)
- [`TutorialRouteDestinationView`](../Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift)
- [`TutorialShellDefinitionsBuilder`](../Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift)
- [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift)

These seams are the reason a production-page refactor can remain tutorial-compatible without a production/tutorial fork.

### 5.4 Startup And Presentation Seams

- [`AppStartupCoordinator`](../Sources/App/AppStartupCoordinator.swift)
- [`TutorialOnboardingHandoffState`](../Sources/App/Shell/IOSPresentation.swift)
- `iosPresentationController` / `macPresentationController` environment bridges

These are not yet a complete coordinator layer, but they are already real boundaries that should be preserved and relocated rather than discarded.

## 6. Updated Priority Ranking

| Priority | Surface | Why it ranks here | Risk level | Suggested next action |
|---|---|---|---|---|
| P1 | [`KeyManagementService`](../Sources/Services/KeyManagementService.swift) | Largest service, broadest responsibility spread, closest to security-sensitive behavior | High | Split internal ownership behind the existing facade |
| P1 | [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift) | Most overloaded production screen and the clearest workflow state machine in the App layer | High | Use it to define the screen-model cleanup and long-running-operation pattern |
| P1 | [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift) | Same architectural pressure as decrypt, with heavy exporter and output-interception state | High | Refactor in the same pattern once decrypt is defined |
| P1 | [`SettingsView`](../Sources/App/Settings/SettingsView.swift) | Security-adjacent coordination hidden inside a view, with auth-mode flow split across confirmation and presentation helpers | High | Extract a screen model and pull auth-mode flow ownership together without changing `AuthenticationManager` behavior |
| P2 | [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift) | Detail page is already a workflow coordinator | Medium | Move export/delete/revocation/expiry state out of the view |
| P2 | [`ContactService`](../Sources/Services/ContactService.swift) | Persistence and import-policy concerns are still mixed | Medium | Split persistence first; do not duplicate App-layer workflow helpers |
| P2 | [`AddContactView`](../Sources/App/Contacts/AddContactView.swift) | Active production contact-import entry point; partially extracted already, but the remaining coordination is still view-owned | Medium | Reuse the existing helpers and move the remaining state machine out of the view |
| P2 | [`CypherAirApp`](../Sources/App/CypherAirApp.swift) | App root is still overloaded, but existing seams mean it can be tackled after the screen-model pattern is proven | Medium | Wrap and relocate existing startup/presentation/import seams into coordinators |
| P3 | [`SignView`](../Sources/App/Sign/SignView.swift) and [`VerifyView`](../Sources/App/Sign/VerifyView.swift) | Less urgent, but architecturally aligned with encrypt/decrypt changes | Medium | Migrate after the long-running-tool-screen pattern is established |
| P3 | Tutorial host adapters | Large, but not currently the main source of boundary drift | Low | Keep stable; adapt only for compatibility |
| P4 | Smaller helpers and single-purpose services | Most are already narrow and useful | Low | Leave them alone unless a higher-priority change proves they need adjustment |

## 7. Risks And Non-Goals

### 7.1 Refactor Risks

- Security-adjacent code is nearby even when a target file lives under `Sources/App/`.
- Tutorial compatibility is not optional; production-page refactors must preserve the current configuration-driven adaptation model.
- Current tests are strong on services and tutorial state, but they are still less exhaustive on UI-level parity for tool screens than on service semantics.
- A screen-model refactor that does not first define ownership and cleanup rules will likely produce inconsistent patterns across pages.

### 7.2 Explicit Non-Goals For The First Structural Refactor

- No change to user-visible behavior, strings, route structure, tutorial module order, or current import/export semantics.
- No Rust changes.
- No behavioral changes under `Sources/Security/`.
- No rewrite of the tutorial state machine in [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift).
- No attempt to unify the production and tutorial containers.
- No facade API narrowing as part of the initial ownership split.

## 8. Assessment Summary

The current repository does not have a generic "everything is too big" problem. It has a more specific structural pattern:

- one clear god service: [`KeyManagementService`](../Sources/Services/KeyManagementService.swift)
- one second-tier service with mixed persistence and import-policy ownership: [`ContactService`](../Sources/Services/ContactService.swift)
- several production pages that have grown into workflow coordinators: [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift), [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift), the broader Settings/auth-mode surface centered on [`SettingsView`](../Sources/App/Settings/SettingsView.swift), [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift), and the active contact-import surface [`AddContactView`](../Sources/App/Contacts/AddContactView.swift)
- an app root that is still doing too much coordination work even though some seams have already been extracted: [`CypherAirApp`](../Sources/App/CypherAirApp.swift)
- tutorial host seams that are currently valuable and should be preserved, not rewritten
- one major missing prerequisite: the repository still has no shared, repo-validated implementation baseline for the documented screen-model pattern

That means the next implementation spec should focus on:

- preserving current facades and tutorial `Configuration` compatibility
- defining the missing screen-model ownership pattern before broad screen migration
- extracting internal ownership only where the current code clearly justifies it
- treating the Settings/auth-mode flow as a cross-view surface rather than as a single-page cleanup
- describing app-presentation coordination in cross-platform terms rather than as an iOS-only handoff problem
- reusing existing helpers and coordinators instead of assuming a blank-slate rewrite
