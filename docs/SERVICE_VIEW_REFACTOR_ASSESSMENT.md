# Service / View Refactor Assessment

> Purpose: Assess the current Service and App-layer boundaries in CypherAir before any structural refactor work begins.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [CONVENTIONS](CONVENTIONS.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)

## 1. Scope And Classification

This assessment reviews three related surfaces together:

1. production services under `Sources/Services/`
2. production views and app hosts under `Sources/App/`
3. tutorial and onboarding host layers that adapt production pages into the guided tutorial sandbox

The goal is not to prescribe patch-level implementation steps. The goal is to classify the current state, document evidence, and identify where the design boundaries are currently holding versus where they are already overloaded.

This assessment uses the following labels consistently:

- `Within boundary`: the file is doing the job expected of its layer, even if it is not tiny.
- `Large but coherent`: the file is big, but the responsibilities are still mostly aligned to one domain.
- `Boundary overflow`: the file mixes responsibilities that belong in different layers or abstractions.
- `Coordination hotspot`: the file is the place where too many flows converge, even if each individual flow is still understandable.
- `Sensitive / constrained`: the file sits near a security or product boundary where structural change needs extra caution.

Boundary judgments are based on current code shape, current integration seams, and current project rules. They are not based on line count alone. The relevant UI rule already exists in [CONVENTIONS](CONVENTIONS.md): views should stay thin and avoid business logic, Keychain access, and crypto operations in views. The same expectation appears in [CODE_REVIEW](CODE_REVIEW.md).

## 2. Current-State Matrix

| Surface | Current role | Approx. size | Classification | Evidence summary | Immediate implication |
|---|---|---:|---|---|---|
| [`KeyManagementService`](../Sources/Services/KeyManagementService.swift) | Key lifecycle facade plus SE unwrap, export, mutation, metadata, and recovery | 679 lines | `Boundary overflow`, `Sensitive / constrained` | One type owns generation, import, export, revocation export, expiry mutation, deletion, default-key logic, crash recovery, and private-key unwrap | This is the clearest god service candidate and the riskiest refactor surface in the Service layer |
| [`ContactService`](../Sources/Services/ContactService.swift) | Public-key persistence, merge/update handling, replacement detection, verification-state storage | 385 lines | `Large but coherent` trending toward `Boundary overflow` | Same file owns validation handoff, merge decisions, file I/O, metadata manifest, and in-memory list maintenance | Good candidate for internal repository/import split while keeping the facade stable |
| [`EncryptionService`](../Sources/Services/EncryptionService.swift) | Text/file encryption orchestration | 334 lines | `Large but coherent` | Service remains focused on encryption, but text/file/streaming branches duplicate coordination logic | Not the first structural split target; helper extraction is sufficient for the first refactor wave |
| [`DecryptionService`](../Sources/Services/DecryptionService.swift) | Two-phase decrypt orchestration, streaming file decrypt, signature resolution | 356 lines | `Large but coherent`, `Sensitive / constrained` | The Phase 1 / Phase 2 boundary is clear, but the file is security-critical and carries multiple orchestration paths | Preserve the current public contract; avoid semantic churn while views are being thinned |
| [`SigningService`](../Sources/Services/SigningService.swift) | Sign/verify orchestration for text and files | 290 lines | `Large but coherent` | Clear responsibility, mostly a transport/orchestration service over engine calls | Not a first-wave service split target |
| [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift) | Encrypt form, recipient selection, export UX, file import/export, task orchestration | 614 lines | `Boundary overflow` | 4 environment dependencies, 16 state properties, 351-line `body`, file-export wiring, output interception, warning flow, and async orchestration all live in one view | This screen has already outgrown the "thin view" expectation |
| [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift) | Two-phase decrypt screen, import heuristics, temp-file cleanup, export UX | 754 lines | `Boundary overflow` | 17 state properties, 289-line `body`, manual invalidation logic, armored-text heuristics, file inspection, temp-file deletion, and async orchestration | This is the most overloaded page in the App layer and the strongest screen-model candidate |
| [`SignView`](../Sources/App/Sign/SignView.swift) | Cleartext/detached signing screen | 414 lines | `Large but coherent` | Still mostly one workflow, but it owns both rendering and task/export orchestration | Worth moving to a screen model during the core-flow refactor, but not the worst current offender |
| [`VerifyView`](../Sources/App/Sign/VerifyView.swift) | Cleartext/detached verify screen | 475 lines | `Large but coherent` | Shares the same pattern as `SignView`, with additional file-import and streaming-verify coordination | Similar treatment to `SignView`; lower urgency than decrypt/encrypt |
| [`SettingsView`](../Sources/App/Settings/SettingsView.swift) | Settings UI plus auth-mode switching and onboarding/tutorial launch coordination | 433 lines | `Coordination hotspot`, `Sensitive / constrained` | The view directly coordinates auth-mode confirmation, mode switching, backup-aware warnings, and platform-specific presentation branching | This is not just a form anymore; it is a coordinator hidden inside a view |
| [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift) | Key detail UI plus export, default-key, delete, revocation, and modify-expiry coordination | 418 lines | `Coordination hotspot` | The view kicks off async revocation export, clipboard writes, default-key updates, destructive delete, and modal presentation | Clear candidate for a screen model even if key-generation/import screens are deferred |
| [`AddContactView`](../Sources/App/Contacts/AddContactView.swift) | Contact import UI with paste/QR/file modes | 349 lines | `Coordination hotspot` | Better factored than other screens because it already uses `PublicKeyImportLoader` and `ContactImportWorkflow`, but the view still owns import-mode state, QR task lifecycle, fallback host wiring, and alert flow | Good reference point for future extraction, but still not fully thin |
| [`CypherAirApp`](../Sources/App/CypherAirApp.swift) | App composition root plus startup, onboarding/tutorial handoff, URL import coordination, and global alerts | 380 lines | `Coordination hotspot`, `Sensitive / constrained` | The app root constructs the container, runs startup, manages iOS presentation state, coordinates tutorial handoff, and handles URL-based contact import | The app root is doing more than composition and needs dedicated coordinators before further growth |
| [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift) | Tutorial session state machine and sandbox-flow owner | 432 lines | `Large but coherent`, `Coordination hotspot` | Central state owner for tutorial lifecycle, sandbox artifacts, navigation, modal routing, and task progression | This is intentionally central and should be preserved, not rewritten, in the first refactor wave |
| [`TutorialView`](../Sources/App/Onboarding/TutorialView.swift) | Tutorial host UI and hub/completion presentation | 382 lines | `Large but coherent` | Large host view, but the responsibilities still align with the tutorial experience rather than leaking into unrelated domains | Lower priority than production screens; keep stable while adapting integrations around it |
| [`TutorialConfigurationFactory`](../Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift) | Adapter from tutorial state to production-page configuration | 195 lines | `Within boundary` | It is a focused compatibility seam that feeds configuration into production pages without rewriting them | Keep this seam; it is the main reason a production-page refactor can stay tutorial-compatible |
| [`TutorialRouteDestinationView`](../Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift) | Tutorial-specific route adapter for production pages | 150 lines | `Within boundary` | Its job is almost entirely route adaptation and host wrapping | Keep stable; update only as production pages change shape |
| [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift) | Tutorial host wrapper and inline-header integration | 237 lines | `Large but coherent` | It centralizes tutorial host chrome and visible-surface reporting | This is integration-heavy but structurally healthy |
| [`TutorialShellDefinitionsBuilder`](../Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift) | Tutorial tab/root composition | 106 lines | `Within boundary` | Purpose is narrow and clear | No current boundary issue |
| [`TutorialSandboxContainer`](../Sources/App/Onboarding/TutorialSandboxContainer.swift) | Isolated tutorial dependency graph and sandbox storage | 118 lines | `Within boundary`, `Sensitive / constrained` | Focused composition root backed by tutorial-only storage and mock security primitives | Preserve this isolation boundary; do not fold it into the main app container in the first wave |

## 3. Service Findings

### 3.1 [`KeyManagementService`](../Sources/Services/KeyManagementService.swift)

**Classification**

- `Boundary overflow`
- `Sensitive / constrained`

**Evidence**

- The file is the largest service in the repository at 679 lines.
- It carries at least five distinct responsibility families:
  - key enumeration and metadata loading
  - generation and import
  - export and revocation export
  - expiry mutation, deletion, and default-key mutation
  - crash recovery and private-key unwrap
- It owns 9 injected collaborators or stores, including Secure Enclave, Keychain, defaults, metadata storage, and migration coordination.
- The largest methods already read like internal workflows rather than facade entry points:
  - `generateKey(...)`
  - `importKey(...)`
  - `modifyExpiry(...)`
  - `exportRevocationCertificate(...)`

**Why this is beyond the intended boundary**

`KeyManagementService` is no longer only a service facade for "key management". It is also acting as:

- a catalog store
- a provisioning workflow owner
- an export workflow owner
- a mutation transaction coordinator
- a crash-recovery coordinator
- a private-key access gateway

That breadth matters more than the raw line count because each responsibility brings a different risk profile and test surface.

**Impact**

- Review cost is high because routine key-feature changes share a file with security-sensitive recovery and unwrap paths.
- The service has become the default dependency for unrelated downstream concerns, which makes future splitting harder if postponed.
- A small change to one key flow risks accidental regression in another because the file is the only place where many of those behaviors are expressed.

**Suggested action**

- Keep the current facade name and public call surface in the first refactor wave.
- Split internal ownership behind the facade so the file stops being the only home for every key-lifecycle concern.

### 3.2 [`ContactService`](../Sources/Services/ContactService.swift)

**Classification**

- `Large but coherent`

**Evidence**

- The file is 385 lines and still mostly about one domain: imported public contacts.
- The main pressure point is `addContact(...)`, which spans validation, same-fingerprint merge, same-user replacement detection, file persistence, verification-state persistence, and in-memory updates.
- The service also owns both contact file storage and the verification-state manifest format.

**Why this is still mostly coherent**

Unlike `KeyManagementService`, the logic still orbits one business capability: storing and evolving trusted public-contact state. The problem is not a domain mismatch. The problem is that repository, import policy, and merge/replacement workflow are all collapsed into one type.

**Impact**

- Contact import behavior is harder to reason about than it needs to be.
- It is difficult to reuse or unit-isolate persistence behavior versus merge behavior without going through the full service surface.
- The current shape encourages App-layer flows to treat the service as a transaction script endpoint.

**Suggested action**

- Preserve `ContactService` as the facade.
- Separate persistence responsibilities from import/merge workflow responsibilities behind the facade.

### 3.3 Other Services

The remaining services are not the current primary split targets:

- [`EncryptionService`](../Sources/Services/EncryptionService.swift): `Large but coherent`. It should stay focused on encryption orchestration while core screens are moved off view-owned coordination.
- [`DecryptionService`](../Sources/Services/DecryptionService.swift): `Large but coherent`, `Sensitive / constrained`. Preserve the existing two-phase contract and avoid structural changes that obscure the auth boundary.
- [`SigningService`](../Sources/Services/SigningService.swift): `Large but coherent`. Internal helper extraction is fine; a facade split is not urgent.
- [`PasswordMessageService`](../Sources/Services/PasswordMessageService.swift): `Within boundary`. Small and purpose-built.
- [`SelfTestService`](../Sources/Services/SelfTestService.swift): `Large but coherent`. It is intentionally a diagnostic orchestrator rather than a production workflow owner.

## 4. View Findings

### 4.1 Core Message Screens

#### [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift)

**Classification**

- `Boundary overflow`

**Evidence**

- 614 lines total and a 351-line `body`.
- 4 environment dependencies and 16 local state properties.
- The view does not only render:
  - it computes recipient compatibility state
  - coordinates confirmation dialogs
  - runs file operations
  - manages export and clipboard interception
  - owns task lifecycle state via `OperationController`

**Impact**

- Presentation and workflow changes are tightly coupled.
- Tutorial restrictions and production behavior are both threaded through the same view type.

**Suggested action**

- Move state transitions, task orchestration, and output handling into a dedicated screen model while keeping the current `Configuration` seam intact.

#### [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift)

**Classification**

- `Boundary overflow`

**Evidence**

- 754 lines total and a 289-line `body`.
- 17 local state properties.
- The view performs several non-render responsibilities directly:
  - text/file mode invalidation and cleanup
  - armored-text file inspection and suggestion flow
  - imported-file state reconciliation
  - temporary-output deletion
  - async parse/decrypt orchestration

**Impact**

- This is the clearest App-layer example of a screen acting as its own workflow state machine.
- The current shape makes the security-sensitive decrypt experience harder to review because view logic and workflow logic are interleaved.

**Suggested action**

- Make this the first screen-model extraction target in the View layer.

#### [`SignView`](../Sources/App/Sign/SignView.swift) and [`VerifyView`](../Sources/App/Sign/VerifyView.swift)

**Classification**

- `Large but coherent`

**Evidence**

- Both screens follow the same pattern as encrypt/decrypt:
  - render form controls
  - manage file picker state
  - run async work
  - own export and error presentation
- `VerifyView` also owns detached-file import and streaming verification setup.

**Impact**

- These pages are not as overloaded as decrypt, but they repeat the same architectural pattern that caused encrypt/decrypt to grow too large.

**Suggested action**

- Refactor them in the same wave as encrypt/decrypt so the screen architecture becomes consistent across the message tools.

### 4.2 Settings And Key Detail

#### [`SettingsView`](../Sources/App/Settings/SettingsView.swift)

**Classification**

- `Coordination hotspot`
- `Sensitive / constrained`

**Evidence**

- The view directly coordinates:
  - auth-mode picker interception
  - warning generation
  - backup-aware risk messaging
  - async mode switching
  - onboarding/tutorial launch routing
  - platform-specific presentation fallbacks

**Impact**

- A settings change now requires reviewing both UI behavior and security-mode orchestration in the same file.
- The view is effectively acting as a coordinator already.

**Suggested action**

- Move mode-switch intent handling and presentation state into a screen model while keeping `AuthenticationManager` behavior unchanged.

#### [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift)

**Classification**

- `Coordination hotspot`

**Evidence**

- The view directly drives revocation export, public-key copy, delete confirmation, default-key mutation, and modify-expiry presentation.
- It also owns multiple export-related state machines and async task state.

**Impact**

- This is a high-value refactor target because key detail is already a mini workflow surface rather than a pure detail page.

**Suggested action**

- Move action orchestration and export state into a screen model; keep the visible layout and navigation structure unchanged.

### 4.3 Contact Import

#### [`AddContactView`](../Sources/App/Contacts/AddContactView.swift)

**Classification**

- `Coordination hotspot`

**Evidence**

- The view already depends on two extracted helpers:
  - [`PublicKeyImportLoader`](../Sources/App/Contacts/Import/PublicKeyImportLoader.swift)
  - [`ContactImportWorkflow`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift)
- That is a good sign, but the view still owns:
  - import-mode switching
  - QR task lifecycle
  - fallback confirmation-host coordination
  - key-update alert state
  - file-load branching

**Impact**

- This screen proves the extraction direction is workable, but it also shows the current limit of helper-only factoring. The remaining coordination logic is still view-owned.

**Suggested action**

- Promote the remaining view-owned coordination into a screen model while preserving the loader/workflow helpers and confirmation coordinator.

### 4.4 App Root

#### [`CypherAirApp`](../Sources/App/CypherAirApp.swift)

**Classification**

- `Coordination hotspot`
- `Sensitive / constrained`

**Evidence**

- The app root currently does all of the following:
  - builds the dependency container
  - runs startup recovery
  - manages iOS onboarding/tutorial presentation state
  - coordinates onboarding-to-tutorial handoff
  - handles URL-driven contact import
  - surfaces global alerts for import and startup conditions

**Impact**

- This makes the app root harder to reason about than a composition root should be.
- It also means tutorial hosting and URL import behavior currently depend on the same file that owns initial dependency construction.

**Suggested action**

- Move app-flow coordination into dedicated coordinators so `CypherAirApp` can become a composition root again.

## 5. Tutorial / Onboarding Findings

### 5.1 [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift)

**Classification**

- `Large but coherent`
- `Coordination hotspot`

**Evidence**

- The store is the central tutorial state owner by design.
- It owns lifecycle state, sandbox container lifecycle, navigation state, visible-surface reporting, module progression, and tutorial artifacts.
- The existing tests in [`TutorialSessionStoreTests`](../Tests/ServiceTests/TutorialSessionStoreTests.swift) already treat it as the source of truth for tutorial behavior.

**Assessment**

- This is not the kind of "large" file that should be broken up immediately.
- It is large because it is the intentional state machine for the tutorial product.

**Suggested action**

- Keep this state machine stable in the first refactor wave.
- Refactor the production-page adapters around it, not the tutorial state model itself.

### 5.2 [`TutorialConfigurationFactory`](../Sources/App/Onboarding/Tutorial/TutorialConfigurationFactory.swift)

**Classification**

- `Within boundary`

**Evidence**

- The factory is the current compatibility seam between tutorial state and production pages.
- It injects restrictions and callbacks without rewriting the production screens themselves.

**Assessment**

- This file is strategically important because it makes a production-screen refactor possible without forcing a tutorial rewrite.

**Suggested action**

- Preserve the factory pattern and keep `Configuration` compatibility as a design constraint.

### 5.3 [`TutorialRouteDestinationView`](../Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift), [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift), and [`TutorialShellDefinitionsBuilder`](../Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift)

**Classification**

- `Within boundary` to `Large but coherent`

**Evidence**

- These files are mostly host adapters:
  - route-to-view adaptation
  - tutorial host wrapping
  - tab/root definition building
- They are integration-dense, but the responsibilities are clear.

**Assessment**

- These are not first-wave rewrite candidates.
- They should evolve only as much as needed to keep tutorial routing compatible with production-page changes.

### 5.4 [`TutorialSandboxContainer`](../Sources/App/Onboarding/TutorialSandboxContainer.swift)

**Classification**

- `Within boundary`
- `Sensitive / constrained`

**Evidence**

- The file is a focused tutorial-only composition root backed by sandbox storage and mock security primitives.
- Existing tests already validate its isolation guarantees.

**Assessment**

- This boundary is working for the current product.
- It should not be merged into the main app container during the first refactor wave.

### 5.5 [`OnboardingView`](../Sources/App/Onboarding/OnboardingView.swift) and [`TutorialView`](../Sources/App/Onboarding/TutorialView.swift)

**Classification**

- `Within boundary` to `Large but coherent`

**Evidence**

- `OnboardingView` remains primarily presentation logic with handoff actions.
- `TutorialView` is a large host, but its size comes from hub/completion presentation and tutorial-owned navigation, not from direct service orchestration.

**Assessment**

- The biggest tutorial/onboarding risk is not the views themselves.
- The biggest risk is the app-root and compatibility seams that launch and wrap them.

## 6. Priority Ranking

| Priority | Surface | Why it ranks here | Risk level | Suggested next action |
|---|---|---|---|---|
| P1 | [`KeyManagementService`](../Sources/Services/KeyManagementService.swift) | Largest service, broadest responsibility spread, closest to security-sensitive behavior | High | Split internal ownership behind the existing facade |
| P1 | [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift) | Most overloaded production screen and most workflow-heavy App file | High | Move to a dedicated screen model first |
| P1 | [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift) | Same architectural pressure as decrypt, large coordination surface | High | Refactor in the same wave as decrypt |
| P1 | [`SettingsView`](../Sources/App/Settings/SettingsView.swift) | Security-sensitive coordination hidden inside a view | High | Extract a screen model without changing `AuthenticationManager` behavior |
| P1 | [`CypherAirApp`](../Sources/App/CypherAirApp.swift) | App root is overloaded with startup, handoff, and URL-import coordination | High | Introduce dedicated app-flow coordinators |
| P2 | [`ContactService`](../Sources/Services/ContactService.swift) | Repository and import workflow logic are still collapsed into one service | Medium | Split persistence from import policy behind the facade |
| P2 | [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift) | Detail page is already a workflow coordinator | Medium | Extract a screen model in the key/settings wave |
| P2 | [`AddContactView`](../Sources/App/Contacts/AddContactView.swift) | Partially extracted already, but remaining coordination is still view-owned | Medium | Keep existing helpers and move the remaining state machine out of the view |
| P2 | Tutorial app-host integration seams | Tutorial compatibility depends on several adapters staying stable during production refactors | Medium | Treat `Configuration` compatibility as a non-negotiable constraint |
| P3 | [`SignView`](../Sources/App/Sign/SignView.swift) and [`VerifyView`](../Sources/App/Sign/VerifyView.swift) | Less urgent, but architecturally aligned with encrypt/decrypt changes | Medium | Refactor in the core message-flow wave after decrypt/encrypt are defined |
| P3 | [`TutorialView`](../Sources/App/Onboarding/TutorialView.swift) and [`TutorialSurfaceView`](../Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift) | Large, but not currently the main source of boundary drift | Low | Keep stable; adapt only for compatibility |
| P4 | Smaller helpers and single-purpose services | Most are already narrow and useful | Low | Leave them alone unless a higher-priority change proves they need adjustment |

## 7. Risks And Non-Goals

### 7.1 Refactor Risks

- Security-adjacent code is nearby even when a target file is in `Sources/App/`.
- Tutorial compatibility is not optional; production-page refactors must preserve the current configuration-driven adaptation model.
- Xcode project updates will be unavoidable once new files are added, so implementation should batch project-file edits carefully.
- Current tests are strong on services and tutorial state, but thinner on UI-level parity for encrypt/decrypt/sign/verify flows than on service semantics.

### 7.2 Explicit Non-Goals For The First Refactor Wave

- No change to user-visible behavior, strings, route structure, tutorial module order, or current import/export semantics.
- No Rust changes.
- No first-wave behavior changes under `Sources/Security/`.
- No rewrite of the tutorial state machine in [`TutorialSessionStore`](../Sources/App/Onboarding/TutorialSessionStore.swift).
- No attempt to unify the production and tutorial containers.
- No facade API narrowing as part of the first structural split.

## 8. Assessment Summary

The current repository does not have a generic "everything is too big" problem. It has a more specific structural pattern:

- one clear god service: [`KeyManagementService`](../Sources/Services/KeyManagementService.swift)
- one second-tier service with mixed repository and import-policy ownership: [`ContactService`](../Sources/Services/ContactService.swift)
- several production pages that have grown into workflow coordinators: [`EncryptView`](../Sources/App/Encrypt/EncryptView.swift), [`DecryptView`](../Sources/App/Decrypt/DecryptView.swift), [`SettingsView`](../Sources/App/Settings/SettingsView.swift), [`KeyDetailView`](../Sources/App/Keys/KeyDetailView.swift), and [`AddContactView`](../Sources/App/Contacts/AddContactView.swift)
- an app root that is doing too much coordination work: [`CypherAirApp`](../Sources/App/CypherAirApp.swift)
- tutorial host seams that are currently valuable and should be preserved, not rewritten, in the first wave

That means the refactor should focus on ownership boundaries and coordination flow, not on line-count reduction for its own sake.
