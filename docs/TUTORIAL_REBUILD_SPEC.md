# Tutorial Rebuild Specification

> Purpose: Define the ideal end-state guided tutorial product for CypherAir across iPhone, iPad, and macOS.
> Audience: Human developers, designers, product owners, and AI coding tools.
> Companion documents: [TUTORIAL_MODE_ISSUES](TUTORIAL_MODE_ISSUES.md) · [PRD](PRD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [LIQUID_GLASS](LIQUID_GLASS.md) · [TESTING](TESTING.md)
> Spec posture: This document defines the target tutorial product, not a patch plan for the current implementation. It is written from the ideal end-state backward. The final tutorial may diverge materially from the current code wherever needed to satisfy CypherAir's privacy, offline, security, accessibility, and cross-platform product goals. Current code may inform problem framing, reusable seams, and low-intrusion implementation direction, but it does not constrain the correctness of this target-state specification.

## 1. Product Intent

### 1.1 Why The Tutorial Exists

The guided tutorial exists to help a first-time CypherAir user reach confidence before they touch their real workspace. It must teach the minimum mental model required to understand what the app does, why it is safe, and how the core encryption workflow fits together.

The tutorial is not a marketing carousel and not a fake demo. It is a sandboxed learning experience that uses isolated tutorial data and isolated tutorial security plumbing while keeping the user close to the real app's UI, structure, and workflow.

The intended outcome is: "I understand what this app does, I trust the boundaries, I know where things live, and I know what to do next in the real app."

### 1.2 Product Goals

- Teach the core CypherAir workflow without requiring prior PGP knowledge.
- Preserve trust by making only promises the tutorial can literally keep.
- Keep the first-run learning path short, focused, and deterministic.
- Let the user learn the real app's UI, real navigation locations, and real workflow sequence inside an isolated sandbox.
- Use real tutorial-sandbox operations wherever safe: real key generation, real contact import into sandbox, real encryption, real decryption, real backup generation, and real auth-mode changes in sandbox.
- Restrict only the parts of the experience that would otherwise affect real user data or launch real-world side effects.
- Produce one coherent tutorial product across iPhone, iPad, and macOS, with platform adaptations but not separate tutorial philosophies.

### 1.3 Success Criteria

- A new user can finish the full guided tutorial in approximately 4 to 7 minutes on iPhone and iPad, and approximately 4 to 8 minutes on macOS, without touching real user data.
- After the tutorial, the user understands these concepts:
  - the tutorial is isolated from the real workspace
  - keys represent identities
  - contacts provide recipient public keys
  - encrypting and decrypting are separate steps
  - backup matters before stronger security decisions
  - High Security changes operational behavior
  - the real app is where they create and manage their own real key afterward
- The user can skip the tutorial at first run without broken state and replay it later from Settings.
- The tutorial never performs a real file import, real file export, real share sheet export, real clipboard write, photo-picker import, URL handoff, or real workspace mutation.
- The tutorial keeps the user close enough to real UI and navigation that the learning transfers directly into the real app.

### 1.4 Non-Goals

- The tutorial is not a full manual.
- The tutorial is not a fake slideshow detached from the app.
- The tutorial does not need final marketing copy or final localization strings in this specification.
- The tutorial is not the place to exercise real-world file exchange, QR photo workflows, or system-level export flows.
- The tutorial is not required to expose every production feature during the learning path.

### 1.5 Primary Users

| User | Need |
|------|------|
| First-time non-technical user | Understand the app safely and reach first confidence without touching real data |
| Returning user who skipped first run | Take the tutorial later from Settings |
| User who wants to learn backup and stronger security concepts | Practice those concepts in the same isolated tutorial flow |

## 2. Tutorial Product Model

### 2.1 Single Tutorial Product

CypherAir has one guided tutorial product, not separate "core" and "advanced" tutorial layers.

The tutorial is a single modular learning path inside one tutorial hub and one tutorial sandbox session model. Some modules may appear later in the sequence because they depend on earlier sandbox state, but they are still part of the same tutorial product.

### 2.2 Module Sequence

The tutorial contains these seven modules in fixed order:

1. Understand the tutorial sandbox
2. Create a demo identity
3. Add a demo contact
4. Encrypt a demo message
5. Decrypt and verify
6. Back up a key
7. Enable High Security

The tutorial ends only when the user explicitly finishes from the final completion surface.

### 2.3 Entry Points

| Entry Point | Behavior |
|------------|----------|
| First-run onboarding | Offers the tutorial as a primary learning path and allows skip |
| Settings replay | Opens the tutorial hub and allows replay |
| Completion surface | Ends the tutorial and hands the user to the app context; it does not branch into a separate advanced-tutorial product |

### 2.4 Replay Rules

- First-run always enters the same unified tutorial product.
- Settings replay opens the tutorial hub.
- Replaying starts a fresh sandbox session.
- The tutorial may show module-level progress for the current spec version, but it remains one product and one completion model.

### 2.5 Skip Rules

- First-run onboarding must always offer a clear skip path.
- Skipping the tutorial does not mark the tutorial as finished.
- Skipping does not create tutorial sandbox data.

### 2.6 Lifecycle Semantics

The product distinguishes these states:

| State | Meaning |
|------|---------|
| Not Started | No tutorial run has begun for the current spec version |
| In Progress | A tutorial sandbox session exists and the user is inside the tutorial |
| Steps Completed | All tutorial modules are complete, but the user has not yet explicitly finished from the completion surface |
| Finished | The user explicitly finished the tutorial; only here is the tutorial version recorded as complete |

Rules:

- Completing modules does not by itself write the global tutorial completion version.
- The global tutorial completion version is written only when the user explicitly finishes from the completion surface.
- If module-level progress is persisted for the current spec version, it is unified tutorial progress, not a separate advanced-module system.
- Resetting a sandbox session clears tutorial-local artifacts only; it does not erase tutorial completion history for the current spec version.

### 2.7 Mapping Tutorial Learning To Real App Use

The tutorial must continuously explain where each lesson maps in the real app.

Rules:

- Each module shows the corresponding real app area label, such as `Keys`, `Contacts`, `Encrypt`, `Decrypt`, or `Settings`.
- Guidance and completion states explain how the tutorial action maps to the real app.
- The final completion state ends with one explicit real-world next step: create a real key in the real app.

## 3. Cross-Platform Host Model

### 3.1 Shared Host Principles

- The tutorial is one product across platforms.
- The tutorial host owns sandbox isolation, navigation limits, exit semantics, and guidance presentation.
- The tutorial host should keep the user close to the real app's page structure and navigation locations while still enforcing tutorial restrictions.
- The tutorial host is responsible for isolating tutorial data and intercepting dangerous side effects; production pages should remain tutorial-agnostic where possible.

### 3.2 Onboarding Tutorial Decision Page

Onboarding page 3 is the tutorial decision page.

Rules:

- It is not a key-generation page.
- Its copy must clearly communicate:
  - the tutorial is an isolated sandbox
  - the user may start the tutorial first
  - the user may skip the tutorial and enter the real app
  - tutorial actions do not touch real keys, contacts, files, settings, or private-key security assets
- The page must present two distinct actions:
  - start guided tutorial
  - skip tutorial and enter app

The final marketing wording may change later, but the page intent and action semantics are fixed by this specification.

### 3.3 iPhone And iPad Host

- The tutorial launches as a dedicated full-screen experience.
- First run:
  - onboarding page 3 is the tutorial decision page
  - tapping the tutorial CTA must first close onboarding
  - after onboarding is closed, the app root launches the tutorial host
  - this is a one-way handoff; onboarding is not preserved as a return surface
- The tutorial CTA must not attempt to switch to tutorial mode from inside the still-present onboarding surface.
- Success means the user clearly sees onboarding disappear and then sees the tutorial page appear.
- If the user leaves or closes the tutorial after that one-way handoff, the app returns to the post-onboarding app-owned context, not to onboarding itself.
- Replay from Settings launches the tutorial as a dedicated full-screen experience and closing returns to the app context that launched it.

### 3.4 macOS Host

- The tutorial runs as a dedicated tutorial workspace in the main application window.
- It is not hosted as a Settings sheet and not hosted as an onboarding-nested sheet.
- Onboarding and Settings may request tutorial launch, but the main-window tutorial host owns the actual tutorial experience.
- Closing the tutorial returns to the app-owned context that launched it.

### 3.5 Exit Semantics

| Action | Meaning |
|--------|---------|
| Return | Go back from the current module surface to the tutorial hub inside the same tutorial session |
| Close | Leave the tutorial entirely; if progress is in flight, show a leave-confirmation surface |
| Finish | Mark the tutorial as finished and exit the tutorial host |

Rules:

- `Return` never exits the tutorial host.
- `Close` from an active module requires confirmation if a tutorial session is in progress.
- `Finish` is only available from a completion surface.
- First-run `Finish` enters the real app.
- After the one-way onboarding-to-tutorial handoff, tutorial exit must never relaunch onboarding.

### 3.6 Leave Confirmation

If the user attempts to close an in-progress tutorial run, the tutorial must present a tutorial-owned leave-confirmation surface with these actions:

- Continue Tutorial
- Leave Tutorial

This confirmation inherits the tutorial guidance contract and automation contract like any other tutorial modal.

## 4. Tutorial Safety Contract

### 4.1 Tutorial Promise

The tutorial may make exactly this class of promise:

"This tutorial uses isolated tutorial data in a tutorial workspace. It does not read or write your real keys, contacts, settings, files, exports, or other real workspace content."

The UI must not use stronger wording unless the implementation still makes it literally true.

### 4.2 Safety Posture

Tutorial safety is enforced at the tutorial-host level, not merely by injecting a different dependency container.

The host must:

- provide an isolated tutorial data container
- restrict tutorial routes
- intercept dangerous side effects
- preserve guidance while the user moves through real app pages inside the sandbox

### 4.3 Capability Whitelist

The tutorial host may allow only these capability classes:

- tutorial-local identities, contacts, messages, backup artifacts, and auth-mode state
- tutorial-local settings needed to drive sandbox behavior
- tutorial-owned navigation between hub, tutorial task states, completion, and leave confirmation
- guidance overlays, rails, anchors, and tutorial-owned helper surfaces
- tutorial-security simulation plumbing

Everything else is disallowed unless explicitly reintroduced as a tutorial-safe mechanism.

### 4.4 Disallowed Real-World Side Effects

The tutorial must not expose any of the following real-world side effects:

- system file importer against the user's real workspace
- system file exporter that writes real tutorial output into user-chosen destinations
- photo picker import
- share sheet export
- clipboard write actions
- URL handoff or app-open flows
- real app icon changes
- real onboarding management actions
- real app settings mutation outside the isolated tutorial container
- any use of the user's real Keychain items, real Secure Enclave tutorial keys, or real private-key storage path

### 4.5 Authentication And Security Simulation

The tutorial should preserve the real app's authentication feel as much as possible, but without touching the user's real private-key security assets.

Default contract:

- Use real system LocalAuthentication prompts where platform behavior permits.
- Route the authenticated tutorial flow into isolated tutorial security plumbing:
  - mock secure enclave
  - mock keychain
  - tutorial-local private-key wrapping/unwrapping path
- Do not use the user's real tutorial-unrelated Keychain items or real Secure Enclave-wrapped private keys.
- Tutorial-owned explanatory modals may stage or resume context around the system biometric prompt, but they must not replace the default authentication path.
- Only when a platform or test environment cannot reliably present the real system biometric interaction may the tutorial fall back to an explanatory confirmation.

### 4.6 Safe Replacements

When a real app action would create a dangerous real-world side effect, the tutorial must replace only that side effect, not the whole page or workflow.

| Real-world feature | Tutorial-safe handling |
|-------------------|------------------------|
| Import from photo or real file picker | Disable or intercept the dangerous entry while keeping the real page structure intact; use tutorial-provided sample data instead |
| Export backup file | Keep the real backup flow, but intercept the export sink to a tutorial-local artifact rather than a real system file destination |
| Copy/share ciphertext | Keep the real encryption flow, but intercept clipboard/share side effects and replace them with read-only tutorial output handling |
| Private-key security path | Keep the real page and real service flow, but route into tutorial-isolated mock security plumbing |

### 4.7 Scope Of Sandbox Guarantees

- The entire tutorial uses the same safety contract.
- A tutorial replay creates a fresh tutorial sandbox session.
- Tutorial keys, contacts, settings, and messages are ephemeral sandbox artifacts.
- The tutorial may use real cryptographic and service flows inside the sandbox, but it must clearly separate those from the user's real workspace.

## 5. Guidance Model

### 5.1 Guidance Principles

- Guidance must stay close to the current task.
- Guidance must survive context changes, especially around tutorial-owned modals and system biometric prompts.
- Guidance must explain one next action at a time.
- Guidance must indicate where the current lesson maps in the real app.
- Guidance must be recoverable if an auxiliary guidance surface is collapsed.

### 5.2 Tutorial Information Architecture

The tutorial has three top-level surface types:

| Surface | Role |
|---------|------|
| Tutorial Hub | Overview, progress, module map, and start/replay controls |
| Tutorial Workspace | Real app pages shown in a sandboxed, guided task state |
| Completion Surface | End-of-tutorial summary and next action |

The hub is not a large marketing hero page. It is a structured learning dashboard with:

- tutorial promise summary
- estimated time
- progress state
- primary action
- visible module map

### 5.3 Navigation Rules

- Modules unlock sequentially.
- The user may return to the hub between modules.
- The host may guide the user through real navigation locations, but dangerous routes and dangerous side effects must be filtered.
- The tutorial should prefer real page locations and real page structure over tutorial-exclusive replacements.

### 5.4 iPhone Guidance Placement

- Use a single-column layout.
- Show persistent task context at the top of the task state.
- Guidance may use spotlighting when there is exactly one current target.
- The guidance should overlay or frame the real page, not replace it.

### 5.5 iPad Regular-Width Guidance Placement

- Use a content area plus a dedicated guidance rail.
- The rail belongs to the tutorial host, not the platform inspector.
- The guidance rail supplements the real page shown in sandbox mode.

### 5.6 macOS Guidance Placement

- Use a module navigator, primary content area, and dedicated guidance rail.
- The guidance rail belongs to the tutorial host.
- If the rail is collapsed, the content area must show a persistent `Show Guidance` affordance.

### 5.7 Modal Continuity Contract

Tutorial-owned modals must preserve minimum task context:

- current module title
- why this modal exists
- what action the user is expected to take
- what happens next

If the actual authentication interaction is a system biometric prompt, the tutorial must provide that context immediately before or after the prompt, not instead of it.

### 5.8 Spotlight And Anchor Rules

- Tutorial anchors are required for guidance that points to a specific actionable control.
- The tutorial may highlight at most one primary target at a time.
- If a guidance step spans a tutorial-owned modal and then a real system prompt, anchor coverage must still make the user path legible.

## 6. Experience Contract By Tutorial Segment

### 6.1 Tutorial Overview

The guided tutorial is a single learning path to first confidence.

| Module | Teaches | Completion Criteria |
|--------|---------|---------------------|
| Sandbox | What tutorial mode is and is not | User acknowledges the sandbox and enters the tutorial |
| Create Demo Identity | A key is your encryption identity | A sandbox key is generated through the real key-generation flow |
| Add Demo Contact | Contacts hold recipient public keys | A sandbox contact is imported through the real contact flow |
| Encrypt Demo Message | Encryption produces protected output for a chosen contact | A sandbox message is encrypted through the real encrypt flow |
| Decrypt And Verify | Decryption reveals content and signature trust | A sandbox message is parsed, authenticated, and decrypted through the real decrypt flow |
| Back Up a Key | Backup protects a private key with a passphrase | A sandbox backup artifact is created through the real backup flow with export interception |
| Enable High Security | High Security changes auth behavior and depends on backup | Sandbox auth mode is changed through the real settings flow with isolated security plumbing |

### 6.2 Module: Understand The Sandbox

- Entry state:
  - visible tutorial promise
  - estimated time
  - explanation that the tutorial is isolated from the real workspace
- Required context:
  - no real files, exports, settings, or workspace mutations
  - the tutorial uses real pages and real services inside an isolated sandbox
- Completion:
  - explicit acknowledgement

### 6.3 Module: Create A Demo Identity

- Real-app mapping: `Keys`
- Teaching goal:
  - keys represent the user's identity
  - the tutorial uses a sandbox identity so the user can learn safely
- Interaction contract:
  - use the real key-generation page or a target-state equivalent that keeps the same structure and location expectations
  - the key must be generated in the sandbox at runtime
  - any tutorial defaults or locked values must be injected through generic configuration, not a tutorial-exclusive page

### 6.4 Module: Add A Demo Contact

- Real-app mapping: `Contacts`
- Teaching goal:
  - contacts provide public keys used for encryption
- Interaction contract:
  - use the real contact-import page or a target-state equivalent that keeps the same structure and location expectations
  - the imported contact must be stored in sandbox data only
  - dangerous import surfaces such as photo picker or real file importer must be disabled or intercepted by the host or configuration

### 6.5 Module: Encrypt A Demo Message

- Real-app mapping: `Encrypt`
- Teaching goal:
  - choose a recipient
  - write a message
  - produce protected output
- Interaction contract:
  - use the real encrypt page or a target-state equivalent that keeps the same structure and location expectations
  - encryption must run through the real service path in sandbox
  - dangerous side effects such as share, clipboard, or real export must be intercepted

### 6.6 Module: Decrypt And Verify

- Real-app mapping: `Decrypt`
- Teaching goal:
  - a message is first identified as intended for the user's key
  - decryption reveals the message
  - signature verification communicates trust
- Interaction contract:
  - use the real decrypt page or a target-state equivalent that keeps the same structure and location expectations
  - the decrypt flow must run through the real service path in sandbox
  - when authentication is required, the default target-state experience should preserve the real system biometric prompt while routing the secured operation through tutorial-isolated security plumbing

### 6.7 Module: Back Up A Key

- Real-app mapping: `Keys`
- Teaching goal:
  - a private key backup is protected with a passphrase
  - backup status matters before stronger security decisions
- Interaction contract:
  - use the real backup page or a target-state equivalent that keeps the same structure and location expectations
  - backup generation must run through the real service path in sandbox
  - the real exporter sink must be intercepted and replaced with a tutorial-local artifact

### 6.8 Module: Enable High Security

- Real-app mapping: `Settings`
- Teaching goal:
  - High Security removes passcode fallback
  - backup matters before enabling it
  - confirmation is a meaningful security decision
- Interaction contract:
  - use the real settings/auth-mode flow or a target-state equivalent that keeps the same structure and location expectations
  - the mode-switch path must use isolated tutorial security plumbing
  - the biometric interaction should remain as close as possible to the real app's experience while still isolating the user's real security assets

### 6.9 Completion Surface

The completion surface must include:

- confirmation that the tutorial is complete
- reminder that the real workspace is still untouched
- explicit next step in the real app: create a real key

The global tutorial completion version is written only when the user explicitly finishes from this surface.

## 7. Accessibility And Visual System

### 7.1 Accessibility Rules

- All tutorial text uses system text styles.
- All interactive elements meet 44x44 minimum target size.
- VoiceOver labels are required for all CTAs, step indicators, status badges, and tutorial-owned controls.
- Security-sensitive content remains fully readable and never depends on color alone.

### 7.2 Dynamic Type Rules

The tutorial hub and guided task layouts must have explicit accessibility-size behavior.

Rules:

- On compact iPhone at accessibility Dynamic Type sizes, the first screenful must still show:
  - tutorial identity and promise summary
  - the primary CTA
  - the beginning of the visible module map
- Guidance surfaces must wrap naturally and remain readable without truncating the task goal.

### 7.3 Regular-Width Rules

- On iPad regular width, guidance is shown in a dedicated rail adjacent to the content, not as a weak full-width strip.
- On macOS, the task content area remains the priority. Guidance and navigation chrome may not compress the real guided task surface below a usable width.

### 7.4 macOS Width Budget

- The content area is the primary width budget.
- Navigation and guidance rails must be sized around the content area, not vice versa.
- The default tutorial window must open wide enough to show all primary chrome without truncating the guided task surface.

### 7.5 Liquid Glass Rules

- Use standard SwiftUI navigation and control chrome where possible.
- Apply Liquid Glass to navigation and control layers only.
- Do not apply decorative glass to message content, fingerprints, passphrase education, or other security-sensitive reading surfaces.
- Guidance surfaces may use elevated control-layer styling, but content panels remain readability-first.

## 8. Technical Architecture Expectations

### 8.1 Architecture Posture

The rebuilt tutorial is a sandboxed, host-driven learning mode that prefers real production pages, real navigation locations, and real service flows, while isolating data and intercepting dangerous side effects.

### 8.2 Required Contract-Level Interfaces

The implementation must introduce clear contract-level boundaries equivalent to the following responsibilities:

| Interface | Responsibility |
|-----------|----------------|
| `TutorialSandboxHost` | Owns onboarding handoff, replay launch, host lifecycle, exit semantics, and tutorial-level UI surfaces |
| `TutorialSandboxContainer` | Provides isolated tutorial storage, isolated tutorial services, and tutorial-scoped runtime artifacts |
| `TutorialRouteFilter` | Whitelists tutorial-safe routes and blocks unsafe production routes inside the tutorial host |
| `TutorialSideEffectInterceptor` | Intercepts dangerous side effects such as real import/export, share, clipboard, and URL handoff |
| `TutorialSurfaceConfiguration` | Passes generic page-level constraints or defaults into real production pages without making them tutorial-aware |
| `TutorialGuidanceOverlayModel` | Provides guidance rails, overlays, anchors, target context, and modal continuity |
| `TutorialSecuritySimulationStack` | Combines real LocalAuthentication interaction with isolated mock secure enclave, mock keychain, and tutorial-only private-key security flow |
| `TutorialAutomationContract` | Defines required ready markers, accessibility identifiers, and anchor points |

Concrete type names may differ, but these responsibilities may not collapse into ad hoc page logic.

### 8.3 Low-Intrusion Architecture Direction

This specification prefers a low-intrusion implementation direction:

- production pages remain tutorial-agnostic
- tutorial behavior is introduced through host control, route filtering, side-effect interception, isolated dependency injection, and generic configuration seams
- the tutorial should avoid pervasive `if tutorial mode` branches inside real pages
- tutorial-owned helper surfaces are allowed only where a real page cannot safely or clearly carry the required behavior

### 8.4 State Model Contract

The tutorial state model must include, at minimum:

- tutorial spec version
- launch origin
- active module identifier
- lifecycle state
- current tutorial sandbox session identifier
- per-module progress for the current run
- current guidance payload

### 8.5 Persistence Boundaries

- Only tutorial completion history and any explicitly chosen lightweight progress facts may persist outside the tutorial sandbox.
- Tutorial demo keys, demo contacts, demo settings, and demo messages are ephemeral.
- A tutorial replay starts a fresh sandbox session.
- No real app workspace state is passed into tutorial mode except the minimal routing context needed to return control to the correct app-owned context.

### 8.6 Routing Boundaries

- Tutorial hub, completion surface, leave confirmation, and guidance helpers are tutorial-owned host surfaces.
- Guided task states should prefer real production pages, shown through tutorial filtering and configuration.
- If a production page cannot safely satisfy the tutorial contract, the tutorial may introduce a narrowly scoped auxiliary surface for that gap rather than replacing the entire flow.

### 8.7 Side-Effect Interception Boundaries

- Dangerous side effects must be intercepted at the host or shared infrastructure level whenever possible.
- The preferred solution is to keep the page and replace only the unsafe effect.
- Replacing a whole page is the fallback, not the default.

### 8.8 Modal Ownership

- Tutorial-owned helper modals belong to the tutorial host, not whichever production page requested them.
- System biometric prompts remain system-owned, but the tutorial host must frame them with guidance before and after as needed.
- Tutorial modals and guidance around system prompts must still satisfy the automation and continuity contract.

## 9. Testability And Automation Contract

### 9.1 Required Marker Strategy

Every tutorial surface that matters for flow control must expose a stable ready marker.

Required marker families:

- onboarding pages
- tutorial hub
- tutorial sandbox acknowledgement
- each guided module root
- tutorial-owned helper modals
- tutorial completion surface
- leave confirmation surface

### 9.2 Required Identifier Strategy

The tutorial must provide stable identifiers for:

- primary and secondary CTA on the onboarding tutorial-decision page
- hub start/replay controls
- module launch controls
- tutorial return, close, and finish controls
- each helper modal's primary confirm and cancel actions

### 9.3 Required Anchor Strategy

Tutorial anchors are required for:

- the current primary action target in a guided task state
- helper-modal confirm actions when guidance refers to them
- any persistent return or restore-guidance affordance used by the tutorial layout

### 9.4 Mandatory Regression Journeys

#### iOS / iPadOS

- first-run onboarding tutorial-decision page to tutorial launch
- first-run skip path into the real app
- onboarding CTA one-way handoff: onboarding closes, tutorial appears, onboarding is not restored
- sandbox acknowledgement to first guided task
- full tutorial completion to real app entry
- in-progress leave confirmation and exit behavior
- authentication-sensitive guided flow with real LocalAuthentication prompt where supported
- regular-width guidance rail behavior on iPad

#### macOS

- launch tutorial into the dedicated tutorial workspace
- close tutorial and return to the correct app-owned context
- completion and finish behavior
- guidance rail collapse and explicit restore behavior
- tutorial-owned helper modal continuity
- authentication-sensitive guided flow with the tutorial security simulation stack

### 9.5 Smoke Vs Deeper UI Suites

- Smoke tests cover stable top-level host journeys and major screen availability.
- Authentication-sensitive flows, leave confirmation, and tutorial-specific helper surfaces belong in deeper UI suites with explicit preconditions.
- Auth- and timing-sensitive tutorial flows must not be hidden inside generic smoke coverage.

## 10. Acceptance Scenarios

1. A first-run iPhone user reaches onboarding page 3, sees a tutorial decision page, chooses the tutorial, and experiences a one-way handoff where onboarding closes and the tutorial host appears.
2. A first-run user chooses skip and enters the real app without tutorial completion being recorded.
3. A first-run user leaves the tutorial after the one-way handoff and is not sent back to onboarding.
4. A user generates a sandbox key through the real key-generation flow without touching any real user key data.
5. A user imports a sandbox contact through the real contact flow without touching real contact storage.
6. A user encrypts and decrypts a sandbox message through the real service path without touching real workspace data.
7. A user completes backup through the real backup flow without a real file exporter writing outside the sandbox.
8. A user reaches High Security in the tutorial through the real settings flow while the private-key security path remains isolated from real user assets.
9. A user sees real system biometric interaction where supported, while the tutorial still protects real Keychain and Secure Enclave assets by routing the secured path through isolated tutorial security plumbing.
10. An iPad regular-width user sees guidance adjacent to the real guided task surface.
11. A macOS user experiences the tutorial as a single dedicated workspace in the main window and can restore guidance after collapsing it.
12. No tutorial flow performs a real file import, real file export, share sheet export, clipboard write, photo picker import, URL handoff, or real workspace mutation.

## 11. Deferred / Explicitly Out Of Scope

- Final production copywriting and String Catalog keys
- Pixel-perfect mockups, spacing tokens, and final visual polish details
- Tutorial analytics or telemetry
- Real-world file exchange, QR-photo import, or share-sheet practice inside tutorial mode
- Rollout sequencing, migration plan, or implementation phase breakdown beyond what is needed to preserve the target-state contract
