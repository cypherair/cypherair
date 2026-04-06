# Tutorial Rebuild Specification

> Purpose: Define the ideal end-state guided tutorial product for CypherAir across iPhone, iPad, and macOS.
> Audience: Human developers, designers, product owners, and AI coding tools.
> Companion documents: [TUTORIAL_MODE_ISSUES](TUTORIAL_MODE_ISSUES.md) · [PRD](PRD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [LIQUID_GLASS](LIQUID_GLASS.md) · [TESTING](TESTING.md)
> Spec posture: This document is an ideal-state rebuild spec. It is written from the finished tutorial product backward, not from the current implementation forward. The tutorial may diverge materially from the current tutorial architecture wherever that is required to satisfy CypherAir's offline, privacy, security, accessibility, and cross-platform product goals.

## 1. Product Intent

### 1.1 Why The Tutorial Exists

The guided tutorial exists to help a first-time CypherAir user reach confidence before they touch their real workspace. It must teach the minimum mental model required to understand what the app does, why it is safe, and how the core encryption workflow fits together.

The tutorial is not a marketing carousel and not a full manual. It is a contained learning experience that gives the user one clear outcome: "I understand what this app does, I trust the boundaries, and I know what to do next in the real app."

### 1.2 Product Goals

- Teach the core CypherAir workflow without requiring prior PGP knowledge.
- Preserve trust by making only promises the tutorial can truly keep.
- Keep the first-run learning path short, focused, and deterministic.
- Show the user how tutorial actions map to real app concepts without exposing the full real app shell as an uncontrolled playground.
- Support a second layer of optional advanced learning for backup and high-security concepts.
- Produce one coherent product across iPhone, iPad, and macOS, with platform-specific adaptations rather than different tutorial products.

### 1.3 Success Criteria

- A new user can finish the core tutorial in approximately 3 to 5 minutes on iPhone and iPad, and in approximately 3 to 6 minutes on macOS, without importing or exporting any real files.
- After the core tutorial, the user understands these five concepts:
  - the tutorial is isolated from the real workspace
  - keys represent identities
  - contacts provide recipient public keys
  - encrypting and decrypting are separate steps
  - the real app is where they create their own real key afterward
- The user can skip the tutorial at first run without broken state, and can replay the tutorial later from Settings.
- The tutorial never performs a real file import, file export, photo picker import, share sheet export, URL handoff, or real workspace mutation.

### 1.4 Non-Goals

- The tutorial is not required to mirror the full production app shell.
- The tutorial is not required to teach every feature during first run.
- The tutorial is not the place to exercise real-world file exchange, QR exchange, or system-level exports.
- The tutorial is not a substitute for written documentation or the app's help content.
- The tutorial does not need final marketing copy or final localization strings in this specification.

### 1.5 Primary Users

| User | Need |
|------|------|
| First-time non-technical user | Understand the app safely and reach first confidence without touching real data |
| Returning user who skipped first run | Take the core tutorial later from Settings |
| User who wants deeper knowledge | Practice advanced tasks such as backup and High Security mode in a safe environment |

## 2. Tutorial Product Model

### 2.1 Topology

The tutorial product has two layers:

| Layer | Role | Mandatory | Availability |
|------|------|-----------|-------------|
| Core Tutorial | First-run learning path that teaches the minimum workflow to first real success | Offered at first run, but skippable | First run and Settings replay |
| Advanced Modules | Optional, self-contained modules that teach higher-risk or less essential behaviors | No | Available after core completion |

The core tutorial is a single contiguous session. Advanced modules are separate mini-sessions, each with their own seeded sandbox and completion state.

### 2.2 Core Tutorial Sequence

The core tutorial contains five modules in this fixed order:

1. Understand the tutorial sandbox
2. Create a demo identity
3. Add a demo contact
4. Encrypt a demo message
5. Decrypt and verify the demo message

The core tutorial ends immediately after the user completes module 5 and explicitly finishes the tutorial from the completion screen.

### 2.3 Advanced Modules

Advanced modules are available only after core completion. They are not part of the first-run completion requirement.

The initial advanced module set is:

| Module | Purpose | Dependency |
|--------|---------|------------|
| Back Up a Key | Teach passphrase-protected backup and backup status concepts without performing a real file export | Core complete |
| Enable High Security | Teach biometric-only mode, confirmation semantics, and operational consequences in a tutorial-safe environment | Back Up a Key complete |

Advanced modules are individually replayable and individually seed their own demo state. They do not inherit mutable sandbox artifacts from the last core run.

### 2.4 Entry Points

| Entry Point | Behavior |
|------------|----------|
| First-run onboarding | Offers the core tutorial as the primary learning path and allows skip |
| Settings replay | Opens the tutorial hub; if core is incomplete, enters core tutorial, otherwise offers replay plus advanced modules |
| Completion screen | Offers entry to advanced modules after core completion, but does not require them |

### 2.5 Replay Rules

- The first-run entry point always launches the core tutorial, never an advanced module.
- Replay from Settings opens the tutorial hub.
- If the current tutorial spec version has never been finished, the hub prioritizes the core tutorial.
- Once the current spec version has been finished, the hub shows:
  - Replay Core Tutorial
  - Advanced Modules
  - Completed-module badges for the current tutorial spec version

### 2.6 Skip Rules

- First-run onboarding must always offer a clear skip path.
- Skipping the tutorial does not mark the tutorial as completed.
- Skipping does not create tutorial sandbox data.
- If the user exits an in-progress first-run tutorial, they return to the onboarding tutorial-choice page, not directly into the app unless they explicitly choose the skip path there.

### 2.7 Completion Semantics

The product distinguishes these states:

| State | Meaning |
|-------|---------|
| Not Started | No tutorial session has begun for the current spec version |
| Core In Progress | A core tutorial sandbox session exists and the user is inside it |
| Core Steps Completed | All core modules are complete, but the user has not yet finished from the completion screen |
| Core Finished | The user explicitly finished the completion screen; only here is the tutorial version recorded as completed |
| Module In Progress | An advanced module sandbox session is active |
| Module Completed | The user finished the advanced module's completion state |

Rules:

- Core steps completing does not write the global tutorial completion version.
- Global completion version is written only when the user finishes the core completion screen.
- Advanced module completion is tracked separately from core completion.
- Resetting a sandbox session clears tutorial-local artifacts only; it does not erase completion history for the current spec version.

### 2.8 Mapping Tutorial Learning To Real App Use

The tutorial must continuously explain where each lesson maps in the real app without forcing the user through the full production shell.

Rules:

- Each module shows the corresponding real app area label, for example `Keys`, `Contacts`, `Encrypt`, or `Decrypt`.
- Each module completion state includes a short "In the real app..." mapping note.
- Core completion ends with one explicit real-world next step: create a real key in the real app.
- Advanced module completion states explain what will still be different in the real app, especially where real authentication or real file export will occur.

## 3. Cross-Platform Host Model

### 3.1 Shared Host Principles

- The tutorial is one product across platforms.
- The tutorial is not an unrestricted mirror of the production app shell.
- The tutorial host owns navigation, exit semantics, safety policy, and guidance surfaces.
- The first-run host and replay host may enter from different app contexts, but they must resolve to the same tutorial information architecture and state model.

### 3.2 iPhone Host

- The tutorial always launches as a dedicated full-screen experience.
- First run:
  - onboarding page 3 becomes the tutorial decision page
  - selecting tutorial dismisses onboarding and then launches the tutorial host as a new full-screen experience
  - closing an in-progress first-run tutorial returns to the onboarding decision page
- Replay:
  - launched from Settings as a dedicated full-screen experience
  - closing returns to the app context that launched it

### 3.3 iPad Host

- The tutorial uses the same dedicated full-screen host model as iPhone.
- Layout behavior changes with size class, but the host model does not.
- The tutorial must not rely on nested sheet-to-full-screen transitions inside onboarding.

### 3.4 macOS Host

- The tutorial always runs as a dedicated tutorial workspace in the main application window.
- The tutorial is never hosted as a Settings sheet and never hosted as an onboarding-nested sheet.
- The Settings scene and onboarding flow may request tutorial launch, but they do so by handing control to the main-window tutorial workspace.
- Closing the tutorial returns to the prior application context that requested it:
  - first run returns to the tutorial-choice stage
  - in-app replay returns to the prior app surface

### 3.5 Exit Semantics

| Action | Meaning |
|--------|---------|
| Return | Go back from the current module surface to the tutorial hub inside the same tutorial session |
| Close | Leave the tutorial entirely; if progress is in flight, show a leave-confirmation surface |
| Finish | Commit completion for the relevant tutorial layer and exit the tutorial host |

Rules:

- `Return` never exits the tutorial host.
- `Close` from an active module requires confirmation if the session is in progress.
- `Finish` is only available from a completion surface.
- First-run `Finish` enters the real app, not onboarding.

### 3.6 Leave Confirmation

If the user attempts to close an in-progress core tutorial or advanced module, the tutorial must present a tutorial-owned leave confirmation surface with these actions:

- Continue Tutorial
- Leave Tutorial

This confirmation inherits the tutorial guidance contract and participates in testability contracts like any other tutorial modal.

## 4. Tutorial Safety Contract

### 4.1 Tutorial Promise

The tutorial may make exactly this class of promise:

"This tutorial uses isolated demo data in a tutorial workspace. It does not read or write your real keys, contacts, settings, files, exports, or other real workspace content."

The UI must not use stronger wording unless the tutorial shell contract below still makes it literally true.

### 4.2 Shell-Level Safety Principle

Tutorial safety is enforced at the tutorial-shell level, not only at the dependency-container level.

That means the tutorial host must explicitly choose what can appear inside tutorial mode. It is not sufficient to inject sandbox services into unrestricted production views and assume the resulting experience is safe.

### 4.3 Capability Whitelist

The tutorial host may allow only these capability classes:

- tutorial-local identity, contact, message, and module state
- tutorial-local settings needed to demonstrate tutorial-only behavior
- tutorial-owned navigation between tutorial hub, tutorial modules, and tutorial completion surfaces
- tutorial-local previews and educational representations of artifacts
- tutorial-owned modal confirmations and explanatory surfaces

Everything else is disallowed unless explicitly reintroduced as a tutorial-safe replacement.

### 4.4 Disallowed Real-World Side Effects

The tutorial must not expose any of the following real-world surfaces:

- system file importer
- system file exporter
- photo picker
- share sheet
- clipboard write actions
- URL handoff or app-open flows
- real app icon changes
- real onboarding management actions
- real theme or settings changes outside the tutorial-safe settings subset
- real biometric or passcode requirement surfaces for demo-only steps

### 4.5 Safe Replacements

When the tutorial needs to teach a concept that normally uses a real-world side effect, it must use a tutorial-safe replacement:

| Real-world feature | Tutorial replacement |
|-------------------|---------------------|
| Import key from file or photo | Pre-seeded or inline tutorial sample content |
| Export backup file | Tutorial-local preview card with explanation of the real save step |
| Copy/share ciphertext | Read-only preview plus note describing the real app action |
| Real auth prompt | Tutorial-owned confirmation or explainer step that states what the real app would do |
| App-wide settings mutation | Tutorial-local simulated state when the concept must be taught |

### 4.6 Scope Of Sandbox Guarantees

- Core tutorial and advanced modules use the same safety contract.
- Each advanced module gets its own seeded tutorial session and inherits the same no-real-side-effects rules.
- A module may simulate a real operation, but it must clearly label that simulation when the real app would behave differently.

## 5. Guidance Model

### 5.1 Guidance Principles

- Guidance must stay close to the current task.
- Guidance must survive context changes, especially tutorial-owned modals.
- Guidance must explain one next action at a time.
- Guidance must indicate where the lesson maps to the real app.
- Guidance must be recoverable if an auxiliary guidance surface is collapsed.

### 5.2 Tutorial Information Architecture

The tutorial has three top-level surface types:

| Surface | Role |
|---------|------|
| Tutorial Hub | Overview, progress, module list, start/replay controls |
| Tutorial Workspace | The active task surface for a core module or advanced module |
| Completion Surface | End-of-core or end-of-module summary with next actions |

The hub is not a large marketing hero page. It is a structured learning dashboard with:

- tutorial promise summary
- estimated time
- progress state
- primary action
- visible core module map
- advanced modules section after core completion

### 5.3 Core Navigation Rules

- Core modules unlock sequentially.
- The user may return to the hub between modules.
- The tutorial host does not expose unrestricted tab or sidebar navigation during the core flow.
- The workspace may display a location label that corresponds to the real app area being taught, but the user is not given the full production shell as free navigation.

### 5.4 Advanced Module Navigation Rules

- Advanced modules are individually launchable from the hub after core completion.
- Each advanced module is self-contained.
- A module may declare a prerequisite badge state, such as `Requires Back Up a Key`.

### 5.5 iPhone Guidance Placement

- Use a single-column task layout.
- Show a persistent task context card at the top of the workspace.
- The top card includes:
  - module title
  - one-sentence task goal
  - real-app location label
  - return action
- Use spotlight highlighting when there is exactly one current target action.
- Use a bottom completion prompt only after the current module step is complete.

### 5.6 iPad Regular-Width Guidance Placement

- Use a two-column task layout: primary content area plus dedicated guidance rail.
- The guidance rail is part of the tutorial layout, not a system inspector.
- Primary guidance does not appear as a stretched full-width banner above the content.
- Spotlight highlighting is still allowed, but the guidance rail remains the main explanatory surface.

### 5.7 macOS Guidance Placement

- Use a three-part tutorial workspace:
  - module navigator
  - primary content area
  - dedicated guidance rail
- The guidance rail is tutorial-owned and may be collapsible, but it is not the platform inspector.
- If the guidance rail is collapsed, the primary content area must show a persistent `Show Guidance` affordance at the top.

### 5.8 Modal Continuity Contract

Tutorial-owned modals must preserve the minimum task context. Every tutorial-owned modal must show:

- current module title
- why this modal exists
- what action the user is expected to take
- what happens next after the modal resolves

If the modal contains one primary confirm action, the modal may anchor or highlight that action.

### 5.9 Spotlight And Anchor Rules

- Tutorial anchors are required for any guidance state that refers to a specific actionable control.
- The tutorial may highlight at most one primary target at a time.
- If a target is inside a modal, the modal owns the active anchor.
- If no stable target exists, the tutorial falls back to context guidance without spotlight.

## 6. Experience Contract By Tutorial Segment

### 6.1 Core Tutorial Overview

The core tutorial is the minimum path to first confidence. It teaches the product model before the user touches the real app.

| Module | Teaches | Completion Criteria |
|--------|---------|---------------------|
| Sandbox | What tutorial mode is and is not | User acknowledges the sandbox and enters the tutorial workspace |
| Create Demo Identity | A key is your encryption identity | Demo identity is created in tutorial-local state |
| Add Demo Contact | Contacts hold recipient public keys | Demo contact is added in tutorial-local state |
| Encrypt Demo Message | Encryption produces protected output for a chosen contact | Demo message is encrypted in tutorial-local state |
| Decrypt And Verify | Decryption reveals content and signature trust | Demo message is decrypted and signature result is shown |

### 6.2 Module 1: Understand The Sandbox

- Entry state:
  - visible tutorial promise
  - estimated time
  - explanation that the tutorial is isolated from the real workspace
- Required context:
  - no real files, exports, settings, or workspace mutations
  - this is a guided environment, not the real app shell
- CTA hierarchy:
  - primary: Start Tutorial
  - secondary: Leave / return, based on launch origin
- Completion:
  - explicit acknowledgement

### 6.3 Module 2: Create A Demo Identity

- Real-app mapping: `Keys`
- Teaching goal:
  - keys represent the user's identity
  - the tutorial uses a demo identity so the user can learn safely
- Interaction contract:
  - the form is simplified to the fields required for the learning goal
  - non-essential production options may be fixed, hidden, or explained rather than made interactive
- Profile rule:
  - the core tutorial uses one fixed demo profile to keep the first-run flow simple
  - profile comparison is explained only briefly here
  - the real app still asks the user to choose their real profile later
- Completion:
  - the tutorial shows a concise success state, then advances to the next module

### 6.4 Module 3: Add A Demo Contact

- Real-app mapping: `Contacts`
- Teaching goal:
  - contacts provide public keys used for encryption
- Interaction contract:
  - the tutorial uses tutorial-provided sample content only
  - the user never opens a real file picker or photo picker here
  - the step may use prefilled sample key content or a tutorial-owned sample import card
- Completion:
  - the demo contact is visible and confirmed as available for encryption

### 6.5 Module 4: Encrypt A Demo Message

- Real-app mapping: `Encrypt`
- Teaching goal:
  - choose a recipient
  - write a message
  - produce protected output
- Interaction contract:
  - text mode only in core tutorial
  - non-essential controls may be fixed or hidden
  - the surface focuses on recipient selection, message entry, and the encrypt action
- Output contract:
  - the encrypted result is shown as tutorial-local output only
  - no copy, save, share, or export actions are available
- Completion:
  - the encrypted demo message becomes the input to the decrypt module

### 6.6 Module 5: Decrypt And Verify

- Real-app mapping: `Decrypt`
- Teaching goal:
  - a message is first identified as intended for the user's key
  - decryption reveals the message
  - signature verification communicates trust
- Interaction contract:
  - the module may visually show the two-phase model, but it is one tutorial module, not two separate hub steps
  - the module must clearly state when the real app would normally ask for device authentication
  - tutorial mode uses a tutorial-owned explainer or simulated auth confirm instead of a real biometric prompt
- Completion:
  - plaintext is displayed
  - signature result is explained
  - the user reaches the core completion surface

### 6.7 Core Completion Surface

The core completion surface must include:

- confirmation that the core tutorial is complete
- reminder that the real workspace is still untouched
- explicit next step in the real app: create a real key
- optional next step: explore advanced modules

CTA hierarchy:

- first-run primary: Start Using CypherAir
- first-run secondary: Explore Advanced Skills
- replay primary: Done
- replay secondary: Explore Advanced Skills

The global tutorial completion version is written only when the user finishes from this surface.

### 6.8 Advanced Module: Back Up A Key

- Real-app mapping: `Keys`
- Teaching goal:
  - a private key backup is protected with a passphrase
  - backup status matters before stronger security decisions
- Interaction contract:
  - the module starts with a seeded demo key
  - the user enters a backup passphrase
  - the result is shown as a tutorial-local preview or status card
  - no real file exporter appears
- Completion:
  - the module marks tutorial-local backup as complete
  - the module completion surface explains that the real app would save a file outside tutorial mode

### 6.9 Advanced Module: Enable High Security

- Real-app mapping: `Settings`
- Teaching goal:
  - High Security removes passcode fallback
  - backup matters before enabling it
  - confirmation is a meaningful decision, not a decorative warning
- Dependency:
  - the module is unavailable until `Back Up a Key` is completed
- Interaction contract:
  - the module uses tutorial-local settings state
  - the confirmation step is a tutorial-owned modal with full modal context
  - the module explains that the real app later requires real biometric authentication for this change
- Completion:
  - the tutorial-local auth mode changes to High Security
  - the completion surface explains the operational consequence in the real app

## 7. Accessibility And Visual System

### 7.1 Accessibility Rules

- All tutorial text uses system text styles.
- All interactive elements meet 44x44 minimum target size.
- VoiceOver labels are required for all CTAs, step indicators, status badges, and tutorial-owned controls.
- Security-sensitive content remains fully readable and never depends on color alone.

### 7.2 Dynamic Type Rules

The tutorial home and workspace layouts must have explicit accessibility-size behaviors.

Rules:

- On compact iPhone at accessibility Dynamic Type sizes, the first screenful of the hub must show:
  - tutorial identity and promise summary
  - the primary start/replay CTA
  - at least the beginning of the visible module list
- The hub must not rely on a large decorative hero that pushes the learning map below the fold.
- Task guidance cards must wrap naturally and remain readable without truncating the task goal.

### 7.3 Regular-Width Rules

- On iPad regular width, guidance is shown in a dedicated rail adjacent to the content, not as a weak full-width strip.
- On macOS, the task content area must remain the priority. Guidance and navigation chrome may not compress the task surface below a usable form width.
- The task content area must retain a comfortable reading and form-entry width with guidance visible.

### 7.4 macOS Width Budget

The macOS tutorial workspace must guarantee a usable detail area with both navigation and guidance visible.

Contract:

- the content area is the primary width budget
- navigation and guidance rails must be sized around the content area, not vice versa
- the default macOS tutorial window must open wide enough to show all primary tutorial chrome without truncating a form-focused module

### 7.5 Liquid Glass Rules

Tutorial visuals follow `docs/LIQUID_GLASS.md`.

Rules:

- Use standard SwiftUI navigation and control chrome where possible.
- Apply Liquid Glass to navigation and control layers only.
- Do not apply decorative glass to message content, fingerprints, passphrase education, or other security-sensitive reading surfaces.
- Tutorial guidance cards may use elevated control-layer styling, but content panels remain readable first.

## 8. Technical Architecture Expectations

### 8.1 Architecture Posture

The rebuilt tutorial is a tutorial-specific product surface that may embed adapted production views where safe, but it is not a general-purpose mirror shell.

### 8.2 Required Contract-Level Interfaces

The implementation must introduce clear contract-level boundaries equivalent to the following responsibilities:

| Interface | Responsibility |
|-----------|----------------|
| TutorialCapabilityPolicy | Defines what operations, routes, and side effects are allowed in tutorial mode |
| TutorialLifecycleModel | Represents core progress, module progress, completion semantics, and spec version state |
| TutorialPresentationHost | Owns onboarding handoff, replay launch, exit semantics, and platform-specific host behavior |
| TutorialGuidanceModel | Provides current task context, target anchor, real-app mapping label, and modal continuity payload |
| TutorialAutomationContract | Defines required ready markers, accessibility identifiers, and tutorial anchor points |

Concrete type names may differ, but the responsibilities may not be merged into ad hoc view logic.

### 8.3 State Model Contract

The tutorial state model must include, at minimum:

- tutorial spec version
- launch origin
- active layer: core vs advanced module
- active module identifier
- lifecycle state
- current tutorial session identifier
- per-module completion history for the current spec version
- current guidance payload

### 8.4 Persistence Boundaries

- Only completion history and tutorial version state persist outside the tutorial sandbox.
- Tutorial demo keys, demo contacts, demo settings, and demo messages are ephemeral.
- Core tutorial and advanced modules use isolated tutorial sessions.
- No real app workspace state is passed into tutorial mode except the minimal routing context needed to return to the correct app origin afterward.

### 8.5 Routing Boundaries

- Tutorial hub, tutorial workspace, tutorial completion, leave confirmation, and tutorial-owned teaching modals are tutorial routes, not borrowed production routes.
- Production task surfaces may be embedded or adapted inside tutorial routes only when:
  - their side effects are constrained by the tutorial capability policy
  - their UI complexity does not undermine the teaching goal
  - their guidance targetability remains stable
- If a production surface cannot satisfy those conditions, the tutorial uses a dedicated tutorial surface instead.

### 8.6 Modal Ownership

- Tutorial-owned confirmation and teaching modals belong to the tutorial host, not to whichever production view happened to request them.
- Modal presentation rules must be consistent across platforms.
- Tutorial modals inherit the guidance, anchor, and automation contracts.

### 8.7 Mirroring Policy

The tutorial may reuse the interaction model of real app screens, but it may not expose the full real app shell merely for visual fidelity.

Rules:

- mirror the task, not the whole shell
- prioritize clarity, trust, and guidance over exact production-shell reproduction
- show real-app location mapping explicitly instead of relying on unrestricted wandering through tabs or sidebars

## 9. Testability And Automation Contract

### 9.1 Required Marker Strategy

Every tutorial surface that matters for flow control must expose a stable ready marker.

Required marker families:

- onboarding pages
- tutorial hub
- tutorial sandbox acknowledgement
- each core module root
- each advanced module root
- each tutorial-owned modal
- core completion surface
- advanced module completion surface
- leave confirmation surface

### 9.2 Required Identifier Strategy

The tutorial must provide stable identifiers for:

- primary and secondary CTA on the onboarding tutorial-choice page
- hub start/replay controls
- module launch controls
- tutorial return, close, and finish controls
- each modal's primary confirm and cancel actions
- advanced module entry buttons

### 9.3 Required Anchor Strategy

Tutorial anchors are required for:

- the current primary action target in a module
- tutorial-owned modal confirm actions when guidance refers to them
- any persistent return or restore-guidance affordance used by the tutorial layout

Unused reserved anchors are not allowed. Every declared anchor must map to a real contractually supported target.

### 9.4 Mandatory Regression Journeys

#### iOS / iPadOS

- first-run onboarding tutorial-choice page to core tutorial start
- first-run skip path into the real app
- sandbox acknowledgement to first core module
- full core tutorial completion to real app entry
- in-progress leave confirmation and return behavior
- advanced module launch from hub
- tutorial-owned auth-related modal continuity
- regular-width guidance rail behavior on iPad

#### macOS

- launch tutorial into the dedicated tutorial workspace
- close tutorial and return to the prior app context
- core completion and finish behavior
- advanced module launch and finish behavior
- guidance rail collapse and explicit restore behavior
- tutorial-owned modal continuity

### 9.5 Smoke Vs Deeper UI Suites

- Smoke tests cover stable top-level host journeys and major screen availability.
- Tutorial-specific modal flows, leave confirmation, and advanced modules belong in deeper UI suites with explicit preconditions.
- Auth- and timing-sensitive tutorial flows must not be hidden inside generic smoke coverage.

## Acceptance Scenarios

1. A first-run iPhone user reaches onboarding page 3, sees a tutorial decision page, chooses the tutorial, and enters a dedicated full-screen tutorial host without a broken transition.
2. A first-run user chooses skip and enters the real app without tutorial completion being recorded.
3. A first-run user exits an in-progress tutorial and returns to the tutorial-choice page after confirming they want to leave.
4. A user completes the core tutorial and only then is the tutorial spec version recorded as finished.
5. A replay user opens the tutorial from Settings and sees a hub that offers core replay plus advanced modules after core completion.
6. A user completes `Back Up a Key` without encountering a real file exporter and still understands that the real app would save a file.
7. A user opens `Enable High Security` and sees a tutorial-owned confirmation modal that preserves task context and explains the real-world consequence.
8. An iPad regular-width user sees guidance adjacent to the task surface, not as a weak full-width banner.
9. A macOS user experiences the tutorial as a single dedicated workspace in the main window and can restore guidance after collapsing it.
10. A user at accessibility Dynamic Type on iPhone can still discover the start CTA and the module map without the hub collapsing into an oversized hero.
11. No tutorial flow performs a real file import, real file export, share sheet export, clipboard write, photo picker import, or real workspace mutation.
12. Every regression-critical tutorial surface exposes stable ready markers, identifiers, and anchors required for UI automation.

## Deferred / Explicitly Out Of Scope

- Final production copywriting and String Catalog keys
- Pixel-perfect mockups, spacing tokens, and final visual polish details
- Tutorial analytics or telemetry
- New feature modules beyond the initial advanced module set
- Real-world file, QR-photo, or share-sheet practice inside tutorial mode
- Rollout sequencing, migration plan, or implementation phase breakdown beyond what is needed to preserve the end-state contract

