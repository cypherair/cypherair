# App Data Documentation Review

> Status: Archived review snapshot from 2026-04-20. Kept as historical evidence for one point-in-time review of the App Data proposal stack against the current repository state.
> Archival reason: The historical `APP_DATA_*` proposal docs absorbed the key follow-up fixes; implemented Phase 1-6 facts now live in long-lived current-state documentation.
> Successor docs: [ARCHITECTURE](../ARCHITECTURE.md), [SECURITY](../SECURITY.md), [TDD](../TDD.md), [TESTING](../TESTING.md), [CODE_REVIEW](../CODE_REVIEW.md), and Contacts-specific docs for Phase 8.
> Scope: `APP_DATA_PROTECTION_PLAN.md`, `APP_DATA_PROTECTION_TDD.md`, `APP_DATA_FRAMEWORK_SPEC.md`, `APP_DATA_MIGRATION_GUIDE.md`, and `APP_DATA_VALIDATION.md`, with comparison against archived `archive/APP_DATA_CONTACTS_ALIGNMENT.md`, `ARCHITECTURE.md`, `SECURITY.md`, `TESTING.md`, and current code.
> Current code and active canonical docs outrank this archived file whenever they disagree.

## Executive Summary

This review found one blocking design inconsistency and four follow-up issues in the current App Data document stack.

Verdict summary:

| ID | Severity | Verdict | Short note |
|---|---|---|---|
| AD-1 | P0 | Confirmed | The registry recovery matrix cannot be applied exactly as written because `cleanupOnly` depends on external evidence even though the docs require classification before evidence inspection. |
| AD-2 | P1 | Confirmed | The migration inventory says it is complete, but it does not explicitly account for current private-key-domain persisted state such as Keychain metadata and wrapped key bundles. |
| AD-3 | P1 | Confirmed | The macOS file-protection contract is still too abstract to satisfy the stack's own "no hidden decisions" readiness bar. |
| AD-4 | P2 | Confirmed | The documents acknowledge startup/session migration, but they under-model how much ownership is currently split across UI, config, auth, and startup code. |
| AD-5 | P2 | Confirmed | The validation stack defines review questions and failure paths, but it does not yet map them to concrete test layers or repository-owned validation commands. |

Non-findings from this pass:

- The proposal stack consistently preserves the private-key domain as a separate authority and does not weaken existing Secure Enclave wrapping semantics.
- The proposal stack consistently rejects silent reset to empty state for unreadable protected-domain data.
- archived `APP_DATA_CONTACTS_ALIGNMENT.md` still reads as a temporary bridge document rather than a third permanent architecture source.

## Source Priority

Primary evidence for this pass:

- `docs/APP_DATA_PROTECTION_PLAN.md`
- `docs/APP_DATA_PROTECTION_TDD.md`
- `docs/APP_DATA_FRAMEWORK_SPEC.md`
- `docs/APP_DATA_MIGRATION_GUIDE.md`
- `docs/APP_DATA_VALIDATION.md`
- `docs/archive/APP_DATA_CONTACTS_ALIGNMENT.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/TESTING.md`
- `Sources/Models/AppConfiguration.swift`
- `Sources/App/Common/PrivacyScreenModifier.swift`
- `Sources/App/AppStartupCoordinator.swift`
- `Sources/Security/AuthenticationManager.swift`
- `Sources/Security/KeyBundleStore.swift`
- `Sources/Security/KeyMetadataStore.swift`
- `Sources/Services/ContactRepository.swift`
- `Sources/Services/SelfTestService.swift`

Review rules for this pass:

- App Data proposal docs were treated as a claim set.
- Current code and canonical docs were treated as comparison evidence.
- This review did not modify the proposal docs or implementation.

## Detailed Findings

### AD-1. `cleanupOnly` makes the registry-first recovery algorithm non-deterministic as written

- Severity: P0
- Documents/sections:
  - `docs/APP_DATA_PROTECTION_TDD.md:437-476`
  - `docs/APP_DATA_FRAMEWORK_SPEC.md:101-136`
  - `docs/APP_DATA_VALIDATION.md:53-61`
- Conflict:
  - The TDD says startup recovery must validate the registry row, classify that row, and only then inspect the external evidence allowed by that classified row.
  - The framework spec repeats the same ordering and says classification happens "before it inspects external evidence".
  - The same matrix then defines two separate outcomes for the exact same registry row shape: `0 / absent / none / n/a`, where one path is `resumeSteadyState` and the other is `cleanupOnly` depending on whether orphan shared-resource evidence exists.
- Why this is a real blocker:
  - A recovery implementation cannot choose between those two rows from registry data alone.
  - If it inspects evidence first, it violates the documented registry-first ordering.
  - If it does not inspect evidence first, it cannot uniquely classify the row, which violates the documented "exactly one recovery disposition" rule.
- Risk:
  - Recovery code will be forced to invent undocumented behavior.
  - Different implementers could either over-scan the filesystem before classification or skip orphan cleanup entirely.
  - This ambiguity sits directly in the framework recovery path, which is the highest-risk part of the proposal.
- Recommended correction:
  - Make the matrix row keys depend only on registry-state inputs.
  - Move orphan-evidence handling into a second documented step after a registry-only row-shape classification.
  - Alternatively, redefine `cleanupOnly` so it is a post-classification action under the empty steady-state row rather than a separate row.
  - Update `APP_DATA_VALIDATION.md` so the validation language matches the corrected algorithm.
- Follow-up impact:
  - Requires synchronized edits in the TDD, framework spec, and validation guide.
  - No current code changes are implied by this review finding, but any future implementation would be blocked until this is resolved.

### AD-2. The migration inventory overclaims completeness and does not explicitly account for private-key-domain persisted state

- Severity: P1
- Documents/sections:
  - `docs/APP_DATA_MIGRATION_GUIDE.md:197-246`
  - `docs/APP_DATA_PROTECTION_PLAN.md:180-184`
- Comparison evidence:
  - `docs/ARCHITECTURE.md:317-350`
  - `docs/SECURITY.md:153-180`
  - `Sources/Security/KeyMetadataStore.swift:3-43`
  - `Sources/Security/KeyBundleStore.swift:17-120`
- Conflict:
  - The migration guide says implementation planning must maintain "a complete inventory of currently persisted app-owned state".
  - The actual baseline table only inventories `UserDefaults`, current Contacts files, self-test reports, temp disk surfaces, and future app-data bootstrap artifacts.
  - The repository also persists private-key-domain state in the Keychain, including cold-launch metadata items (`PGPKeyIdentity` JSON) and the three-item wrapped key bundles used by the existing private-key path.
- Why this matters:
  - The proposal repeatedly emphasizes separation between the private-key domain and the new app-data domain.
  - A "complete inventory" that omits existing private-key-domain persisted surfaces makes that boundary look smaller and cleaner than it really is.
  - Reviewers can mistakenly read the current inventory as full current-state coverage instead of a partial "non-private-key-domain" subset.
- Risk:
  - Future migration work can miss startup dependencies that already rely on persisted Keychain metadata.
  - The architecture boundary between "out of scope private-key domain" and "in scope app-data domain" remains implicit instead of documented.
  - The stack's own acceptance test for "all existing persisted app-owned state" is currently impossible to pass literally.
- Recommended correction:
  - Either narrow the inventory claim to "currently persisted app-owned state outside the private-key domain", or
  - Add an explicit excluded-surfaces subsection that lists the private-key-domain persisted surfaces and states why they stay out of scope for the app-data migration inventory.
  - At minimum, call out Keychain metadata items and wrapped private-key bundles as reviewed-but-excluded surfaces.
- Follow-up impact:
  - Primary edit target is `APP_DATA_MIGRATION_GUIDE.md`.
  - `APP_DATA_PROTECTION_PLAN.md` and `APP_DATA_VALIDATION.md` should then use the same narrowed or expanded wording.

### AD-3. The macOS file-protection contract is still too abstract for the stack's own readiness standard

- Severity: P1
- Documents/sections:
  - `docs/APP_DATA_PROTECTION_TDD.md:633-650`
  - `docs/APP_DATA_VALIDATION.md:63-68`
  - `docs/APP_DATA_VALIDATION.md:93-113`
- Conflict:
  - The TDD says the implementation must use "the strongest platform-supported local static protection it can enforce for app-owned files".
  - The validation guide repeats that wording and also says an implementer should be able to proceed "without making hidden architectural decisions".
  - The current contract does not say what concrete macOS mechanism or acceptance evidence satisfies "strongest platform-supported local static protection".
- Why this matters:
  - iOS/iPadOS/visionOS have an explicit `complete` file-protection target.
  - macOS has only a containment-level floor plus a qualitative adjective.
  - That leaves implementers and reviewers to decide the actual security contract during implementation rather than before it.
- Risk:
  - Two reasonable implementations can both claim conformance while enforcing materially different storage guarantees.
  - Review and QA cannot produce a clear pass/fail check for the macOS path.
  - The proposal stack's "decision complete" claim becomes weaker precisely on one of its platform-specific security seams.
- Recommended correction:
  - Keep the current caution against over-claiming iOS-style semantics on macOS.
  - Replace the qualitative wording with a concrete v1 acceptance contract that states:
    - the required storage root,
    - allowed and forbidden fallback locations,
    - any required file-creation attributes or sandbox assumptions,
    - what evidence validation must collect on macOS to prove compliance.
  - Mirror that exact contract into the validation guide so the checklist has a real oracle.
- Follow-up impact:
  - Requires edits in the TDD and validation guide.
  - `TESTING.md` should later absorb the concrete validation steps once the contract is finalized.

### AD-4. The proposal acknowledges startup/session migration, but it still under-models the current ownership split in code

- Severity: P2
- Documents/sections:
  - `docs/APP_DATA_PROTECTION_TDD.md:335-364`
  - `docs/APP_DATA_PROTECTION_TDD.md:416-433`
  - `docs/APP_DATA_PROTECTION_TDD.md:478-512`
  - `docs/APP_DATA_MIGRATION_GUIDE.md:160-193`
- Comparison evidence:
  - `Sources/App/Common/PrivacyScreenModifier.swift:13-142`
  - `Sources/Models/AppConfiguration.swift:79-157`
  - `Sources/App/AppStartupCoordinator.swift:9-35`
  - `Sources/App/AppContainer.swift:58-75`
  - `Sources/Security/AuthenticationManager.swift:87-180`
- Conflict:
  - The proposal correctly says future app-data should have one session owner (`AppSessionOrchestrator`) and one app-data coordinator (`ProtectedDataSessionCoordinator`).
  - It also correctly says startup ordering, locked-state routing, and coordinator wiring are explicit migration surfaces.
  - What it does not yet document is how much of that ownership is currently distributed across the shipping app:
    - `PrivacyScreenModifier` owns background/active re-auth routing,
    - `AppConfiguration` owns in-memory grace-window timestamps and content-clear generation,
    - `AuthenticationManager` owns actual auth evaluation,
    - `AppStartupCoordinator` owns cold-start loading and temp cleanup.
- Why this matters:
  - This is the real migration surface that future implementers have to unwind.
  - Without a current-state owner map, the "new files and narrow integration seams" language can still be read too optimistically.
- Risk:
  - The work can be underestimated as a new service-layer addition.
  - Implementation can miss view-level or scene-level ownership transfers that are required for a real single-owner session model.
  - Reviewers may not know whether a given future diff is legitimately touching app routing code or accidentally overreaching.
- Recommended correction:
  - Add a short current-state migration note or table that maps the existing owners of launch auth, resume auth, grace-window timing, content clearing, and startup loading.
  - Keep it implementation-prep scoped; this does not need to redesign the current app, only to document the handoff points that the future architecture must absorb.
- Follow-up impact:
  - Best home is `APP_DATA_MIGRATION_GUIDE.md`, with light cross-links from the TDD.

### AD-5. The validation stack defines failure paths, but it does not yet map them to concrete repository test layers

- Severity: P2
- Documents/sections:
  - `docs/APP_DATA_VALIDATION.md:77-91`
  - `docs/APP_DATA_VALIDATION.md:93-148`
  - `docs/APP_DATA_PROTECTION_PLAN.md:226-245`
- Comparison evidence:
  - `docs/TESTING.md:7-220`
- Conflict:
  - The validation guide lists the right categories of failure-path checks and says the proposal is only acceptable if an implementer can proceed without hidden decisions.
  - The roadmap says the proposal docs are not yet canonical and that `TESTING.md` will be updated later.
  - The current testing guide has no app-data-specific layer, no app-data-specific command set, and no mapping from the validation matrix to local/macOS/device/manual execution paths.
- Why this matters:
  - The current stack is strong on what must be true, but still weak on how those truths would be validated inside this repository.
  - That makes the current "implementation-ready" posture too strong for the testing dimension.
- Risk:
  - Important failure paths remain conceptually specified but not operationally assigned.
  - Future implementation work can ship with ad hoc tests because the repository has no pre-agreed layer ownership for these cases.
  - Reviewers may disagree about which failures must be unit-tested, device-tested, or validated only in manual LocalAuthentication runs.
- Recommended correction:
  - Add an implementation-prep appendix that maps each validation bucket to an expected test layer:
    - pure registry/state-machine cases -> Swift unit tests,
    - disk/file-protection behavior -> platform-targeted tests or manual verification,
    - LocalAuthentication right behavior -> device/manual path,
    - startup/relock integration -> macOS-local or targeted UI smoke path where possible.
  - When the proposal becomes active work, mirror the accepted version into `docs/TESTING.md`.
- Follow-up impact:
  - Primary edit target is `APP_DATA_VALIDATION.md`.
  - `TESTING.md` becomes the long-term home after the proposal leaves draft status.

## Appendix A: Document Responsibility Matrix

| Document | Intended role | Observed role in this pass | Review note |
|---|---|---|---|
| `APP_DATA_PROTECTION_PLAN.md` | Roadmap, sequencing, non-goals, canonicalization boundary | Mostly clean and phase-oriented | Strongest statement that proposal docs are not yet canonical for shipped behavior. |
| `APP_DATA_PROTECTION_TDD.md` | Primary architecture and security source for protected app data | Generally consistent | Strong on ownership boundaries; weakened by the recovery-classification ambiguity inherited from the spec. |
| `APP_DATA_FRAMEWORK_SPEC.md` | Concrete execution rules and interface/file breakdown | Mostly consistent | Contains the highest-severity ambiguity because the recovery matrix is not registry-only in practice. |
| `APP_DATA_MIGRATION_GUIDE.md` | Rollout sequencing, startup adoption, persisted-state inventory | Useful but incomplete | Inventory needs scope correction or explicit exclusions; startup migration would benefit from a current-owner map. |
| `APP_DATA_VALIDATION.md` | Review matrix and acceptance criteria | Useful but not fully operationalized | Good checklist language, but not yet tied to concrete test-layer ownership. |
| `archive/APP_DATA_CONTACTS_ALIGNMENT.md` | Temporary bridge over stale Contacts docs | Still temporary, not yet overgrown | Exit criteria and guardrail are clear enough in the current snapshot. |

## Appendix B: Terminology and State Consistency Matrix

| Concept | Primary definition source | Cross-doc consistency | Note |
|---|---|---|---|
| `ProtectedDataRegistry` | `APP_DATA_PROTECTION_TDD.md:111-120` | Consistent | Registry authority is stable across Plan, TDD, Spec, and Validation. |
| `SharedResourceLifecycleState` | `APP_DATA_PROTECTION_TDD.md:122-136` | Consistent | `absent`, `ready`, `cleanupPending` semantics do not drift. |
| `PendingMutation` | `APP_DATA_PROTECTION_TDD.md:138-152` | Consistent | Single in-flight mutation rule is stable. |
| `frameworkRecoveryNeeded` | `APP_DATA_PROTECTION_TDD.md:181-192` | Partially inconsistent | The state meaning is stable, but the path that leads to `cleanupOnly` vs steady state is not uniquely classifiable as written. |
| `restartRequired` | `APP_DATA_PROTECTION_TDD.md:181-192` | Consistent | Runtime-only, fail-closed meaning is stable across the stack. |
| domain-scoped `recoveryNeeded` | `APP_DATA_PROTECTION_TDD.md:194-202` | Consistent | Cleanly separated from framework-level recovery. |
| `LAPersistedRight` shared gate | `APP_DATA_PROTECTION_TDD.md:257-304` | Consistent | Stable across Plan, TDD, Validation, and Alignment. |
| `ProtectedSettingsStore` first-domain rule | `APP_DATA_PROTECTION_TDD.md:416-433`, `APP_DATA_MIGRATION_GUIDE.md:265-269` | Consistent | The bootstrap-critical whitelist and no-shadow-copy rule are stable. |
| Contacts as framework consumer | `APP_DATA_PROTECTION_TDD.md:779-792`, archived `APP_DATA_CONTACTS_ALIGNMENT.md` | Consistent | The desired destination remains clear even though the bridge document is now archived. |

## Appendix C: Persisted-State Inventory Validation Table

| Surface | Current evidence | Covered by migration baseline? | Review note |
|---|---|---|---|
| `authMode`, `gracePeriod`, `encryptToSelf`, `clipboardNotice`, `requireAuthOnLaunch`, `hasCompletedOnboarding`, `guidedTutorialCompletedVersion`, `colorTheme` | `Sources/Models/AppConfiguration.swift:19-97` | Yes | Baseline table matches the shipping preference set. |
| Private-key recovery flags in `UserDefaults` | `Sources/Security/AuthenticationManager.swift:236-238`, `Sources/Security/AuthenticationManager.swift:327-332` | Yes | `rewrap*` and `modifyExpiry*` flags are covered. |
| Contacts files in `Documents/contacts/` | `Sources/Services/ContactRepository.swift:36-87` | Yes | Current plaintext Contacts storage is represented. |
| Self-test reports in `Documents/self-test/` | `Sources/Services/SelfTestService.swift:325-363` | Yes | Explicitly represented. |
| `tmp/decrypted/` and `tmp/streaming/` | `Sources/App/AppStartupCoordinator.swift:45-56` | Yes | Explicitly represented. |
| Keychain metadata items (`PGPKeyIdentity` JSON) | `Sources/Security/KeyMetadataStore.swift:3-43`, `docs/ARCHITECTURE.md:346-350` | No | Missing unless the doc is intentionally narrowed away from private-key-domain surfaces. |
| Permanent/pending wrapped private-key bundles | `Sources/Security/KeyBundleStore.swift:17-120`, `docs/SECURITY.md:153-180` | No | Also missing unless explicitly treated as reviewed-but-excluded private-key-domain state. |

## Appendix D: Document vs Current-Code Gap List

| Area | Future document position | Current code reality | Review note |
|---|---|---|---|
| Session ownership | One `AppSessionOrchestrator` owns grace-window policy and launch/resume sequencing | `PrivacyScreenModifier` drives active/background re-auth flow; `AppConfiguration` carries grace timestamps and content clear generation | Future migration is correctly anticipated, but the current owner split should be documented more explicitly. |
| App-data unlock gate | `ProtectedDataSessionCoordinator` authorizes one shared `LAPersistedRight` | Current shipping app uses `AuthenticationManager.evaluate(...)` for app privacy re-auth, not a LocalAuthentication right-backed app-data session | This is an expected future-state gap, not a contradiction. |
| Startup loading | Pre-auth bootstrap then post-auth domain unlock | `AppStartupCoordinator` currently loads keys and contacts on cold start before any app-data layer exists | The proposal correctly calls out startup as a migration surface. |
| Contacts architecture | Future Contacts domain must consume shared framework | Current Contacts remain plaintext files under `Documents/contacts/` | This is explicitly documented as out of scope for the first protected-domain round. |
| Testing ownership | Validation matrix should eventually govern implementation review | `docs/TESTING.md` has no app-data-specific layer yet | The proposal is ahead of the repo's concrete validation workflow. |

## Overall Conclusion

The App Data proposal stack is directionally strong: it preserves private-key-domain separation, treats registry authority and recovery semantics seriously, and avoids silent reset semantics. It is not yet fully implementation-ready, though, because one recovery rule is internally inconsistent and several migration/validation edges still rely on implied decisions.

The highest-priority next step is to fix the recovery classification algorithm so it is truly registry-first and single-valued. After that, the most useful cleanup is to tighten the migration inventory scope, make the macOS file-protection contract concrete, and document the current startup/session owner split that the future architecture will need to absorb.
