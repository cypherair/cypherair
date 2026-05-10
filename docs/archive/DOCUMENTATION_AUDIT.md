# Documentation Audit

> Status: Archived review snapshot from 2026-04-17. Kept as historical evidence for the repository-wide documentation audit that drove the April 18, 2026 governance and sync pass.
> Archival reason: The corrective work identified by this audit has been absorbed into the active documentation set and governance rules.
> Successor docs: [DOCUMENTATION_GOVERNANCE](../DOCUMENTATION_GOVERNANCE.md) and the active canonical docs updated by this pass.
> Current code and active canonical docs outrank this archived file whenever they disagree.

> Date: 2026-04-17
> Scope: `README.md`, `CLAUDE.md`, `AGENTS.md`, all `docs/*.md`, and all `docs/archive/*.md`
> Excludes: `.claude/` tooling docs
> Phase: Inspection and recording only. No code changes, no content edits to existing docs, and no archive moves were performed in this pass.

## Executive Summary

CypherAir's documentation stack is active and recently maintained, but it is not currently governed as one coherent system. The repo has strong, current source-of-truth documents in a few areas, especially testing and security, while other high-impact documents still mix shipped behavior, planning material, review snapshots, and historical context in ways that can mislead implementation or review work.

- Documents reviewed: `33`
- Doc-class mix:
  - Entry docs: `3`
  - Canonical current-state docs: `10`
  - Active design/roadmap docs: `7`
  - Active audit/review snapshots: `2`
  - Archived docs: `11`
- Recommended dispositions:
  - `keep as canonical`: `6`
  - `update`: `16`
  - `archive`: `1`
  - `leave archived`: `10`
- Finding counts:
  - `High`: `3`
  - `Medium`: `4`
  - `Low`: `3`
- Governance hygiene signals:
  - Only `12/33` scoped docs currently expose a full `Status + Purpose + Audience` front-matter pattern.
  - Local markdown link audit found `1` broken-link document with `3` broken links: `docs/archive/POC.md`.

Highest-risk findings:

1. Canonical docs disagree with the shipped Rust/UniFFI/Xcode integration model. `docs/TDD.md`, `docs/PRD.md`, `README.md`, `CLAUDE.md`, and `AGENTS.md` still present an XCFramework-first story, while `docs/TESTING.md` and `CypherAir.xcodeproj/project.pbxproj` show that the current Xcode link step uses direct release static archives plus `bindings/module.modulemap`.
2. The active Rust/FFI current-state stack is materially stale after the 2026-04-16 and 2026-04-17 rollout. `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`, `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md`, and `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md` still describe `CertificateSignatureService`, selective revocation, and detailed result ownership as missing or pending even though those service surfaces and tests already exist.
3. `docs/ARCHITECTURE.md` is stale on a security-sensitive decrypt boundary and on storage/build topology. It still shows Swift doing recipient matching after Rust parsing, still lists a nonexistent `uniffi.toml`, and still documents outdated storage defaults and temp-path layout.

Docs with the strongest sampled alignment to current repository truth:

- `docs/TESTING.md`
- `docs/SECURITY.md`
- `docs/CODE_REVIEW.md`
- `docs/CONVENTIONS.md`
- `docs/LIQUID_GLASS.md`

## Methodology and Truth-Source Rules

- Truth precedence for this audit was:
  1. production code, generated bindings, tests, Xcode/test-plan/workflow config, and git history
  2. canonical prose docs
  3. active planning docs
  4. audit/review snapshots
  5. archived material
- Existing audit/review documents were treated as claim lists, not as evidence.
- Every scoped document was classified before judgment:
  - `Canonical current-state`
  - `Active design or roadmap`
  - `Audit or review snapshot`
  - `Archive`
- Freshness was judged by both content and chronology. A recent doc update was not treated as sufficient if the related code/config surface changed again afterward.
- The `Last Related Code Update` field below is a freshness signal based on the nearest obvious code/config surface for that document. It is not standalone evidence; the evidence remains the cited repository files.
- Cross-document consistency was checked against a fixed fact set:
  - platform targets
  - build/link pipeline
  - Rust/UniFFI integration model
  - test-plan layout and workflow usage
  - current service ownership
  - tutorial state
  - authentication modes
  - delivered vs planned features
  - storage locations/defaults
  - archive/supersession chains
- Governance hygiene checks covered:
  - local markdown links
  - metadata presence
  - status/version/supersedes chains
  - naming conventions
  - archive placement
  - whether future/planning docs are easy to distinguish from canonical current-state docs

## Full Inventory Matrix

### Entry Docs

| Path | Doc Class | Lifecycle Status | Audience | Claim Type | Expected Freshness Rule | Primary Truth Sources | Last Doc Update | Last Related Code Update | Key Findings | Recommended Disposition |
|---|---|---|---|---|---|---|---|---|---|---|
| `README.md` | Entry overview | Canonical current-state | Public + developers | Product summary, build quickstart, doc index | Must match canonical docs and shipped build/test topology | `docs/PRD.md`, `docs/TESTING.md`, `CypherAir.xcodeproj/project.pbxproj`, `Sources/`, `Tests/` | 2026-04-10 | 2026-04-17 (static-archive link fix + Rust/FFI rollout) | XCFramework-first wording and simplified architecture tree lag the current direct static-archive link model and newer module/service split. | `update` |
| `CLAUDE.md` | Agent workflow guide | Canonical current-state | Developers + AI tools | Repo rules, build/test workflow, architecture summary | Must match active workflow and canonical docs | `docs/TESTING.md`, `CypherAir.xcodeproj/project.pbxproj`, `Sources/`, `Tests/`, `.github/workflows/` | 2026-04-10 | 2026-04-17 (static-archive link fix + current test-plan layout) | Omits `CypherAir-MacUITests.xctestplan` and still frames full sync around XCFramework output rather than current direct-archive linkage. | `update` |
| `AGENTS.md` | Agent workflow guide | Canonical current-state | Developers + AI tools | Repo rules, build/test workflow, sensitive-boundary guidance | Must match active workflow and canonical docs | `docs/TESTING.md`, `CypherAir.xcodeproj/project.pbxproj`, `Sources/`, `Tests/` | 2026-04-10 | 2026-04-17 (static-archive link fix + current test-plan layout) | Lower-drift than `CLAUDE.md`, but still uses the same XCFramework-first shorthand and does not surface the Mac UI plan as part of the current test-plan set. | `update` |

### Canonical Current-State Docs

| Path | Doc Class | Lifecycle Status | Audience | Claim Type | Expected Freshness Rule | Primary Truth Sources | Last Doc Update | Last Related Code Update | Key Findings | Recommended Disposition |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/ARCHITECTURE.md` | Architecture spec | Canonical current-state | Developers + AI tools | Current module breakdown, data flow, storage model | Must match shipped services, storage, and FFI integration | `Sources/`, `pgp-mobile/src/`, `Tests/`, `CypherAir.xcodeproj/project.pbxproj` | 2026-04-12 | 2026-04-17 (service rollout + static-archive link fix) | Stale on phase-1 decrypt matching ownership, Rust crate inventory, storage defaults/paths, and `DiskSpaceChecker` scope. | `update` |
| `docs/CHANGELOG.md` | Revision log | Canonical current-state | Developers + product authors | Documentation revision history | Must accurately reflect the documentation revision chain | `docs/PRD.md`, `git log -- docs` | 2026-03-30 | 2026-04-09 (last PRD/TDD-facing doc revision recorded here) | The log itself is coherent; the drift is that `PRD.md` and `TDD.md` headers were not advanced to the latest logged revision label. | `keep as canonical` |
| `docs/CODE_REVIEW.md` | Review checklist | Canonical current-state | Human reviewers + AI tools | Current review criteria | Must match active review-sensitive surfaces and validation expectations | `docs/SECURITY.md`, `docs/TESTING.md`, `Sources/`, `pgp-mobile/src/` | 2026-04-10 | 2026-04-17 (security-sensitive service/test surfaces) | Sampled checklist items align well with the current security, test-plan, and screen-model practices. | `keep as canonical` |
| `docs/CONVENTIONS.md` | Coding guide | Canonical current-state | Developers + AI tools | Current coding and SwiftUI patterns | Must match active code patterns | `Sources/App/`, `Sources/Services/`, `Tests/ServiceTests/` | 2026-04-12 | 2026-04-11 (screen-model rollout across workflow-heavy screens) | Sampled rules align with current `@Observable` screen-model usage and view ownership patterns. | `keep as canonical` |
| `docs/LIQUID_GLASS.md` | UI design guide | Canonical current-state | Developers + AI tools | Current iOS 26 design rules | Must stay aligned with platform baseline and current exceptions | `Sources/App/Common/PrivacyScreenModifier.swift`, `Sources/App/ContentView.swift`, `Sources/App/` | 2026-03-30 | 2026-04-11 (tutorial/macOS UI and privacy-screen follow-ups) | Sampled guidance still matches current usage; no material contradiction found in the checked paths. | `keep as canonical` |
| `docs/PRD.md` | Product requirements | Canonical current-state | Product, engineering, QA | Shipped scope, requirements, acceptance criteria, architecture summary | Must distinguish shipped behavior from roadmap and stay consistent with TDD/TESTING | `Sources/`, `Tests/`, `docs/TDD.md`, `docs/TESTING.md`, `docs/CHANGELOG.md` | 2026-04-09 | 2026-04-17 (static-archive link fix + Rust/FFI service rollout) | Header still says `v4.0` while the revision log points to `v4.1`; the technical summary still presents an XCFramework-first FFI story. | `update` |
| `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md` | Current-state rollout baseline | Canonical current-state | Developers, reviewers, AI tools | Current Rust/FFI service ownership and app-consumer baseline | Must match the current service/app state exactly | `Sources/Services/`, `Sources/App/`, `Tests/ServiceTests/`, `Tests/FFIIntegrationTests/` | 2026-04-13 | 2026-04-17 (certificate service, selective revocation, detailed results) | Still says certificate-signature workflows have no service owner and that detailed-result adoption is only partial, even though those service surfaces are now present and tested. | `update` |
| `docs/SECURITY.md` | Security model | Canonical current-state | Developers, security auditors, AI tools | Current crypto/auth/security invariants | Must match shipped security-sensitive code exactly | `Sources/Security/`, `Sources/Services/DecryptionService.swift`, `pgp-mobile/src/` | 2026-04-09 | 2026-04-17 (security-sensitive service rollout continues) | Sampled high-risk claims align with code: HKDF info string, auth modes, recovery states, and Argon2 guard behavior all match. | `keep as canonical` |
| `docs/TDD.md` | Technical design | Canonical current-state | Developers, security auditors | Current technical design, build pipeline, storage model | Must match shipped integration model and storage/build topology | `CypherAir.xcodeproj/project.pbxproj`, `docs/TESTING.md`, `Sources/`, `pgp-mobile/` | 2026-04-08 | 2026-04-17 (static-archive link fix + current storage defaults) | Stale on XCFramework-driven integration wording, `cargo-swift` emphasis, storage defaults, and temp-path inventory. | `update` |
| `docs/TESTING.md` | Testing guide | Canonical current-state | Developers + AI tools | Current validation workflow and test strategy | Must match actual test plans, workflows, and Xcode linkage | `.github/workflows/`, `CypherAir-*.xctestplan`, `CypherAir.xcodeproj/project.pbxproj`, `Tests/`, `UITests/` | 2026-04-17 | 2026-04-17 (same-day alignment with shipped config) | Strongest current-source-of-truth doc in the stack; sampled guidance matches plans, workflows, and direct static-archive linkage. | `keep as canonical` |

### Active Design or Roadmap Docs

| Path | Doc Class | Lifecycle Status | Audience | Claim Type | Expected Freshness Rule | Primary Truth Sources | Last Doc Update | Last Related Code Update | Key Findings | Recommended Disposition |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/CONTACTS_PRD.md` | Future product spec | Active design or roadmap | Product, design, engineering, QA | Planned Contacts product behavior | Must remain clearly future and not be mistaken for shipped behavior | `Sources/Services/ContactService.swift`, `Sources/Models/Contact.swift`, `docs/archive/CONTACTS_ENHANCEMENT_PLAN.md` | 2026-04-10 | 2026-04-10 (current Contacts implementation still flat-list based) | Clearly marked `Draft`, but it sits beside canonical docs and describes unimplemented vault/tag/recipient-list behavior. | `update` |
| `docs/CONTACTS_TDD.md` | Future technical spec | Active design or roadmap | Engineering, QA, AI tools | Planned Contacts technical architecture | Must remain clearly future and consistent with current-code absence | `Sources/Services/ContactService.swift`, `Sources/Models/Contact.swift`, `docs/CONTACTS_PRD.md` | 2026-04-10 | 2026-04-10 (current Contacts implementation still flat-list based) | Clearly future, but its placement makes a large planned vault architecture easy to confuse with shipped state. | `update` |
| `docs/RUST_FFI_APP_SURFACE_ADOPTION_PLAN.md` | App adoption plan | Active design or roadmap | Developers, reviewers, designers, AI tools | Future UI adoption for landed Rust/FFI service work | Must separate future UI work from the shipped UI baseline | `Sources/App/Sign/VerifyScreenModel.swift`, `Sources/App/Decrypt/DecryptScreenModel.swift`, `Sources/App/Keys/KeyDetailView.swift`, `Sources/App/Contacts/ContactDetailView.swift` | 2026-04-17 | 2026-04-17 (same-day app/service state) | Posture is good, but the "current app-surface baseline" is already partially stale because `Verify` and `Decrypt` now call the detailed service APIs directly. | `update` |
| `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md` | FFI/reference spec | Active design or roadmap | Developers, reviewers, AI tools | Future expansion reference with some current-state claims | Must keep current-state assertions synchronized even when mostly future-facing | `Sources/Services/`, `pgp-mobile/src/`, `Tests/` | 2026-04-16 | 2026-04-17 (service rollout completed) | Still says there is no current `CertificateSignatureService` owner and that detailed-result service ownership is future work. | `update` |
| `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md` | Rollout plan | Active design or roadmap | Developers, reviewers, AI tools | Future service-rollout queue | Must only describe work that has not already landed | `Sources/Services/`, `Tests/ServiceTests/`, `docs/RUST_FFI_APP_SURFACE_ADOPTION_PLAN.md` | 2026-04-17 | 2026-04-17 (same-day service rollout) | Still lists landed service work as future rollout items, so the remaining queue is no longer represented accurately. | `update` |
| `docs/archive/SPECIAL_SECURITY_MODE.md` | Withdrawn feature spec | Archived review note | Product, design, engineering, QA | Rejected third auth mode | Must remain explicitly non-canonical and unplanned | `Sources/Security/AuthenticationEvaluable.swift`, `Sources/App/Settings/`, `docs/PRD.md`, `docs/SECURITY.md` | 2026-05-10 | 2026-04-17 (auth code still exposes only `standard` + `highSecurity`) | The proposal is withdrawn and archived because the narrow anti-re-enrollment benefit does not justify the permanent private-key loss risk. | `archived` |
| `docs/TUTORIAL_REBUILD_SPEC.md` | Future/tutorial target spec | Active design or roadmap | Developers, designers, product owners, AI tools | Ideal end-state tutorial design | Must stay clearly target-state and pair cleanly with current implementation audits | `Sources/App/Onboarding/Tutorial/`, `Tests/ServiceTests/TutorialSessionStoreTests.swift`, `docs/TUTORIAL_IMPLEMENTATION_AUDIT.md` | 2026-04-06 | 2026-04-11 (tutorial host fixes and macOS launch follow-ups) | Posture is explicit and useful; the remaining issue is taxonomy and placement, not core ambiguity inside the file. | `update` |

### Active Audit or Review Snapshots

| Path | Doc Class | Lifecycle Status | Audience | Claim Type | Expected Freshness Rule | Primary Truth Sources | Last Doc Update | Last Related Code Update | Key Findings | Recommended Disposition |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/ARCHITECTURE_TESTING_DOC_REVIEW.md` | Review snapshot | Audit or review snapshot | Developers, reviewers, AI tools | Point-in-time verification of architecture/testing doc claims | Must be clearly snapshot-scoped and easy to distinguish from canonical docs | `docs/ARCHITECTURE.md`, `docs/TESTING.md`, `CLAUDE.md`, `Sources/`, `Tests/`, `.github/workflows/` | 2026-04-16 | 2026-04-17 (same surfaces changed again afterward) | Useful evidence, but the title is confusing/self-referential and the file lives in top-level `docs/` rather than an archive/review namespace. | `archive` |
| `docs/TUTORIAL_IMPLEMENTATION_AUDIT.md` | Review snapshot | Audit or review snapshot | Developers, designers, product owners, AI tools | Point-in-time tutorial implementation audit | Must stay explicitly dated, scoped, and non-canonical | `Sources/App/Onboarding/Tutorial/`, `Tests/ServiceTests/TutorialSessionStoreTests.swift` | 2026-04-10 | 2026-04-11 (tutorial host follow-ups) | Strongly dated and scoped, but it lacks standardized snapshot metadata and shares top-level space with canonical docs. | `update` |

### Archived Docs

| Path | Doc Class | Lifecycle Status | Audience | Claim Type | Expected Freshness Rule | Primary Truth Sources | Last Doc Update | Last Related Code Update | Key Findings | Recommended Disposition |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/archive/CONTACTS_ENHANCEMENT_PLAN.md` | Archived plan | Archive | Product authors, design authors, developers, AI tools | Historical Contacts planning baseline | Must stay explicitly historical with valid successor links | `docs/CONTACTS_PRD.md`, `docs/CONTACTS_TDD.md` | 2026-04-08 | 2026-04-10 (Contacts PRD/TDD supersession + contact validation changes) | Archive framing is explicit; body still carries some authoritative future-language from its pre-archive phase. | `leave archived` |
| `docs/archive/POC.md` | Archived test plan | Archive | Historical POC contributors | Historical validation record | Must stay historical and keep working successor links | `docs/TESTING.md`, `docs/PRD.md`, `docs/TDD.md` | 2026-03-19 | 2026-04-17 (canonical testing/build story moved on) | Archive framing is clear, but three local links are broken because they still point to sibling paths instead of `../`. | `update` |
| `docs/archive/RUST_FFI_CURRENT_STATE_AUDIT.md` | Archived audit | Archive | Developers, reviewers, AI tools | Historical claim verification | Must stay explicitly historical; no need to mirror current code after archival | Active Rust/FFI docs, `pgp-mobile/src/`, `Sources/Services/` | 2026-04-13 | 2026-04-16 (newer Rust/FFI review snapshot exists) | Archival framing and scope are explicit; useful only as historical evidence. | `leave archived` |
| `docs/archive/RUST_FFI_SERVICE_ADOPTION_ASSESSMENT.md` | Archived assessment | Archive | Developers, reviewers, AI tools | Historical service-adoption assessment | Must stay historical with explicit successor links | Active Rust/FFI docs | 2026-04-13 | 2026-04-17 (service rollout moved forward) | Strong supersession notice; no navigation issue found. | `leave archived` |
| `docs/archive/RUST_FFI_SERVICE_INTEGRATION_PLAN_ASSESSMENT.md` | Archived assessment | Archive | Developers, reviewers, AI tools | Historical rollout-feasibility assessment | Must stay historical with explicit successor links | Active Rust/FFI docs | 2026-04-13 | 2026-04-17 (service rollout moved forward) | Strong supersession notice; no navigation issue found. | `leave archived` |
| `docs/archive/RUST_FFI_THREE_DOC_REVIEW.md` | Archived review | Archive | Developers, reviewers, AI tools | Historical point-in-time review of the April 13 Rust/FFI stack | Must stay historical and clearly dated | Active Rust/FFI docs | 2026-04-16 | 2026-04-17 (service/app state changed again afterward) | Clear snapshot framing; still useful as historical context. | `leave archived` |
| `docs/archive/RUST_SEQUOIA_INTEGRATION_TODO.md` | Archived roadmap | Archive | Developers, reviewers, AI tools | Historical Sequoia expansion roadmap | Must stay historical and linked to successors | Active Rust/FFI docs, `pgp-mobile/src/` | 2026-04-13 | 2026-04-17 (later Rust/FFI doc stack superseded it) | Archive framing and successor chain are clear. | `leave archived` |
| `docs/archive/SEQUOIA_CAPABILITY_AUDIT.md` | Archived audit | Archive | Developers, reviewers, AI tools | Historical capability inventory | Must stay historical and not be mistaken for current source of truth | Active Rust/FFI docs, `pgp-mobile/Cargo.toml`, `pgp-mobile/src/` | 2026-04-13 | 2026-04-17 (later Rust/FFI doc stack superseded it) | Archive banner is strong, but the body still uses extensive present-tense current-build language. | `leave archived` |
| `docs/archive/SEQUOIA_CAPABILITY_AUDIT_APPENDIX.md` | Archived appendix | Archive | Developers, reviewers, AI tools | Historical out-of-boundary appendix | Must stay historical and paired with its parent archive | Parent archive + active Rust/FFI docs | 2026-04-13 | 2026-04-17 (later Rust/FFI doc stack superseded it) | Clear archive framing; no material navigation issue found. | `leave archived` |
| `docs/archive/SERVICE_VIEW_REFACTOR_ASSESSMENT.md` | Archived assessment | Archive | Developers, reviewers, AI tools | Historical service/view refactor assessment | Must stay historical with explicit completion/defer framing | `Sources/App/`, `Sources/Services/`, `docs/CONVENTIONS.md` | 2026-04-12 | 2026-04-11 (scoped refactor phases completed/deferred) | Archive framing is explicit and coherent. | `leave archived` |
| `docs/archive/SERVICE_VIEW_REFACTOR_IMPLEMENTATION_SPEC.md` | Archived implementation spec | Archive | Developers, reviewers, AI tools | Historical refactor plan | Must stay historical and clearly non-authoritative for new work | Companion assessment + current app/service architecture | 2026-04-12 | 2026-04-11 (scoped refactor phases completed/deferred) | Archive framing is explicit and coherent. | `leave archived` |

## Findings by Severity

### High

1. **Canonical build/link pipeline narrative conflicts with the shipped Xcode integration**
   - Buckets: `Code drift`, `Cross-document contradiction`
   - What is wrong:
     - `docs/TDD.md:184-188` still documents the Rust/UniFFI handoff as `uniffi-bindgen -> lipo -> xcodebuild -create-xcframework -> import XCFramework`.
     - `docs/PRD.md:314` still summarizes FFI as `Wrapper crate -> Swift bindings -> XCFramework`.
     - `README.md:110`, `CLAUDE.md:11,48-49`, and `AGENTS.md:50-51` still use the same XCFramework-first shorthand.
   - Contradicting evidence:
     - `docs/TESTING.md:111-121` explicitly says the current Xcode project links the target-specific release archives directly and that the local XCFramework is not used directly for the current link step.
     - `CypherAir.xcodeproj/project.pbxproj:469-578,795-810` wires `bindings/module.modulemap` plus the three `libpgp_mobile.a` release archives into the build settings.
   - Why it matters:
     - This is a high-impact contributor workflow. Getting it wrong can send maintainers to the wrong refresh path after Rust or UniFFI changes.

2. **Active Rust/FFI current-state docs are stale after the 2026-04-16 and 2026-04-17 rollout**
   - Buckets: `Code drift`, `Cross-document contradiction`
   - What is wrong:
     - `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md:43-45` still says certificate-signature workflows have no service owner and that richer signature results are only partially integrated.
     - `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:48-55,91-158,302-312` still treats `CertificateSignatureService`, selector-driven selective revocation, and detailed decrypt/signing work as future rollout items.
     - `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md:519,558-559,677` still says the current Swift production boundary is none for certificate signatures and that detailed-result service adoption remains future work.
   - Contradicting evidence:
     - `Sources/Services/CertificateSignatureService.swift:5-176`
     - `Sources/Services/KeyManagementService.swift:176-206,276`
     - `Sources/Services/SigningService.swift:153-310`
     - `Sources/Services/DecryptionService.swift:229-437`
     - `Tests/ServiceTests/CertificateSignatureServiceTests.swift`
     - `Tests/ServiceTests/KeyManagementServiceTests.swift:1488-1811`
     - `Tests/ServiceTests/SigningServiceDetailedResultTests.swift`
     - `Tests/ServiceTests/DecryptionServiceTests.swift:801-1164`
   - Why it matters:
     - These files are supposed to tell engineers what already exists versus what is still pending. Right now they invert that boundary.

3. **`docs/ARCHITECTURE.md` is stale on a security-sensitive flow and on current topology**
   - Buckets: `Code drift`
   - What is wrong:
     - `docs/ARCHITECTURE.md:168-170` still shows Rust returning recipient IDs and Swift doing the local match in phase 1.
     - `docs/ARCHITECTURE.md:113-121` still lists `uniffi.toml`, which no longer exists.
     - `docs/ARCHITECTURE.md:308-323` still documents `Documents/revocation/`, `defaultBlue`, and only `tmp/decrypted/`.
   - Contradicting evidence:
     - `Sources/Services/DecryptionService.swift:57-126` calls `engine.matchRecipients(...)` and `engine.matchRecipientsFromFile(...)` during phase 1.
     - `pgp-mobile/Cargo.toml:13-14` and `pgp-mobile/uniffi-bindgen.rs` show the current UniFFI helper layout; there is no `pgp-mobile/uniffi.toml`.
     - `Sources/Services/ContactRepository.swift:83` stores `contact-metadata.json`.
     - `Sources/Models/AppConfiguration.swift:66-97,137-145` persists `guidedTutorialCompletedVersion`, persists `colorTheme`, and defaults `colorTheme` to `.systemDefault`.
     - `Sources/App/AppStartupCoordinator.swift:40-51` cleans both `tmp/decrypted` and `tmp/streaming`.
   - Why it matters:
     - Contributors rely on `ARCHITECTURE.md` to understand boundaries, especially around decrypt/auth flow and storage. This drift can misdirect review in exactly the parts of the app that are most sensitive.

### Medium

1. **`PRD.md`, `TDD.md`, and `CHANGELOG.md` no longer present one coherent revision story**
   - Buckets: `Cross-document contradiction`
   - Evidence:
     - `docs/PRD.md:3` and `docs/TDD.md:3-4` still declare `v4.0`.
     - `docs/CHANGELOG.md:8` records `v4.1` as the documentation-and-infrastructure-sync revision.
     - `docs/PRD.md:378-379` now points readers to `CHANGELOG.md` for the full revision history.
   - Why it matters:
     - This creates ambiguity about which revision label is authoritative and whether later sync work was actually absorbed into the canonical specs.

2. **Entry docs and agent docs underdescribe the current test-plan layout**
   - Buckets: `Cross-document contradiction`, `Governance gap`
   - Evidence:
     - `CLAUDE.md:122` lists only `CypherAir-UnitTests.xctestplan` and `CypherAir-DeviceTests.xctestplan`.
     - `docs/TESTING.md:82-90` documents all three test plans, including `CypherAir-MacUITests.xctestplan`.
     - `CypherAir.xcodeproj/xcshareddata/xcschemes/CypherAir.xcscheme:32-39` includes the Mac UI plan in the shared scheme.
   - Why it matters:
     - The omission is not fatal for ordinary validation, but it makes route/tutorial/macOS UI changes easier to under-test.

3. **Future specs are mixed into top-level `docs/` beside canonical docs**
   - Buckets: `Lifecycle or placement issue`, `Governance gap`
   - Evidence:
     - `docs/CONTACTS_PRD.md`, `docs/CONTACTS_TDD.md`, `docs/TUTORIAL_REBUILD_SPEC.md`, and the Rust/FFI plan stack all live in top-level `docs/`; `docs/archive/SPECIAL_SECURITY_MODE.md` previously did too before withdrawal and archival.
     - Those files do use draft/plan language, for example:
       - `docs/archive/SPECIAL_SECURITY_MODE.md:5`
       - `docs/RUST_FFI_APP_SURFACE_ADOPTION_PLAN.md:7`
   - Why it matters:
     - The lifecycle signal depends on readers noticing prose disclaimers. The path itself does not distinguish future design work from canonical current-state guidance.

4. **Active review snapshots are not governed consistently**
   - Buckets: `Lifecycle or placement issue`, `Broken navigation or metadata`
   - Evidence:
     - `docs/ARCHITECTURE_TESTING_DOC_REVIEW.md:1` has a confusing self-referential title.
     - `docs/TUTORIAL_IMPLEMENTATION_AUDIT.md:1-15` is clearly dated and scoped, but it does not use the same structured metadata pattern as the archived review stack.
     - Both files live in top-level `docs/`, not in `docs/archive/` or a dedicated review namespace.
   - Why it matters:
     - These are useful documents, but they currently look too similar to permanent guidance docs unless the reader already knows the taxonomy.

### Low

1. **`docs/archive/POC.md` has broken local links**
   - Buckets: `Broken navigation or metadata`
   - Evidence:
     - `docs/archive/POC.md:3-6` links to `TESTING.md`, `PRD.md`, and `TDD.md` as siblings.
     - Local link audit for this pass resolved those paths as missing because the correct archive-relative targets should be `../TESTING.md`, `../PRD.md`, and `../TDD.md`.
   - Why it matters:
     - The file is archived, so the severity is low, but it still breaks navigation from a historical document to its active successors.

2. **Front-matter coverage is inconsistent across the stack**
   - Buckets: `Governance gap`
   - Evidence:
     - Repo-wide scan for this pass found only `12/33` scoped docs with a full `Status + Purpose + Audience` pattern.
     - Missing or partial metadata is especially common in entry docs, `CHANGELOG.md`, and active review snapshots.
   - Why it matters:
     - Readers do not get a uniform lifecycle signal from the docs themselves, which makes misclassification more likely.

3. **Archived docs still rely on front matter more than body language to communicate archival state**
   - Buckets: `Governance gap`, `Lifecycle or placement issue`
   - Evidence:
     - `docs/archive/SEQUOIA_CAPABILITY_AUDIT.md` and `docs/archive/CONTACTS_ENHANCEMENT_PLAN.md` have strong archive banners, but the bodies still contain strong present-tense or authoritative planning language from their original active phase.
   - Why it matters:
     - The archive state is still understandable, but a stronger archive template would reduce the need for readers to mentally override the body content.

## Per-Document Recommended Disposition

### `keep as canonical`

- `docs/CHANGELOG.md`
- `docs/CODE_REVIEW.md`
- `docs/CONVENTIONS.md`
- `docs/LIQUID_GLASS.md`
- `docs/SECURITY.md`
- `docs/TESTING.md`

### `update`

- `README.md`
- `CLAUDE.md`
- `AGENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/CONTACTS_PRD.md`
- `docs/CONTACTS_TDD.md`
- `docs/PRD.md`
- `docs/RUST_FFI_APP_SURFACE_ADOPTION_PLAN.md`
- `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md`
- `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`
- `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md`
- `docs/archive/SPECIAL_SECURITY_MODE.md`
- `docs/TDD.md`
- `docs/TUTORIAL_IMPLEMENTATION_AUDIT.md`
- `docs/TUTORIAL_REBUILD_SPEC.md`
- `docs/archive/POC.md`

### `archive`

- `docs/ARCHITECTURE_TESTING_DOC_REVIEW.md`

### `leave archived`

- `docs/archive/CONTACTS_ENHANCEMENT_PLAN.md`
- `docs/archive/RUST_FFI_CURRENT_STATE_AUDIT.md`
- `docs/archive/RUST_FFI_SERVICE_ADOPTION_ASSESSMENT.md`
- `docs/archive/RUST_FFI_SERVICE_INTEGRATION_PLAN_ASSESSMENT.md`
- `docs/archive/RUST_FFI_THREE_DOC_REVIEW.md`
- `docs/archive/RUST_SEQUOIA_INTEGRATION_TODO.md`
- `docs/archive/SEQUOIA_CAPABILITY_AUDIT.md`
- `docs/archive/SEQUOIA_CAPABILITY_AUDIT_APPENDIX.md`
- `docs/archive/SERVICE_VIEW_REFACTOR_ASSESSMENT.md`
- `docs/archive/SERVICE_VIEW_REFACTOR_IMPLEMENTATION_SPEC.md`

## Governance Baseline for the Remediation Phase

### 1. Target Taxonomy

The doc stack should converge on five durable classes:

1. `Entry`
   - Root orientation docs such as `README.md`, `CLAUDE.md`, and `AGENTS.md`
   - Job: explain the project and point into canonical sources of truth
2. `Canonical current-state`
   - Docs that are expected to match shipped code/config/tests right now
   - Examples: architecture, security, testing, conventions, review checklist, canonical product/technical specs
3. `Proposal or roadmap`
   - Future product or engineering direction
   - Must say explicitly that the content is not yet shipped
4. `Audit or review snapshot`
   - Point-in-time verification artifact
   - Must be dated, scoped, and clearly non-canonical
5. `Archive`
   - Historical context only
   - Must live under `docs/archive/` and point to active successors where they exist

### 2. Required Metadata Fields by Class

Canonical current-state docs should standardize on:

- `Status: Canonical current-state`
- `Purpose`
- `Audience`
- `Source of truth`
- `Last reviewed`
- `Update triggers`

Proposal/roadmap docs should standardize on:

- `Status: Draft`, `Active roadmap`, or equivalent
- `Purpose`
- `Audience`
- explicit non-authoritative note such as "not a statement of current shipped behavior"
- `Depends on` / `Supersedes` / `Blocked by` when relevant

Audit/review snapshots should standardize on:

- `Date`
- `Scope`
- `Evidence roots`
- `Verdict summary`
- `Superseded by` when a later snapshot replaces them

Archived docs should standardize on:

- `Status: Archived`
- archival reason
- snapshot date
- successor docs
- explicit statement that current code/docs outrank the archived file

### 3. Archive Rules

- Only archived docs belong in `docs/archive/`.
- Archived docs must keep working local links to their active successors.
- The first paragraph after the archive banner should read historically, not like current guidance.
- Active docs should not depend on archived docs for primary current-state claims.
- When a review snapshot is superseded, either archive it or move it into a dedicated review namespace; do not leave it mixed with canonical docs indefinitely.

### 4. Doc-Update Triggers

The following code/config changes should automatically trigger doc review in the same change:

- Build/link pipeline changes:
  - update `README.md`, `CLAUDE.md`, `AGENTS.md`, `docs/PRD.md`, `docs/TDD.md`, and `docs/TESTING.md`
- Test-plan/workflow changes:
  - update `README.md`, `CLAUDE.md`, `AGENTS.md`, and `docs/TESTING.md`
- Rust/FFI service ownership or current rollout changes:
  - update `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`, `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md`, `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md`, and any affected app-adoption plan
- Storage keys/defaults or temp-path changes:
  - update `docs/ARCHITECTURE.md`, `docs/TDD.md`, and any canonical product/security summary that exposes those details
- Auth mode or recovery changes:
  - update `docs/SECURITY.md`, `docs/PRD.md`, `docs/TDD.md`, and entry docs if the user-facing story changes
- New future feature docs:
  - place them in a proposal namespace or give them unmistakable lifecycle metadata before adding them to top-level documentation navigation

### 5. Repo-Wide Remediation Priority Order

1. **Repair canonical current-state drift first**
   - `README.md`, `CLAUDE.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/PRD.md`, `docs/TDD.md`
   - Goal: one coherent story for build/test topology, architecture, storage defaults, and shipped scope
2. **Repair the active Rust/FFI doc stack second**
   - `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`
   - `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md`
   - `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md`
   - `docs/RUST_FFI_APP_SURFACE_ADOPTION_PLAN.md`
   - Goal: restore the boundary between "already landed" and "still planned"
3. **Establish lifecycle governance**
   - Create clear taxonomy and metadata rules for canonical docs, proposals, reviews, and archives
   - Decide whether future specs and active review snapshots stay in `docs/` or move into dedicated namespaces
4. **Clean up navigation and metadata hygiene**
   - Fix broken archive links
   - normalize front matter
   - rename or archive ambiguous snapshot docs
5. **Only then reconsider archive compression or redundancy cleanup**
   - Historical Rust/FFI and refactor snapshots can be evaluated for deeper consolidation after active docs are stable again
