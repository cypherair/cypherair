# PgpMobile FFI Artifact Decision

> Status: Decision record — accepted 2026-07-11. The "Current shape" section is canonical current-state and must match the shipped build; the recorded decision stands until a revisit trigger (§5) fires.
> Purpose: Record why CypherAir keeps the UniFFI outputs tracked in-tree and links a locally built static-library `PgpMobile.xcframework`, and the concrete conditions that would reopen that choice.
> Audience: AI coding tools and human developers touching the FFI artifact, the generated bindings, or the release asset set.
> Update triggers: a §5 revisit trigger fires; the artifact shape, the `pgp_mobileFFI` module name, or generated-output tracking actually changes; or the release-asset contract for `PgpMobile.xcframework` changes (reconcile with [RELEASE.md](RELEASE.md), which owns it).
> Originating issue: #545.

## 1. Context

Issue #545 asks whether the PgpMobile FFI boundary should keep its current shape or move to a framework-shaped XCFramework, a cleaner module name, and/or a stronger generated-output ownership model. The concrete friction is real: the module map and header search paths that let Swift see the C FFI layer are repeated in every build configuration of the Xcode project rather than travelling inside the artifact. This document records the decision and — the load-bearing part — the triggers that would justify paying to change it. It does not schedule or design a migration; the altitude here is invariants and red lines, not mechanics.

## 2. Current shape (as-is)

Ground truth as built by `build-xcframework.sh` (which execs `scripts/build_apple_arm64e_xcframework.sh`) and consumed by `CypherAir.xcodeproj`:

- **Artifact.** `PgpMobile.xcframework` is a **static-library** XCFramework: five slices (`aarch64-apple-ios`, `-ios-sim`, `-darwin`, `-visionos`, `-visionos-sim`), each carrying `libpgp_mobile.a` plus a `Headers/` directory with `pgp_mobileFFI.h` and a `module.modulemap`. It is a build product, git-ignored (`*.xcframework/`), rebuilt from source against the pinned arm64e stage1; a project build-phase guard fails the build if it is missing. The release-grade binary and its SDK channels (Edge/Drill/Stable) are owned by [RELEASE.md](RELEASE.md) §3 and §5 and not restated here.
- **Module name.** The UniFFI-generated C module is `pgp_mobileFFI`; the generated Swift opens with `#if canImport(pgp_mobileFFI)` / `import pgp_mobileFFI`.
- **Tracked generated outputs.** Five generated files are committed to the tree: `Sources/PgpMobile/pgp_mobile.swift`, `bindings/pgp_mobile.swift`, `bindings/pgp_mobileFFI.h`, `bindings/module.modulemap`, and `bindings/pgp_mobileFFI.modulemap`. The build regenerates them into a scratch directory and re-syncs the tracked copies only when they change. `Sources/PgpMobile/pgp_mobile.swift` and `bindings/pgp_mobile.swift` are byte-identical, but only the `Sources/PgpMobile/` copy is a compile source; the `bindings/` copy is a staging file. `bindings/module.modulemap` and `bindings/pgp_mobileFFI.modulemap` are likewise byte-identical.
- **Linkage.** Xcode links the static `PgpMobile.xcframework` in the Frameworks phase, compiles the generated Swift as ordinary app source, and reaches the C module through **per-configuration** build settings repeated across every configuration: `HEADER_SEARCH_PATHS` and `SWIFT_INCLUDE_PATHS` include `$(PROJECT_DIR)/bindings`, and `OTHER_CFLAGS`/`OTHER_SWIFT_FLAGS` pass `-Xcc -fmodule-map-file=$(PROJECT_DIR)/bindings/module.modulemap`. That duplication is the "scattered configuration" #545 names.

When a Rust/UniFFI change requires the full rebuild before Swift validation is governed by `.claude/skills/rust-sync`.

## 3. Options considered

**Option 1 — Status quo.** Keep the tracked generated outputs and the locally built static-library XCFramework; accept the per-configuration module/header settings. Zero build or release churn; clean checkouts compile without a mandatory bindgen bootstrap; the generated Swift stays diff-reviewable. Cost: the scattered pbxproj settings and the duplicated generated files persist.

**Option 2 — Framework-shaped / artifactized XCFramework (issue Directions A and B).** Reshape `PgpMobile.xcframework` so each slice is a `*.framework` carrying its own `Modules/module.modulemap` and `Headers/`. Xcode then resolves the module from the artifact and the global `-fmodule-map-file` / search-path settings disappear. The A/B split is a naming sub-decision: `pgp_mobileFFI.xcframework` keeps the existing module/import name (lower disruption, less idiomatic), while `PgpMobileFFI.xcframework` is cleaner Apple-style naming but is a module/API rename that ripples through the generated bindings and the FFI adapter surface. Cost: a framework wrapper, a re-verified static-link posture, and a consistent update to the release-asset names, manifest, attestation, relink-kit, and source-compliance surface ([RELEASE.md](RELEASE.md) §3/§5).

**Option 3 — Generated-output ownership redesign (issue Direction C).** Stop tracking the generated UniFFI outputs and define a reliable restore/generate model spanning local dev, GitHub CI, Xcode Cloud WF1/WF2, release assets, App Store candidate validation, docs, and source compliance. This is the most complete generated-output fix and the most disruptive; it is independent of the Option 2 shape/name choice.

Naming unification (`pgp_mobileFFI` vs `PgpMobileFFI`) is not a standalone option — it only pays off riding on Option 2, and on its own would be churn without benefit.

## 4. Decision

**Accept Option 1 as deliberate, not accidental.** The current tracked-generated + locally-built static-library shape is Apple-supported, idiomatic for UniFFI/Rust static linking, and correct for a single first-party consumer. The scattered pbxproj settings are contained, static, and well understood; the reshaping and rename churn of Options 2 and 3 exceeds their benefit today. The SDK channels already vend the static XCFramework to downstream consumers ([RELEASE.md](RELEASE.md) §5) without a framework wrapper.

These invariants hold regardless of any future revisit and constrain whatever replaces this decision:

- **Static linking stays.** No dynamic or embedded runtime framework — this preserves the single-binary MIE posture and is an explicit #545 non-goal.
- **Generated Swift stays compiled as app source** unless a separate Swift-module packaging decision is made.
- **`PgpMobile.xcframework` stays reproducible from the pinned arm64e stage1** — never `latest` (pin owned by [ARM64E_STATUS.md](ARM64E_STATUS.md)).
- **Any reshape keeps every gate green** — clean-checkout local build, GitHub CI, Xcode Cloud WF1/WF2, and stable releases — and updates the release-asset contract ([RELEASE.md](RELEASE.md) §3/§5: names, manifest, attestation, relink-kit, source compliance) in the same change.
- **Out of bounds:** do not split `pgp-mobile/` into its own repository, and do not touch Contacts SQLCipher storage (both #545 non-goals).

## 5. Revisit triggers

Reopen this decision when any of these becomes true — each shifts the cost/benefit toward Option 2 or Option 3:

1. **A second consumer.** Any target, app, or SDK integration beyond the first-party app needs to link PgpMobile without hand-copying the per-configuration module/header settings. A framework-shaped artifact (Option 2) starts paying for itself at consumer #2.
2. **SwiftPM packaging need.** A decision to vend PgpMobile as a Swift Package binary target. SwiftPM binary targets require an `.xcframework`, and a framework-shaped one with an embedded module map is materially cleaner to distribute than a static-library XCFramework that forces consumer-side `-fmodule-map-file` flags.
3. **Upstream UniFFI packaging change.** A UniFFI release (beyond the pinned 0.31.x) that changes the generated module/import name, ships a framework-shaped packaging path, or changes the modulemap/header layout enough to break the current sync — re-evaluate both the shape and the `pgp_mobileFFI` vs `PgpMobileFFI` name at that boundary.
4. **Generated-output friction crosses a threshold.** Recurring merge conflicts on the large generated Swift, the two byte-identical `pgp_mobile.swift` copies drifting, or clean-checkout builds needing a mandatory bindgen bootstrap anyway — reopen Option 3 (untrack plus a restore/generate model).
5. **The scattered settings stop being reliable.** A future Xcode toolchain changes how static-library XCFrameworks or global `-fmodule-map-file` resolution behave, such that the per-configuration settings break — reshape to a framework-shaped artifact.

## 6. Consequences

- **Now:** no build or release churn; clean checkouts build; the generated Swift stays visible in diffs and governed by `.claude/skills/rust-sync`; the static-link + MIE posture and the release-asset contract are untouched.
- **Accepted costs:** the module map and header search paths stay duplicated per build configuration in the pbxproj; the generated Swift is tracked in two byte-identical locations (`Sources/PgpMobile/pgp_mobile.swift` compiled, `bindings/pgp_mobile.swift` staged), as are the two modulemaps; the lowercased `pgp_mobileFFI` module name — less Apple-idiomatic — stays load-bearing across the generated bindings; refreshing the artifact still requires the full pinned rebuild.
- **When a trigger fires:** this record is where the reopened decision is re-recorded, or it is superseded by the implementation issue that selects Option 2 or Option 3. Issue #545 is closed by recording the decision, not by changing the build.
