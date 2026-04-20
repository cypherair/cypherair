# Compliance Remediation Plan

> Status: Selected direction, implementation pending.
> Purpose: Record CypherAir's selected licensing and distribution-compliance remediation direction, the channel-specific fulfillment plan, the required release assets, and the implementation sequence.
> Audience: Human developers, reviewers, release owners, and AI coding tools.
> This document records the chosen remediation path. It is not, by itself, a statement that all downstream docs, release workflows, product metadata, or shipped binaries have already been updated.
> Current code and active canonical docs still describe shipped behavior unless and until they are updated in the implementation phases below.
> Companion documents: [README.md](../README.md) · [CLAUDE.md](../CLAUDE.md) · [AGENTS.md](../AGENTS.md) · [TDD.md](TDD.md) · [TESTING.md](TESTING.md) · [XCFRAMEWORK_RELEASES.md](XCFRAMEWORK_RELEASES.md) · [DOCUMENTATION_GOVERNANCE.md](DOCUMENTATION_GOVERNANCE.md)

## 1. Role And Scope

This document is CypherAir's primary remediation-plan document for licensing and distribution compliance.

Use this document to:

- record the selected first-party licensing direction
- separate first-party license changes from third-party `LGPL` fulfillment work
- define the selected fulfillment basis for `sequoia-openpgp` and `buffered-reader`
- describe the chosen App and `XCFramework` distribution paths
- define the minimum stable-release asset contract
- record release-blocking conditions and implementation phases

Do not use this document as the sole statement of current shipped compliance status.

## 2. Current Planning Baseline

The following repository facts remain the planning baseline for this remediation work:

- The App already includes an in-product license and notices experience through the Settings flow.
- The bundled notices payload includes full license texts and highlights core direct dependencies in the current UI grouping.
- `sequoia-openpgp` currently appears unmodified in-repo. The checked-in Rust manifest shows no local patch override for `sequoia-openpgp`; the current `[patch.crates-io]` override is limited to `openssl-src`.
- The current Rust integration uses `staticlib` packaging into `PgpMobile.xcframework`.
- The project currently distributes `PgpMobile.xcframework` as a standalone binary release artifact through the documented `XCFramework` release channel.
- First-party repo, crate, and bundled notice messaging now use `GPL-3.0-or-later OR MPL-2.0`; remaining product and release-surface updates continue in the implementation phases below.
- The default App Store path remains Apple's standard EULA unless implementation or submission reality requires an explicit custom-EULA fallback later.

## 3. Selected Direction

CypherAir's selected remediation direction is:

- First-party code uses `GPL-3.0-or-later OR MPL-2.0`.
- The retained `GPL` branch is preserved for project identity, historical continuity, and public licensing continuity.
- The retained `GPL` branch is not treated as a continuing sole downstream constraint because public recipients may elect the `MPL-2.0` branch.
- Third-party `LGPL` fulfillment remains a separate parallel obligation and is not satisfied by the first-party dual-license change.
- The current remediation path does not adopt Sequoia commercial terms or Sequoia replacement as the primary plan. Those remain fallback options only.
- The default App Store path does not assume a custom EULA.

This plan intentionally selects a public dual-license path instead of a channel-split private relicensing path.

## 4. Selected Fulfillment Basis

For planning and implementation, the project will treat `sequoia-openpgp` and `buffered-reader` as `LGPL-2.0-or-later` components and organize fulfillment materials on an `LGPL 2.1` basis.

This selected basis means:

- the project records the upstream components as `LGPL-2.0-or-later`
- the fulfillment materials are organized around the successor `LGPL 2.1` framing rather than the older Library GPL wording currently bundled in notices
- the plan does not adopt `LGPL 3.0` as the primary fulfillment basis

The reason for not adopting `LGPL 3.0` as the project default is operational rather than ideological:

- it does not remove relink or recombine style obligations for combined works
- it may introduce heavier installation-information framing than the project wants as its primary App-distribution basis

This is a selected fulfillment-organizing basis for remediation work, not a claim that all legal uncertainty is eliminated.

## 5. Channel-Specific Distribution Plan

### App

The selected App path is:

- do not embed a full source bundle in the App package
- add an exact `Source & Compliance` entry from the About surface
- for release builds, display the marketing version, build number, commit SHA, dependency summary, and the exact GitHub release URL for the corresponding stable build release
- do not place a long-form written-offer text inside the App UI
- rely on exact version-bound release materials, durable release-page linkage, and immutable release assets as the primary operational fulfillment path

The selected App path is intentionally lighter than an embedded full-source package or in-App long-form offer. That choice leaves residual legal-risk questions, which are recorded below rather than hidden.

### XCFramework

The selected `XCFramework` path is:

- continue the existing edge and drill prerelease model for validation work
- move stable `XCFramework` distribution into the unified stable build release page described below
- publish a technical `relink kit` for the stable `XCFramework` path as a supplement to the source bundle, not as a replacement for it
- treat the `relink kit` as a technical compliance asset for SDK consumers rather than an App-bundled asset

## 6. Stable Release Topology

CypherAir's selected release topology is:

- edge and drill prereleases remain separate from stable release handling
- stable builds use a unified release page with tag format `cypherair-vX.Y.Z-buildN`
- the unified stable release page acts as both:
  - the App build's compliance landing page
  - the stable `XCFramework` release page
- the stable release page publishes one shared source bundle and one shared compliance manifest for the tagged build
- the stable release page also publishes the stable `XCFramework` binary assets and the `XCFramework`-specific `relink kit`

This design keeps daily validation prereleases separate while giving formal stable builds a single exact public landing page.

## 7. Formal Stable Asset Contract

Every unified stable build release must include, at minimum:

- `CypherAir-source-bundle.tar.zst`
- `CypherAir-compliance-manifest.json`
- `PgpMobile.xcframework.zip`
- `PgpMobile.xcframework.sha256`
- `PgpMobile-relink-kit.tar.zst`

The shared source bundle must include, at minimum:

- the exact first-party repository snapshot for the tagged commit
- `Cargo.lock`
- the build scripts needed to reproduce the tagged build outputs
- vendored Rust third-party source snapshots for the exact locked dependency set
- license and notice materials required for the tagged release

The shared compliance manifest must encode, at minimum:

- product kind and channel
- release tag
- marketing version
- build number
- commit SHA
- source bundle filename and SHA256
- binary asset filename and SHA256 entries
- `sequoia-openpgp` version
- `buffered-reader` version
- elected fulfillment basis = `LGPL 2.1`
- first-party license = `GPL-3.0-or-later OR MPL-2.0`

The `XCFramework` relink kit is a stable-release technical asset and must include enough version-bound material and instructions to support relink-focused compliance review for the stable SDK channel.

## 8. Automation And Immutability

The selected automation model is:

- pushing the stable App build tag triggers the stable release workflow
- the stable release workflow rebuilds the formal assets from the tagged commit
- the stable release workflow does not reuse edge prerelease assets as the formal stable assets
- the stable release workflow creates the unified stable release page immediately after the stable tag is pushed
- the stable release workflow must verify that the tag, marketing version, build number, and tagged commit are internally consistent before publishing assets

The selected immutability rule is:

- compliance assets are immutable once published
- release assets may not be silently replaced
- if a published asset set is wrong, the fix is a new build number, new tag, and new release

## 9. Release-Blocking Conditions

No new formal stable release should proceed unless all of the following are true:

- the stable tag matches the intended `marketing version + build number` pair
- the unified stable release page is generated for that exact tag
- the shared source bundle is generated and checksummed
- the shared compliance manifest is generated and checksummed
- `PgpMobile.xcframework.zip` and `PgpMobile.xcframework.sha256` are generated for that exact stable build
- the stable `XCFramework` relink kit is generated
- the release assets are internally version-bound to the same commit and tag

No documentation update should describe the stable topology as implemented until the workflow and release assets above actually exist.

## 10. App Residual Risk

The selected App path intentionally accepts residual risk that this document should state explicitly:

- the App does not embed a full source bundle
- the App does not include a long-form written-offer text
- the App relies on an exact GitHub stable-release link and durable online release assets instead of an in-bundle full-material package
- App Store distribution is not the same hosting surface as the GitHub release page that will carry the compliance materials

Accordingly, this plan treats the App path as the selected operational remediation path, not as proof that all legal uncertainty is resolved. If implementation or release review shows this path is not sufficiently robust, the project must block release rather than silently downgrade the fulfillment posture.

## 11. Implementation Phases

The selected implementation sequence is:

- Phase 1: finalize this remediation document and the stable asset contract
- Phase 2: implement stable App build release automation and shared compliance-asset generation
- Phase 3: add the About-surface exact `Source & Compliance` entry with version, build, commit, dependency summary, and exact stable release link
- Phase 4: implement the stable `XCFramework` relink kit and unify the stable `XCFramework` assets under the stable App build release page
- Phase 5: update downstream docs, product metadata, and outward-facing license messaging to the new selected path

This document remains the planning and implementation reference while later phases continue to land.

## 12. Downstream Docs And Metadata To Update Later

The following surfaces are expected to require synchronized updates in later phases:

- root entry docs such as `README.md`, `CLAUDE.md`, and `AGENTS.md`
- technical docs such as `TDD.md`, `TESTING.md`, and `XCFRAMEWORK_RELEASES.md`
- product-facing metadata and release notes that currently describe the App as `GPLv3` only
- product UI strings and views that expose first-party license or source-compliance entry points

This list remains the downstream follow-up set; some entry-point documents may already reflect the selected first-party license while stable release automation and product-surface rollout continue.

## 13. Exit Criteria

This remediation plan can be considered complete only when all of the following are true:

- the unified stable release page and the edge versus stable topology are implemented as described here
- the About page exact `Source & Compliance` entry is implemented for release builds
- the shared source bundle, shared compliance manifest, and stable `XCFramework` relink kit are generated automatically
- all formal stable assets are immutable and version-bound to their tagged build
- downstream docs, product metadata, and release notes have switched to the selected licensing and distribution path
- no active canonical doc continues to describe the first-party license as `GPLv3` only

Until those conditions are met, this document remains the selected remediation plan rather than a statement that implementation is complete.
