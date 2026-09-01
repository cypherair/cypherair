# Build and Release

*The build, release, and artifact contract — the parts a reader cannot recover from the machinery itself. `ci_scripts/`, `.github/workflows/`, and `scripts/` carry their own header comments and error strings; this document never mirrors them. Test lanes: [TESTING.md](TESTING.md). The machine-parsed stage1 pin: [ARM64E_STATUS.md](ARM64E_STATUS.md).*

## 1. Stable release

**Tag-first.** Pushing an annotated, SSH-signed `cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>` tag on the release commit is the trigger. A `workflow_dispatch` is never a substitute, and lightweight or unsigned stable tags are not allowed — both Xcode Cloud and `stable-release-attest.yml` re-verify the tag object, its signature, and the commit it peels to.

**Build numbers.** `CURRENT_PROJECT_VERSION` encodes `MARKETING_VERSION` (`1.5.5` → `15500`). For macOS App Store uploads the build number must be strictly higher than the highest macOS build previously uploaded, *even when the marketing version increases* — an Apple-side fact no gate here can see.

**Draft-then-publish.** WF1 creates the stable GitHub Release as a draft with the SDK/compliance asset set already fixed; WF2 attaches only the App Store upload payloads and flips the draft to published, so "published" is atomic and published assets are immutable. **A wrong asset set is fixed with a new build number, a new stable tag, and a new release — never by replacing assets in place.**

**Two load-bearing strings.** The Xcode Cloud scripts branch on `$CI_WORKFLOW`, so the workflow names configured in App Store Connect — `PgpMobile XCFramework` (WF1) and `CypherAir Release` (WF2) — must match exactly, or be overridden with `XCFRAMEWORK_WORKFLOW_NAME` / `RELEASE_WORKFLOW_NAME`. They are coupled to the repo from outside it, where no local change can catch a rename.

**Break-glass order.** If Xcode Cloud is unavailable: the stable release for the tag must already exist, *then* archive the `CypherAir AppStore Candidate` scheme locally on a non-beta macOS and upload via Transporter. Nothing stops an archive from starting too early; the ordering is the human's to hold.

**Internal TestFlight is a different path.** Day-to-day uploads archive the plain `CypherAir` scheme, which requires no stable release; such a build is never the formal App Store candidate.

**Two human-only checks** before promoting a candidate — nothing in the repo can decide either: the macOS build-number monotonicity above, and whether the pinned arm64e stage1 tag is the intended input for *this* release. Every other candidate condition is machine-gated.

## 2. Published artifacts

`PgpMobile.xcframework` reaches downstream consumers on three channels: **edge** (every push to `main`), **drill** (manual validation runs from non-`main` refs), and **stable** (the release-grade binary attached to each app stable release). The consumption rule is the consumer's to hold: **a drill artifact is never discovered or consumed as if it were edge.** Restored artifacts and downloaded assets are never committed.

## 3. arm64e toolchain contract

- **Device slices ship `arm64` alongside `arm64e`** because Apple distribution requires an `arm64` slice whenever a bundle contains `arm64e`.
- **`arm64e` builds use stable Cargo with `RUSTC` pointed at the pinned stage1 compiler and its prebuilt std payloads — never nightly Cargo, never `-Zbuild-std`.** The repo has no `rust-toolchain.toml`; every ordinary validation names its toolchain (`cargo +stable`).
- **App-side Rust or UniFFI changes never require a new stage1 prerelease** — only a change to the Rust compiler fork itself does. The opposite assumption costs a publication cycle.
- The pinned tag and the never-`latest` red line live in [ARM64E_STATUS.md](ARM64E_STATUS.md); the App Store candidate gate parses that file against `third_party/arm64e-stage1-toolchain.pin.json`.

**Re-pin rule.** A new stage1 prerelease becomes the official input only when every pinned location rotates in the same PR. Two parts of a rotation are not derivable from the scripts: refresh every per-asset SHA-256 and byte size for both host triples, confirmed against a real download rather than an API-reported digest, and run `scripts/verify_arm64e_stage1_release.sh` before the pin lands; and revisit the semantic constants in `scripts/validate_arm64e_stage1_toolchain.py` only when the new release changes a semantic contract, not when it merely rotates the build identity — the prefix names the publishing family and carries no version, and the Rust series is pinned solely by the stable-base constants.

## 4. Owned carry chains

`pgp-mobile/Cargo.toml` patches `openssl-src` to the `cypherair/openssl-src-rs` fork, whose submodule points at the `cypherair/openssl` fork carrying the Apple arm64e target definitions — the entire reason the chain exists. `Cargo.lock`, never prose, is the truth for the current heads; the branches stay downstream until equivalent arm64e support lands upstream. The compiler fork (`cypherair/rust`, plus its LLVM work) has no output-time `ptrauth` operand-bundle stripper — each layer enforces its own contract — and production stage1 forces the unmodified bundled-LLVM gitlink.

## 5. FFI artifact shape

`PgpMobile.xcframework` is a **static-library** XCFramework built locally from the pinned stage1: static linking is what preserves the single-binary MIE posture. The accepted cost is that the module map and header search paths that let Swift see the C FFI layer are repeated in every build configuration rather than travelling inside the artifact. **The generated UniFFI outputs are build products and are never committed**; they ride inside the bundle under `cypherair-generated-bindings/`, and `scripts/restore_generated_bindings.sh` is the only thing that writes them into a checkout. Reopen the decision if a second consumer must link PgpMobile, it is vended as a SwiftPM binary target, or a UniFFI release beyond the pinned 0.32.x changes the generated layout.

## 6. The sync contract

Rust changes under `pgp-mobile/src` do **not** refresh what Xcode links. Three build inputs are never produced by a Swift build and are not in git — the XCFramework with its build manifest, the generated UniFFI outputs carried inside it, and the pinned `SQLCipher.xcframework` — so **a fresh clone runs the sync before Xcode can build at all**:

```bash
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release
scripts/restore_sqlcipher_xcframework.sh
```

**Staleness is machine-checked, not remembered.** Every Xcode build re-hashes the crate inputs, the packaged slices, and the generated bindings against the fingerprint the sync recorded, and fails with the command that fixes it. The gate is content-based, so **any** edit to a fingerprinted input — comments included — requires the sync, and a hand-edit to the generated Swift is a build failure: **never hand-edit generated bindings; rerun the sync**. `PgpMobileSourceInputs.xcfilelist` is generated but tracked, and is committed whenever it changes.

**Stale-artifact symptom:** the Rust tests show the new behavior but the Swift/FFI tests still show the old one, or new UniFFI symbols are missing at link time. Suspect a stale artifact or stale bindings before suspecting Swift source. A stale target-specific `libpgp_mobile.dylib` beside the release archives can shadow the static archive that was meant to be linked.

To move the SQLCipher pin, publish a new stable immutable release from `cypherair/sqlcipher-xcframework` first, then rotate the pin file, the notices, and the tests together.
