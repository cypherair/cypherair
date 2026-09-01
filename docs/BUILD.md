# Build and Release

*The build, release, and artifact contract — the parts a reader cannot recover from the machinery itself. `ci_scripts/`, `.github/workflows/`, and `scripts/` each carry their own header comments and error strings; this document never mirrors them. Test lanes and plans: [TESTING.md](TESTING.md). The machine-parsed stage1 pin: [ARM64E_STATUS.md](ARM64E_STATUS.md).*

## 1. Stable release

**Tag-first.** Pushing an annotated, SSH-signed `cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>` tag on the release commit is the trigger. A `workflow_dispatch` is never a substitute for it, and lightweight or unsigned stable tags are not allowed — both Xcode Cloud and `stable-release-attest.yml` re-verify the tag object, its signature, and the commit it peels to.

**Build numbers.** `CURRENT_PROJECT_VERSION` encodes `MARKETING_VERSION` in this project (`1.5.5` → `15500`). For macOS App Store uploads the build number must be strictly higher than the highest macOS build previously uploaded, *even when the marketing version increases* — an Apple-side fact no gate here can see.

**Draft-then-publish.** WF1 creates the stable GitHub Release as a draft with the SDK/compliance asset set already fixed; WF2 attaches only the App Store upload payloads and flips the draft to published. That is why "published" is atomic and why published assets are immutable. **A wrong asset set is fixed with a new build number, a new stable tag, and a new release — never by replacing assets in place.**

**Two load-bearing strings.** The Xcode Cloud scripts branch on `$CI_WORKFLOW`, so the workflow names configured in App Store Connect — `PgpMobile XCFramework` (WF1) and `CypherAir Release` (WF2) — must match exactly, or be overridden with `XCFRAMEWORK_WORKFLOW_NAME` / `RELEASE_WORKFLOW_NAME`. They are coupled to the repo from outside it, where no local change can catch a rename.

**Break-glass order.** If Xcode Cloud is unavailable: the stable release for the tag must already exist, *then* archive the `CypherAir AppStore Candidate` scheme locally on a non-beta macOS and upload via Transporter. Nothing stops an archive from starting too early; the validator can only fail it afterwards, so the ordering is the human's to hold.

**Internal TestFlight is a different path.** Day-to-day and exploratory uploads archive the plain `CypherAir` scheme, which requires no stable release (`SOURCE_COMPLIANCE_REQUIRE_STABLE_RELEASE = NO`; only the candidate scheme sets it `YES`). Such a build is never the formal App Store candidate.

**Two human-only checks** before promoting a candidate — nothing in the repo can decide either: the macOS build-number monotonicity above, and whether the pinned arm64e stage1 tag is the intended input for *this* release. Every other candidate condition is machine-gated.

## 2. Published artifacts

`PgpMobile.xcframework` reaches downstream consumers on three channels: **edge** (every push to `main`), **drill** (manual validation runs from non-`main` refs), and **stable** (the release-grade binary attached to each app stable release). The producing workflow enforces the tag prefixes; the consumption rule is the consumer's to hold: **a drill artifact is never discovered or consumed as if it were edge.**

Every bundle carries `cypherair-source-fingerprint.json`, which the Xcode build phase verifies against the checkout it is linked into; a bundle without it fails closed until it is rebuilt from source.

The SDK/compliance asset set is fixed by WF1 and re-verified on publication; WF2 adds the three App Store upload payloads. Release assets are attested per channel, the ready-made verification command is emitted into the release notes, and the attestation covers the build manifest too, not just the zip. SQLCipher is a separate pinned external dependency with its own restore and verification path (§6); restored artifacts and downloaded assets are never committed.

## 3. arm64e toolchain contract

- **Device slices ship `arm64` alongside `arm64e`** because Apple distribution requires an `arm64` slice whenever a bundle contains `arm64e`. It is a distribution requirement, not a build convenience.
- **`arm64e` builds use stable Cargo with `RUSTC` pointed at the pinned stage1 compiler and its prebuilt std payloads — never nightly Cargo, never `-Zbuild-std`.**
- **The repo has no `rust-toolchain.toml`.** Nothing selects a toolchain implicitly; every ordinary validation names it (`cargo +stable`).
- **App-side Rust or UniFFI changes never require a new stage1 prerelease** — only a change to the Rust compiler fork itself does. The opposite assumption costs a publication cycle.
- The pinned tag and the never-`latest` red line live in [ARM64E_STATUS.md](ARM64E_STATUS.md); the App Store candidate gate parses that file against `third_party/arm64e-stage1-toolchain.pin.json`.

**Re-pin rule.** A new stage1 prerelease becomes the official input only when every pinned location rotates in the same PR. Two parts of a rotation are not derivable from the scripts:

- Refresh **every** per-asset SHA-256 and byte size for **both** host triples. Take them from `gh api`, then confirm them against a real download — an API-reported digest is not evidence on its own — and run `scripts/verify_arm64e_stage1_release.sh` so the attestation chain is proven before the pin lands.
- Revisit the semantic constants in `scripts/validate_arm64e_stage1_toolchain.py` (tag-family prefix, stable base, schema, bundled-LLVM gitlink and version) **only when the new release changes a semantic contract**, not when it merely rotates the build identity. Telling those two cases apart is the judgment the rule exists for. The prefix names the publishing family and carries no version: the Rust series is pinned solely by the stable-base constants, which is the stronger binding — a prefix can only reject a foreign tag, while the base commit rejects the wrong compiler.

## 4. Owned carry chains

`pgp-mobile/Cargo.toml` patches `openssl-src` to the `cypherair/openssl-src-rs` fork, whose submodule points at the `cypherair/openssl` fork carrying the Apple arm64e target definitions — that is the entire reason the chain exists. `Cargo.lock`, never prose, is the machine-checked truth for the current heads. The branches stay downstream until equivalent arm64e support lands upstream.

The compiler fork (`cypherair/rust`, plus the LLVM work it depends on) carries its own rules:

- **No output-time `ptrauth` operand-bundle stripper.** Each layer enforces its own contract instead: Rust never attaches a `ptrauth` bundle to `callbr`, InstCombine guards the direct-callee case, and LLVM's verifier defines that shape as invalid.
- **Production stage1 forces the unmodified bundled-LLVM gitlink.**

## 5. FFI artifact shape

`PgpMobile.xcframework` is a **static-library** XCFramework, built locally from the pinned stage1. **Static linking is what preserves the single-binary MIE posture** — no dynamic or embedded runtime framework. The cost it accepts is real and known: the module map and header search paths that let Swift see the C FFI layer are repeated in every build configuration of the project rather than travelling inside the artifact.

**The generated UniFFI outputs are build products and are never committed.** The bundle is where they live — `PgpMobile.xcframework/cypherair-generated-bindings/` carries them at the repository-relative paths they are placed at, so they travel every path the artifact already takes (`ditto -c -k` of the bundle, the CI artifact, the release asset) and reach the consumers that link a packaged build instead of running the sync. `scripts/restore_generated_bindings.sh` places them, and is the only thing that writes them into a checkout.

Reopen the decision when one of these becomes true: a second consumer needs to link PgpMobile without hand-copying the per-configuration settings; PgpMobile is vended as a SwiftPM binary target; a UniFFI release beyond the pinned 0.32.x changes the generated module name, layout, or packaging path; or a future Xcode toolchain changes how static-library XCFrameworks or global `-fmodule-map-file` resolution behave.

## 6. The sync contract

Rust changes under `pgp-mobile/src` do **not** automatically refresh what Xcode links. The project consumes three build inputs a Swift build never produces, none of which are in git — **a fresh clone runs the sync below before Xcode can build at all**:

- `PgpMobile.xcframework` (locally generated) plus `PgpMobile.arm64e-build-manifest.json`
- the generated UniFFI outputs, `Sources/PgpMobile/pgp_mobile.swift` and `bindings/`, which ride inside the bundle (§5); the sync places them, and a checkout that restores a packaged artifact instead runs `scripts/restore_generated_bindings.sh`
- `SQLCipher.xcframework` (restored from the pinned external release) plus its manifest, privacy file, and release record

**Staleness is machine-checked, not remembered.** A successful sync records into `PgpMobile.xcframework/cypherair-source-fingerprint.json`: the crate inputs it consumed, the SHA-256 of each packaged `libpgp_mobile.a`, and the SHA-256 of each generated binding. Every Xcode build re-hashes all three and fails with the command that fixes it: the sync when the crate, the slices, or the carried bindings no longer match, and `scripts/restore_generated_bindings.sh` when the copies in the checkout are not the ones the bundle carries — which is also what turns a hand-edit to the generated Swift into a build failure. The gate is content-based, so **any** edit to a fingerprinted input — comments included — requires the sync. Because the fingerprint lives inside the bundle it survives `ditto`, so an XCFramework restored from a CI artifact or a release asset is checked the same way.

**`PgpMobileSourceInputs.xcfilelist` is generated but tracked, and committed whenever it changes.** It is the exact list of everything the check re-hashes, because the sandboxed build phase may read only what it declares and the check never walks the tree. It stays at the repository root, with its contents pointing into the ignored artifact, because a list inside the bundle would replace the phase's actionable missing-artifact error with a file-list load failure.

```bash
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release
```

Force-download matches the GitHub Actions path: it consumes the pinned stage1 prerelease instead of trusting local rustup state. (A plain build ignores rustup-linked arm64e toolchains and downloads the pin anyway.) The sync refreshes the stable `arm64` archives, builds the `arm64e` archives with the stage1 compiler, regenerates the bindings from an `arm64e-apple-darwin` host dylib and whitespace-normalizes them — **never hand-edit generated bindings; rerun the sync** — recreates the XCFramework, and writes the build manifest.

| Change type | Run |
|---|---|
| `Cargo.lock` dependency update | audit → Rust tests → sync → unit plan |
| Rust-backed behavior change | Rust tests → sync → unit plan → visionOS probe |
| UniFFI surface / bindings / packaging change | Rust tests → sync → unit plan → visionOS probe |

**Stale-artifact symptom:** the Rust tests show the new behavior but the Swift/FFI tests still show the old one, or new UniFFI symbols are missing at link time. Suspect a stale `PgpMobile.xcframework` or stale generated bindings before suspecting Swift source.

Bindgen run by hand must be invoked from `pgp-mobile/`, because the repo root has no `Cargo.toml`; its output is for inspection only, since only the full sync places bindings the fingerprint gate will vouch for.

After a sync, `cargo clean --manifest-path pgp-mobile/Cargo.toml` is safe — the per-target release archives are intermediates, not Xcode link inputs. Target-specific `libpgp_mobile.dylib` files must not linger beside them: a stale dylib can shadow the static archive that was meant to be linked.

**SQLCipher is restored, not built.**

```bash
scripts/restore_sqlcipher_xcframework.sh                        # local
scripts/restore_sqlcipher_xcframework.sh --require-attestation  # CI / Xcode Cloud
```

To move the pin, publish a new stable immutable release from `cypherair/sqlcipher-xcframework` first, then rotate the pin file, the notices, and the tests together.
