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

The App Store candidate gate trusts a commit-bound verdict file instead of re-querying GitHub. Why that is safe rather than a shortcut is documented where it is enforced — the `load_bound_candidate_verdict` docstring in `scripts/validate_app_store_candidate_release.py`.

## 2. Published artifacts

`PgpMobile.xcframework` reaches downstream consumers on three channels: **edge** (every push to `main`), **drill** (manual validation runs from non-`main` refs), and **stable** (the release-grade binary attached to each app stable release). The producing workflow enforces the tag prefixes; the consumption rule is the consumer's to hold: **a drill artifact is never discovered or consumed as if it were edge.**

Every bundle built after the source-fingerprint gate landed carries `cypherair-source-fingerprint.json`, which the Xcode build phase verifies against the checkout it is linked into; assets published before it do not, so re-archiving one of those older bundles fails closed until it is rebuilt from source.

The SDK/compliance asset set is fixed by WF1 and enumerated in the env block of `.github/workflows/stable-release-attest.yml`, which re-verifies exactly that set on `release.published`; WF2 adds the three `CypherAir-*-AppStore.*` upload payloads. Attestation differs by channel, which is exactly the `--signer-workflow` a verifier must pass: edge bundles are attested in-run by `xcframework-edge-release.yml`, which emits the ready-made `gh attestation verify` command into its own release notes; stable ones are attested after publication by `stable-release-attest.yml`. Either way the attestation covers `PgpMobile.arm64e-build-manifest.json` too, not just the zip. SQLCipher is a separate pinned external dependency with its own restore and verification path (§6); restored artifacts and downloaded assets are never committed.

## 3. arm64e toolchain contract

- **Device slices ship `arm64` alongside `arm64e`** because Apple distribution requires an `arm64` slice whenever a bundle contains `arm64e`. It is a distribution requirement, not a build convenience.
- **`arm64e` builds use stable Cargo with `RUSTC` pointed at the pinned stage1 compiler and its prebuilt std payloads — never nightly Cargo, never `-Zbuild-std`.**
- **The repo has no `rust-toolchain.toml`.** Nothing selects a toolchain implicitly; every ordinary validation names it (`cargo +stable`). An absent file cannot be discovered by reading the tree, so it is stated here.
- **App-side Rust or UniFFI changes never require a new stage1 prerelease** — only a change to the Rust compiler fork itself does. The opposite assumption costs a publication cycle.
- The pinned tag and the never-`latest` red line live in [ARM64E_STATUS.md](ARM64E_STATUS.md); the App Store candidate gate parses that file against `third_party/arm64e-stage1-toolchain.pin.json`.

**Re-pin rule.** A new stage1 prerelease becomes the official input only when every pinned location rotates in the same PR — `.claude/skills/repin-arm64e` enumerates them. Two parts of a rotation are not derivable from the scripts:

- Refresh **every** per-asset SHA-256 and byte size for **both** host triples. Take them from `gh api`, then confirm them against a real download — an API-reported digest is not evidence on its own — and run `scripts/verify_arm64e_stage1_release.sh` so the attestation chain is proven before the pin lands.
- Revisit the semantic constants in `scripts/validate_arm64e_stage1_toolchain.py` (tag-family prefix, stable base, schema, bundled-LLVM gitlink and version) **only when the new release changes a semantic contract**, not when it merely rotates the build identity. Telling those two cases apart is the judgment the rule exists for. The prefix names the publishing family and carries no version: the Rust series is pinned solely by the stable-base constants, which is the stronger binding — a prefix can only reject a foreign tag, while the base commit rejects the wrong compiler.

## 4. Owned carry chains

`pgp-mobile/Cargo.toml` patches `openssl-src` to the `cypherair/openssl-src-rs` fork, whose submodule points at the `cypherair/openssl` fork carrying the Apple arm64e target definitions — that is the entire reason the chain exists. `Cargo.lock`, never prose, is the machine-checked truth for the current heads. The branches stay downstream until equivalent arm64e support lands upstream.

The compiler fork (`cypherair/rust`, plus the LLVM work it depends on) carries its own rules:

- **The ownership test is who decides the behavior**, not whether a thin C API shim happens to live in `llvm-wrapper/`. Rust owns Apple target specifications, the default arm64e feature and ABI model, ABI-mandatory feature diagnostics, and frontend emission of authenticated calls and of function pointers used as data. LLVM owns IR legality for `ptrauth` operand bundles, whether optimization may expose a direct callee while retaining one, and AArch64/Mach-O lowering. Rust's LLVM C API shims express frontend decisions; they never perform optimizer repair or serialized-output rewriting.
- **The output-time `ptrauth` operand-bundle stripper is gone and must not return** — not relocated into another wrapper file, not hidden as a patch file. Dropping only the final strip/keep pair would silently resurrect an earlier, broader stripper. Each layer enforces its own contract instead: Rust never attaches a `ptrauth` bundle to `callbr`, InstCombine guards the direct-callee case, and LLVM's verifier defines that shape as invalid.
- **Production stage1 forces the unmodified bundled-LLVM gitlink.** Neither the Rust gitlink nor `.gitmodules` points at a CypherAir LLVM fork, and the LLVM replay lane stays local-only.
- **Rebase playbook.** Start at the exact stable tag and replay the logical order: target definition, feature/ABI model, frontend metadata and emission, diagnostics, bootstrap, tests, then fork CI. Expect conflicts to concentrate in `rustc_codegen_llvm`, its thin C API surface in `llvm-wrapper/`, and the Apple target definitions. **Drop a carry commit in the same rebase that first contains its upstream equivalent; never retain a no-op copy for history.**
- **A future stage1 candidate re-proves, before publication and re-pin:** `x.py check compiler/rustc_codegen_ssa compiler/rustc_codegen_llvm --stage 1` on the candidate; the `callbr` codegen regression on all four Apple revisions and the serialized-output regression across the LLVM IR, bitcode, and embedded-bitcode paths against the default bundled LLVM; valid commit signatures and `git diff --check` across the whole carry range; owned-fork validation plus a stage1 dry run on both host triples; then the post-publication readback (release immutability, tag-to-commit binding, per-asset provenance, packaged LLVM identity) and consumer acceptance per the re-pin rule.
- **Publication is opt-in.** The fork's stage1 workflow forces `create_release=false` for branch pushes and schedules and defaults it false on manual dispatch; every default is false. Opening an upstream Rust or LLVM pull request is outside this work and needs a new explicit maintainer decision.

## 5. FFI artifact shape

`PgpMobile.xcframework` is a **static-library** XCFramework, built locally from the pinned stage1, and the UniFFI outputs are tracked in the tree. **That shape is deliberate, not accidental** — Apple-supported, idiomatic for UniFFI/Rust static linking, and correct for a single first-party consumer. The cost it accepts is real and known: the module map and header search paths that let Swift see the C FFI layer are repeated in every build configuration of the project rather than travelling inside the artifact.

Five generated files are tracked, as two byte-identical pairs plus a header, and only one file of each pair is live:

- `Sources/PgpMobile/pgp_mobile.swift` is the compile source; `bindings/pgp_mobile.swift` is its staging copy.
- `bindings/module.modulemap` is what Xcode reads through `-fmodule-map-file`; `bindings/pgp_mobileFFI.modulemap` has **no consumer at all** — the build copies its scratch counterpart into each slice and merely syncs the tracked file.
- `bindings/pgp_mobileFFI.h` is the fifth.

Invariants that survive any future reshape: static linking stays (no dynamic or embedded runtime framework — this is what preserves the single-binary MIE posture); the generated Swift stays compiled as app source; any reshape keeps every gate green — clean-checkout local build, GitHub CI, Xcode Cloud WF1/WF2, stable releases — and updates the release-asset contract (names, manifest, attestation, relink-kit, source-compliance surface) in the same change. Out of bounds: splitting `pgp-mobile/` into its own repository, and touching Contacts SQLCipher storage.

Reopen the decision when one of these becomes true: a second consumer needs to link PgpMobile without hand-copying the per-configuration settings; PgpMobile is vended as a SwiftPM binary target; a UniFFI release beyond the pinned 0.32.x changes the generated module name, layout, or packaging path; generated-output friction crosses a threshold (recurring merge conflicts, the byte-identical copies drifting, or clean checkouts needing a mandatory bindgen bootstrap anyway); or a future Xcode toolchain changes how static-library XCFrameworks or global `-fmodule-map-file` resolution behave.

## 6. The sync contract

Rust changes under `pgp-mobile/src` do **not** automatically refresh what Xcode links. The project consumes three artifacts a Swift build never produces:

- `PgpMobile.xcframework` (git-ignored, locally generated) plus `PgpMobile.arm64e-build-manifest.json`
- `bindings/module.modulemap` plus the generated `Sources/PgpMobile/pgp_mobile.swift`
- `SQLCipher.xcframework` (git-ignored, restored from the pinned external release) plus its manifest, privacy file, and release record

**Staleness is machine-checked, not remembered.** A successful sync records the crate inputs it consumed — the non-test crate sources, `Cargo.toml`/`Cargo.lock`, `build.rs`, `uniffi-bindgen.rs`, both build scripts, and the stage1 pin (the tracked `PgpMobileSourceInputs.xcfilelist` is the exact list) — and the SHA-256 of each packaged `libpgp_mobile.a`, into `PgpMobile.xcframework/cypherair-source-fingerprint.json`, and refreshes the tracked `PgpMobileSourceInputs.xcfilelist` that the sandboxed build phase declares — the input list is where a *newly added* crate file surfaces, because the check re-hashes exactly the recorded set and never walks the tree. Every Xcode build re-hashes both and fails with the sync command when either no longer matches. The gate is content-based, so **any** edit to a fingerprinted input — comments included — requires the sync. `pgp-mobile/Cargo.lock` is one of those inputs: even a lockfile-only bump needs the audit, the Rust tests, and a full sync before Swift validation, so the local artifacts are built from the lockfile being submitted. Because the fingerprint lives inside the bundle it survives `ditto`, so an XCFramework restored from a CI artifact or a release asset is checked the same way. Commit the regenerated bindings and `PgpMobileSourceInputs.xcfilelist`; never commit the ignored XCFramework directories.

```bash
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release
```

Force-download matches the GitHub Actions path: it consumes the pinned stage1 prerelease instead of trusting local rustup state. (A plain build ignores rustup-linked arm64e toolchains and downloads the pin anyway, and `latest` is rejected outright.) The sync refreshes the stable `arm64` archives, builds the `arm64e` archives with the stage1 compiler, regenerates the bindings from an `arm64e-apple-darwin` host dylib and whitespace-normalizes them — **never hand-edit generated bindings; rerun the sync** — recreates the XCFramework, and writes the build manifest. Whether a given Rust change needs the rebuild at all is `.claude/skills/rust-sync`.

| Change type | Run |
|---|---|
| `Cargo.lock` dependency update | audit → Rust tests → sync → unit plan |
| Rust-backed behavior change | Rust tests → sync → unit plan → visionOS probe |
| UniFFI surface / bindings / packaging change | Rust tests → sync → unit plan → visionOS probe |

**Stale-artifact symptom:** the Rust tests show the new behavior but the Swift/FFI tests still show the old one, or new UniFFI symbols are missing at link time. Suspect a stale `PgpMobile.xcframework` or stale generated bindings before suspecting Swift source.

Manual bindgen runs from `pgp-mobile/` — the repo root has no `Cargo.toml`:

```bash
cd pgp-mobile
cargo +stable run --release --bin uniffi-bindgen generate \
    --library target/release/libpgp_mobile.dylib \
    --language swift --out-dir ../bindings
```

After a sync, `cargo clean --manifest-path pgp-mobile/Cargo.toml` is safe — the per-target release archives are intermediates, not Xcode link inputs. Target-specific `libpgp_mobile.dylib` files must not linger beside them: a stale dylib from an older direct-link flow can shadow the static archive that was meant to be linked.

**SQLCipher is restored, not built.** The script verifies every pinned release asset's exact byte size and SHA-256 before interpreting it, checks the bundle's versions, slices, and headers, and smoke-tests the restored library (including exact `SQLITE_NOTADB` rejection of a wrong key):

```bash
scripts/restore_sqlcipher_xcframework.sh                        # local
scripts/restore_sqlcipher_xcframework.sh --require-attestation  # CI / Xcode Cloud
```

To move the pin, publish a new stable immutable release from `cypherair/sqlcipher-xcframework` first, then rotate the pin file, the notices, and the tests together.
