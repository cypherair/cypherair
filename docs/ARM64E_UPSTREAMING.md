# CypherAir arm64e Toolchain Upstreaming Plan

> Status: Active Rust 1.97 / LLVM ownership split. The corrected stable197
> stage1 is selected on the CypherAir production re-pin branch. This document
> is not the production pin source of truth.
> Purpose: Record which arm64e changes belong in Rust, which belong in LLVM,
> and how the owned-fork carry is validated, published, and consumed.
> Source of truth for the production stage1 pin:
> [ARM64E_STATUS.md](ARM64E_STATUS.md).
> Scope boundary: The OpenSSL carry chain remains owned by
> [ARM64E_STATUS.md](ARM64E_STATUS.md) and is out of scope here.
> Update triggers: A Rust or LLVM rebase, an upstream merge that retires a
> carried change, a change to the fork topology, or an approved production
> re-pin.
> Last reviewed: 2026-07-15.

## 1. Current Decision

Issue #622 is being carried as a structural update rather than a mechanical
Rust 1.96-to-1.97 rebase:

- Rust-owned behavior remains in `cypherair/rust`.
- LLVM-owned optimizer and verifier fixes, plus object-format regression
  coverage for existing AArch64/Mach-O lowering, live and are tested in
  `cypherair/llvm-project-upstream`.
- The Rust output-time `ptrauth` operand-bundle stripper is removed. It is not
  moved into another Rust wrapper file and is not represented by a patch file
  hidden in the Rust repository.
- A semantically equivalent LLVM series is replayed locally onto Rust's pinned
  LLVM revision to test compatibility. That replay stays local-only under the
  LLVM workspace fork-topology policy.
- No upstream Rust or LLVM pull request is part of this work. The Rust stage1
  prerelease and CypherAir production re-pin were separately approved for the
  CypherAir-owned repositories.

Decision update (2026-07-13): this supersedes the 2026-07-12 issue comment only
in its conclusion to retain the Rust serialized-output stripper. Reconstructing
the 1.97 series showed that stripping was entangled with earlier frontend
commits and could be removed completely once Rust's frontend emission was
narrowed and regression-covered. The no-consumed-fork decision remains:
Rust's `src/llvm-project` is not repointed, no second Rust-LLVM fork is
introduced, and the canonical LLVM patches are replayed local-only for
compatibility. No upstream pull request, release, or production re-pin was
authorized by the ownership decision itself; the owned-fork publication and
preparation of the CypherAir re-pin were subsequently approved and executed as
separate steps.

The production re-pin branch uses the stable197 stage1 tag recorded in
[ARM64E_STATUS.md](ARM64E_STATUS.md); the app's main line retains its predecessor
until that pull request passes all gates and merges. Candidate validation alone
does not change the pin: publication, provenance readback, and the explicit
re-pin remain separate gates.

## 2. Repository And Branch State

Before rebuilding the candidate, the owned fork mainlines were synchronized
with their read-only upstreams. These are the 2026-07-12 synchronization
snapshots, not the Rust stable-tag or LLVM work-branch bases:

| Repository line | Synchronized base | Candidate branch |
| --- | --- | --- |
| `cypherair/rust` | `rust-lang/rust` `main` at `d39561c2d2b55985d3b6331cc52403e038e7fc8b` | `carry/cypherair-arm64e-toolchain-stable-1.97` |
| `cypherair/llvm-project-upstream` | `llvm/llvm-project` `main` at `171ba71128eec9f1859bb995c597dcff296ee730` | `cypherair-arm64e-ptrauth-canonical` |

The Rust 1.97 carry is based exactly on the `1.97.0` tag commit
`2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`. Its twelve-commit signed logical
compiler/CI series ends at `c3a04d4e4ff987b59aacb8d42b66c853db74c02a`.
The first signed publication tip was
`027700f412b05d0148e6eb4e865d618582cbb63f`; its additional commit fixed the
owned-fork workflow's attestation source-ref comparison. The final signed
publication tip is `c405db836704af8307c5c41d6dbdc92068dec0d6`. Its three
intermediate/final workflow commits force source-built bundled LLVM, make the
packaged LLVM identity independently attestable, canonicalize the manifest
source ref, and allow the longer Intel source build to finish. They do not
change Rust compiler-source behavior.

The issue's stable-1.96 pre-step is also resolved: after fetching the owned
Rust fork, `carry/cypherair-arm64e-toolchain-stable-1.96` includes the pinned
source commit `abeb8459f2b459704c1d698c01d8b8c0df8ffffd`. The earlier discrepancy
was a stale local mirror, not a missing carry commit.

## 3. Ownership Boundary

The durable ownership test is who decides the behavior, not whether a thin C
API shim happens to live in `llvm-wrapper/`.

| Rust owns | LLVM owns |
| --- | --- |
| Apple target specifications, including `arm64e-apple-visionos` | Whether optimization may expose a direct callee while retaining a `ptrauth` operand bundle |
| Default arm64e target features and ABI predicates | IR legality for `ptrauth` operand bundles on `callbr` |
| ABI-mandatory feature diagnostics | AArch64/Mach-O lowering and authenticated relocation behavior |
| Clang-compatible ptrauth module flags and entry-point attributes | Focused optimizer, verifier, codegen, and object-format regression tests |
| Frontend emission of authenticated indirect calls and invokes | |
| Frontend `ConstantPtrAuth` emission for function pointers used as data | |
| Avoiding `ptrauth` bundles on inline assembly and `callbr` | |
| Rust bootstrap robustness, compiler tests, and owned-fork CI | |

Rust still uses small LLVM C API shims for APIs that LLVM's public C interface
does not expose. Those shims express Rust frontend decisions; they do not
perform optimizer repair or serialized-output rewriting.

## 4. Rust 1.97 Carry

The former 29-patch stable-1.96 history was reconstructed as twelve signed,
logical compiler/carry commits on Rust 1.97. The history was rebuilt so the
output stripper does not exist at any intermediate commit. Four later signed
commits harden publication, packaged LLVM provenance, canonical source
identity, and the Intel source-build timeout.

| Commit | Purpose | Owner |
| --- | --- | --- |
| `f6f0b28920eb` | Add the Apple arm64e visionOS target | Rust |
| `acd9bbd79335` | Model default Apple pointer-authentication features | Rust |
| `69be3054de1f` | Emit Clang-compatible pointer-authentication metadata | Rust |
| `701aa4548eb4` | Authenticate indirect function calls and avoid unsupported `callbr` bundles | Rust |
| `3026427dab1e` | Authenticate function pointers used as data | Rust |
| `8d2ee46cf833` | Reject incompatible pointer-authentication flag overrides | Rust |
| `3d4d7458ed47` | Reject disabling ABI-mandatory pointer-authentication features | Rust |
| `def17bd149bd` | Handle shallow-fork upstream detection in bootstrap | Rust |
| `ed9539c2e21d` | Add owned-fork arm64e validation CI | Fork CI |
| `23f3f80209af` | Cover visionOS pointer-authentication integration | Rust |
| `92e1dbfed5a2` | Carry safe, opt-in stage1 workflows for stable 1.97 | Fork CI |
| `c3a04d4e4ff9` | Close frontend pointer-authentication IR emission gaps | Rust |
| `027700f412b0` | Verify publication attestations against the canonical GitHub source ref | Fork CI |
| `9e0e9424851b` | Force and attest the bundled LLVM gitlink used by packaged stage1 tools | Fork CI |
| `97f3fa184d22` | Canonicalize the stage1 manifest's owned-branch source ref | Fork CI |
| `c405db836704` | Allow the source-built bundled LLVM lane to finish on Intel | Fork CI |

The old Mach-O metadata-subtype patch is absent because Rust 1.97 already
contains the equivalent upstream change (`8c029d5f456775294204a8c28b24d6ba19865d79`).
The LLVM gitlink remains Rust 1.97's upstream value
`08c84e69a84d95936296dfcab0e38b34100725d5`, and `.gitmodules` remains
unchanged.

### Why the old stripper is not retained

The stable-1.96 history mixed frontend emission and serialized-output repair
across several commits. Dropping only the final strip/keep pair would have
silently resurrected an earlier, broader stripper. Reconstructing the logical
series avoids that trap: no `PtrauthUtils`, strip FFI, serialization hook, or
SSA strip state is introduced anywhere in the 1.97 candidate range.

Rust now avoids attaching a `ptrauth` bundle to `callbr`, while LLVM defines
that unsupported shape as verifier-invalid. LLVM's InstCombine guard prevents
the separate case where optimization exposes a direct callee but preserves an
indirect-call-only bundle. Each layer therefore enforces its own contract.

## 5. Canonical LLVM Candidate

The canonical branch is based on synchronized LLVM main and contains three
signed commits:

| Commit | Change |
| --- | --- |
| `cde471330089` | InstCombine refuses to form a direct call that retains a `ptrauth` operand bundle |
| `ec9476ea9f6e` | The verifier rejects `ptrauth` operand bundles on `callbr` |
| `35721a3b9819` | AArch64 tests `ConstantPtrAuth` function-pointer Mach-O authenticated relocations |

The branch is pushed only to
`cypherair/llvm-project-upstream:cypherair-arm64e-ptrauth-canonical`. That
repository was re-verified as a true fork whose immediate parent is
`llvm/llvm-project`. Canonical upstream is fetch-only locally, and no upstream
pull request has been opened.

A semantically equivalent three-patch series is replayed, without publishing,
on the Rust-consumed LLVM line. Small diff-size differences from the canonical
series are version-context adjustments rather than different behavior:

- base: `08c84e69a84d95936296dfcab0e38b34100725d5`
- local branch: `cypherair-arm64e-ptrauth-rust-llvm`
- replay tip: `3fb59b3c7`

This lane is compatibility evidence only. Its fresh LLVM 22.1.6 optimized
assertions build passed the five focused tests and the external-consumption
component/tool readiness checks. Production stage1 builds force source-built
bundled LLVM at the unmodified
`08c84e69a84d95936296dfcab0e38b34100725d5` gitlink; neither the Rust gitlink
nor `.gitmodules` points to a CypherAir LLVM fork. A Rust stage1 compiler check
against the external replay also passed, as recorded below.

## 6. Validation Status

Completed validation, publication, and readback evidence:

- `x.py check compiler/rustc_codegen_ssa compiler/rustc_codegen_llvm --stage 1`
  passed on the Rust 1.97 candidate.
- The Rust `callbr` codegen regression passed all four revisions: macOS, iOS,
  tvOS, and visionOS.
- The serialized-output regression passed against Rust 1.97's default bundled
  LLVM 22.1.6, including LLVM IR, bitcode, and embedded-bitcode paths.
- `x.py fmt --check` passed for 6,874 files using the available nightly
  rustfmt with a temporary bootstrap configuration. The ordinary tidy entry
  point was unavailable only because the downloaded stage0 lacked rustfmt.
- All sixteen Rust-branch commits and all three canonical LLVM commits have
  valid SSH signatures; both ranges pass `git diff --check`.
- The canonical LLVM 23.0.0git optimized assertions build passed five focused
  lit tests plus direct InstCombine, verifier, `llc`, and Mach-O relocation
  checks. The suite covers `Transforms/InstCombine/ptrauth-call.ll`, both
  `callbr` tests, `CodeGen/AArch64/ptrauth-fnptr-data-macho-reloc.ll`, and the
  neighboring verifier operand-bundle coverage.
- The local Rust-pinned LLVM 22.1.6 optimized assertions replay passed the same
  five-file suite, direct InstCombine checks, and all LLVM archive/tool
  readiness checks needed by Rust's external-LLVM bootstrap path.
- An isolated Rust 1.97 stage1 built against that external LLVM replay passed
  the serialized-output test (`1/1`) and all four Apple-target revisions of the
  `callbr` codegen test (`4/4`). This proves compatibility; normal stage1 builds
  still use the unchanged bundled-LLVM gitlink.
- Owned-fork arm64e validation run `29268159861` passed on both macOS 15 and
  macOS 26 from signed Rust tip `c3a04d4`.
- Owned-fork stage1 dry run `29268161888` passed for both
  `aarch64-apple-darwin` and `x86_64-apple-darwin`; `publish-stage1` was
  skipped. Both uploaded artifact checksums verify, and their manifests record
  source tip `c3a04d4`, Rust 1.97.0 base `2d8144b`, Rust source, and all four
  Apple arm64e targets.
- The first approved publication run, `29273772623`, again built and tested
  both host artifacts but failed before creating a tag or release because its
  publish job compared a raw branch name with the canonical attestation source
  ref. Cleanup confirmed that no partial tag or release remained.
- Signed workflow fix `027700f412b0` made the source-ref contract explicit.
  Retry run `29277996466` passed both host builds and publication, but later
  inspection showed that its schema-v2 artifacts had selected downloaded Rust
  CI LLVM 22.1.8 rather than the Rust 1.97 gitlink's LLVM 22.1.6. That release
  is marked superseded and is not production evidence.
- Correction run `29333736646` at `97f3fa1` proved the Apple Silicon artifact
  but reached the former 240-minute job timeout while Intel was still building
  LLVM from source; no publication was requested. Signed workflow commit
  `c405db8` raised that bound to 360 minutes. Fork validation run `29364945389`
  then passed both macOS lanes at the final tip. Stage1 dry run `29364945460`
  passed both host builds and uploaded both artifact bundles; its publisher
  remained skipped.
- Approved publication run `29390775624` passed both host builds, published the
  corrected immutable schema-v3 prerelease, and completed post-publication
  release and build-attestation verification. The tag, release target, source
  branch, and both manifests resolve to `c405db8`; both packaged compilers use
  source-built bundled LLVM gitlink `08c84e69` with `downloadCiLlvm: false` and
  report LLVM 22.1.6. Independent Apple Silicon, Intel, and release-surface
  readbacks verified all eight assets, their exact digests, embedded LLVM
  identities, target/std payloads, executable `rustc`/`llc` tools, release
  immutability, and SLSA provenance.
- The first consumer rebuild, Rust tests, slice inspection, visionOS build, and
  local app plans all completed against that superseded artifact. They remain
  useful pipeline and app baselines but do not validate the corrected compiler
  package.
- Initial corrected-artifact consumer acceptance completed across signed heads
  `b33d347cf5a2` and `d93b26f15b92`, both descendants of provenance/re-pin
  commit `8aee8304462c`:
  - At `b33d347`, a forced fresh download of the corrected immutable stable197
    prerelease from run `29390775624` passed the pinned outer digests,
    immutable-release and SLSA checks, and the schema-v3 semantic validator
    before any downloaded compiler executed. The selected package resolves to
    Rust source `c405db8`, stable base `2d8144b`, bundled LLVM gitlink
    `08c84e69`, `downloadCiLlvm: false`, and LLVM 22.1.6.
  - The full release XCFramework rebuild passed. Its generated manifest records
    the exact corrected release and `requiredSlicesPresent: true`; iOS, macOS,
    and visionOS device libraries contain `arm64` plus `arm64e`, while both
    simulator libraries remain `arm64`. Generated UniFFI Swift stayed unchanged
    at SHA-256
    `a240ad826bd4be04a4128c9130a91529067d09225a6d9b1f3b8ae701377077d2`.
  - After merging main `4f30409` as `d93b26f`, the full `pgp-mobile` Cargo
    suite and 48 focused downloader, release, provenance, App Store candidate,
    build-phase, and workflow tests passed.
  - Serialized Xcode 26.6 validation on macOS 27.0 build `26A5378n`, using
    isolated build directories and the actual `arm64e` destination, passed
    1,372 Unit, 81 Device, and 31 Mac UI tests with zero failures or skips.
    The first Unit attempt used Xcode's shared default DerivedData; that tree
    disappeared beneath its signed host and resources mid-run, producing
    `errSecCSStaticCodeNotFound` plus missing-file failures. That attempt is not
    acceptance evidence. A dedicated-DerivedData rerun produced the counted
    1,372/1,372 result without a product, test, Keychain, or container change.
  - Xcode 27 beta build `27A5218g` built the corrected app for generic visionOS
    27 with minimum OS 26.5. Both executable slices are present: `arm64` and
    `arm64e`.
- Final-current-main acceptance advanced that corrected-artifact evidence
  through successive signed heads:
  - Main `4693901ca62e` was merged as `e3d73a1859f`. Because that merge changed
    `pgp-mobile`, the corrected stage1 package was downloaded and semantically
    reverified before use, the full release XCFramework was rebuilt, and the
    complete Cargo suite plus all 48 focused Python tests passed. Generated
    UniFFI Swift remained unchanged.
  - Main `ddc867e25a0d` was then merged as `1ab21fa0b4e`. Its three-file delta
    was Swift/test-only and did not change the rebuilt Rust, UniFFI, or
    XCFramework artifact.
  - The first full Unit run after that merge exposed test-harness issue #668:
    18 `EncryptScreenModelTests` teardowns deleted the shared temporary root
    instead of their test-owned contacts directory. Signed test-only commit
    `ae27eb8d29fe` narrows those cleanups to the owned directory. A focused
    reproduction passed 34/34, then both the explicit-serial and canonical
    Unit runs passed 1,375/1,375. The canonical run is the acceptance result;
    no local-only flag is required.
  - At validated code head `ae27eb8`, serialized Xcode 26.6 acceptance passed
    1,375 Unit, 81 Device, and 31 Mac UI tests with zero failures or skips.
    Xcode 27 beta build `27A5218g` also rebuilt the generic visionOS app; its
    `arm64` and `arm64e` slices both record minimum OS 26.5 and SDK 27.0.
  - The signed documentation-only successor to `ae27eb8` records this evidence;
    it does not alter the locally accepted code or packaged artifact.
  - Main `77c548dc7401`, containing pull requests #669 and #670, was then
    merged as signed head `b33c615b40c1`. Its eight-file delta is limited to
    Swift settings and privacy-cover UI, localization, project membership, and
    `SettingsScreenModelTests`; it does not change Rust, UniFFI, the stage1 pin,
    or the rebuilt XCFramework.
  - At `b33c615`, serialized Xcode 26.6 acceptance on the actual macOS `arm64e`
    destination passed 1,379 Unit, 81 Device, and 31 Mac UI tests with zero
    failures or skips. Xcode 27 beta build `27A5218g` also rebuilt the generic
    visionOS app; both `arm64` and `arm64e` executable slices record minimum OS
    26.5 and SDK 27.0. The additional four Unit tests are the coverage inherited
    from current main.
  - Signed documentation-only head `e648de54d3c7` records that local evidence;
    it does not alter the accepted code or packaged artifact.
  - Main `469d63f2c75d`, containing pull request #671, was then merged as signed
    head `87569537592a`. Its only product inputs are 23 PNG assets with
    authoring metadata removed plus their repository checker; it does not
    change source behavior, tests, Rust, UniFFI, the stage1 pin, or the rebuilt
    XCFramework.
  - At `8756953`, all 23 PNGs were verified as the exact metadata-only transform
    of their parent blobs with every rendering chunk unchanged, and the full
    repository metadata scan passed. Fresh macOS `arm64e`, generic iOS, and
    generic visionOS builds passed. Both iOS and visionOS executables contain
    `arm64` and `arm64e` slices with minimum OS 26.5 and SDK 27.0. The prior
    1,379 Unit, 81 Device, and 31 Mac UI results remain the behavioral
    acceptance because every source and test blob is preserved byte-for-byte.
  - Signed documentation-only head `dc0149c6853b` records that current-main
    evidence; it does not alter the accepted code or packaged artifact.
  - Main `4e0d4a81147a`, containing pull request #672, was then merged as signed
    head `109c8fb659c6`. Its only changed file is
    `ci_scripts/ci_post_clone.sh`: Xcode Cloud now confines the release PAT to a
    throwaway `GH_CONFIG_DIR`, removes that directory before the WF1 compiler
    and Cargo build, reauthenticates only for the post-build SQLCipher restore,
    and includes credential cleanup in the existing exit/signal trap. It does
    not change app source, tests, Rust, UniFFI, the stage1 pin, or packaged
    artifacts.
  - At `109c8fb`, Bash syntax validation, a mocked scoped-auth lifecycle, and
    actual exit-trap cleanup all passed. The merged script blob matches main
    exactly, while every issue #622/#668 topic blob is preserved. The prior
    product test and platform-build results therefore remain applicable.
  - The signed documentation-only successor to `109c8fb` records this final
    current-main evidence; it does not alter the accepted code or packaged
    artifact.
- Historical clean-runner PR run `29285509956` on signed CypherAir commit `93c48f0` passed
  the full Rust suite, dependency audit, GnuPG + sq interoperability lane,
  arm64e dependency-freshness check, pinned stable197 download, XCFramework
  rebuild, packaging, and artifact upload. Its best-effort Apple platform job
  skipped the actual iOS and visionOS probes because the runner selected Xcode
  26.6 rather than 26.5. Its best-effort Swift unit job skipped the actual test
  plan because that Xcode mismatch was joined by a macOS 26.4 host below the
  app's 26.5 deployment target. Those two successful job conclusions therefore
  do not replace the local platform and app-test evidence, and its XCFramework
  lane consumed the now-superseded schema-v2 toolchain.

Local app-test incident and resolution:

- Before XCTest could connect, the locked macOS session caused the sandboxed
  app to return `protectedFileWriteFailed` while creating a complete-protected
  UI-test Contacts domain. LLDB captured `errno = EPERM`; a live session check
  then returned `CGSSessionScreenIsLocked = 1`. The same pre-XCTest trap on
  `arm64e` and control `arm64`, plus separate UI-runner authentication-session
  failures, made this host-state evidence rather than a completed test result.
  This is consistent with Apple's [macOS App Sandbox diagnostics](https://developer.apple.com/documentation/Security/accessing-files-from-the-macos-app-sandbox)
  for complete protection being unavailable while locked, but the initial
  evidence alone did not prove that diagnosis.
- After the user unlocked the macOS session, all three plans were rerun
  serially with Xcode 26.6 on `My Mac` (MacBook Air), macOS 27.0 build
  `26A5378j`, using the actual `arm64e` destination:
  - `CypherAir-UnitTests`: 1,363 passed, zero failed or skipped.
  - `CypherAir-DeviceTests`: 81 passed, zero failed or skipped.
  - `CypherAir-MacUITests`: 31 passed, zero failed or skipped.
  Each result bundle reports `Passed`, and each build action reports
  `succeeded` with zero errors. The post-unlock results resolve the host-state
  blocker for that historical run without a product or test-source change.
  Because the packaged toolchain was later superseded, these counts are the
  baseline for — not a substitute for — corrected-artifact acceptance.
- Corrected-artifact exact-head PR run `29406375343` targeted pushed evidence
  head `07c2dfc` but was cancelled before completion; all six jobs concluded
  cancelled. It is audit history only and does not satisfy the merge gate. The
  replacement must be the run GitHub creates from the final pushed evidence
  head.
- Replacement run `29411751060` targeted pushed evidence head `0456863` but
  was likewise cancelled after main advanced to `77c548d`; one dependency
  audit job passed and the other five jobs concluded cancelled. It is also
  audit history only.
- Replacement run `29413325008` targeted pushed evidence head `e648de5` but
  was cancelled while still queued after main advanced to `469d63f`. It is
  audit history only.
- Exact-head run `29414077433` passed all six jobs at pushed evidence head
  `dc0149c`: the Rust suite, dependency audit, GnuPG + sq interoperability,
  XCFramework packaging, hosted Swift preview, and Apple platform probes all
  succeeded. Main then advanced to `4e0d4a8`, so this is a clean validation
  checkpoint rather than the final merge run. The merge gate remains the run
  created from the final pushed documentation successor to `109c8fb`.
- Xcode emitted non-blocking warnings while collecting and merging raw
  coverage profiles from sandbox paths, plus signed-XCTest-library stripping
  warnings. These did not prevent any test from running and are distinct from
  the earlier pre-XCTest app trap and authentication-session failure.
- No shared app-container data was deleted or reset, and protected-data
  behavior was not weakened. Issue #651 retains the diagnostic history and
  non-blocking test-lifecycle follow-up.

Final merge gates for the CypherAir production re-pin:

1. Pull-request CI must pass on the final pushed evidence head; cancelled run
   `29406375343` and superseded replacements `29411751060` and `29413325008`
   are not acceptance evidence, while successful run `29414077433` validates
   only the superseded `dc0149c` checkpoint.
2. Before merge, obtain a fresh verification of that exact final state using
   `gpt-5.6-sol` at maximum effort with fork context disabled.

## 7. Release And Upstream Gates

The stable-1.97 workflow is safe by default:

- branch pushes and schedules may build validation artifacts but force
  `create_release=false`;
- manual dispatch also defaults `create_release=false`;
- publication requires explicit manual opt-in, either by dispatching the
  stage1 workflow with `create_release=true`, or by dispatching upstream-sync
  prep with both `create_refresh_pr=true` and
  `dispatch_stage1_prerelease=true`; all defaults are false.

The stable197 prerelease publication and CypherAir re-pin received that
separate maintainer approval. The exact production pin is therefore the one in
[ARM64E_STATUS.md](ARM64E_STATUS.md). Opening any upstream Rust or LLVM pull
request remains outside this approval and requires a new explicit decision;
all upstream-facing work remains on CypherAir-owned branches.

## 8. Stable-1.96 To Stable-1.97 Lineage

The reconstruction preserves the useful archaeology from the former 29-patch
analysis while removing stale carry advice:

| Stable-1.96 source | Stable-1.97 result |
| --- | --- |
| `1b3d8853` + `b34d21ad` + `46da820b` | Squashed into target commit `f6f0b28920eb` |
| `e5eeab87` | Rebuilt as feature-model commit `acd9bbd79335` |
| `1a4c19c5` | Rebuilt as module-metadata commit `69be3054de1f` |
| `98c04c76` | Frontend call emission retained in `701aa4548eb4`; stripper logic deleted |
| `e2009504` | Rebuilt as function-pointer-data commit `3026427dab1e` |
| `88546cd4` + `e63ffa3e` | Rebuilt as diagnostics commits `8d2ee46cf833` + `3d4d7458ed47` |
| `edd113bf` + `55651c15` | Consolidated into bootstrap commit `def17bd149bd` |
| `ba4f1852` | Frontend IR fixes retained in `c3a04d4e4ff9`; stripper bookkeeping deleted |
| `ecc85bfa` | Dropped because Rust 1.97 contains upstream equivalent `8c029d5f456775294204a8c28b24d6ba19865d79` |
| `df93416f` + `c6de391a` | Consolidated into test commit `23f3f80209af` |
| Twelve stable-1.96 fork-CI commits | Consolidated into `ed9539c2e21d` + `92e1dbfed5a2` |
| `6f895c2d` + `394813b6` | Deleted, not relocated; LLVM root-cause contracts are represented by `cde471330089` + `ec9476ea9f6e` |

The sequencing matters. `98c04c76` originally introduced frontend call
emission together with the broad late stripper; `ba4f1852` mixed genuine
frontend fixes with stripper bookkeeping; `6f895c2d` refactored stripping into
`PtrauthUtils` and serialization/pass hooks; and `394813b6` narrowed it to
`callbr`. Dropping only the final pair would therefore resurrect the earlier,
broader stripper. The stable-1.97 history was rebuilt so no stripper exists in
any intermediate commit.

## 9. Future Rebase And Upstream Guidance

For a future stable Rust rebase, start at the exact stable tag and replay the
logical order: target definition, feature/ABI model, frontend metadata and
emission, diagnostics, bootstrap, tests, then fork CI. Expect conflicts to
concentrate in `rustc_codegen_llvm`, its thin C API surface in `llvm-wrapper/`,
and Apple target definitions. Drop a carry commit in the same rebase that first
contains its upstream equivalent; never retain a no-op copy for history.

Potential future Rust-facing proposals, if the maintainer separately
authorizes upstream work, remain:

1. the fail-closed feature diagnostics (`8d2ee46cf833` + `3d4d7458ed47`);
2. the standalone arm64e visionOS target (`f6f0b28920eb`);
3. the default arm64e feature model (`acd9bbd79335`).

This ordering is planning guidance only. It does not authorize an upstream
pull request or name any maintainer, reviewer, owner, or assignee.
