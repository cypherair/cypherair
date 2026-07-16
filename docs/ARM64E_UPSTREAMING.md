# CypherAir arm64e Toolchain Upstreaming Plan

> Status: Rust 1.97 / LLVM ownership split — landed (issue #622, PR #650).
> This document is not the production pin source of truth.
> Purpose: Record which arm64e changes belong in Rust, which belong in LLVM,
> and how the owned-fork carry is validated, published, and consumed.
> Source of truth for the production stage1 pin:
> [ARM64E_STATUS.md](ARM64E_STATUS.md).
> Scope boundary: The OpenSSL and `ctor` carry chains remain owned by
> [ARM64E_STATUS.md](ARM64E_STATUS.md) and are out of scope here.
> Update triggers: A Rust or LLVM rebase, an upstream merge that retires a
> carried change, a change to the fork topology, or an approved production
> re-pin.
> Last reviewed: 2026-07-16.

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

The production pin is recorded in [ARM64E_STATUS.md](ARM64E_STATUS.md).
Candidate validation alone never changes it: publication, provenance readback,
and the explicit re-pin remain separate maintainer-approved gates.

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
compiler/CI series ends at `c3a04d4e4ff987b59aacb8d42b66c853db74c02a`; the
final signed publication tip is `c405db836704af8307c5c41d6dbdc92068dec0d6`
(the four workflow commits above the series are enumerated in §4 and do not
change Rust compiler-source behavior).

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
against the external replay also passed (serialized-output regression 1/1,
`callbr` codegen 4/4); the broader evidence trail is §6.

## 6. Validation Contract

The corrected stable197 schema-v3 prerelease — the production pin in
[ARM64E_STATUS.md](ARM64E_STATUS.md) — is fully validated and consumed: both
host artifacts, release immutability, per-asset SLSA provenance, the packaged
source-built LLVM 22.1.6 identity, the full XCFramework rebuild, the complete
Rust and focused Python suites, and local app acceptance (Unit / Device /
Mac UI plans, zero failures) all passed at the merged heads. The step-by-step
evidence lives in issue #622, pull request #650, and fork publication run
`29390775624`; it is not restated here.

A future stage1 candidate must re-prove, before publication and re-pin:

- `x.py check compiler/rustc_codegen_ssa compiler/rustc_codegen_llvm --stage 1`
  on the candidate;
- the `callbr` codegen regression on all four Apple revisions (macOS, iOS,
  tvOS, visionOS) and the serialized-output regression across LLVM IR,
  bitcode, and embedded-bitcode paths, against the default bundled LLVM;
- valid commit signatures and `git diff --check` across the whole carry range;
- owned-fork validation and a stage1 dry run on both host triples, then — for
  the publication run — the post-publication readback: release immutability,
  tag-to-commit binding, per-asset SLSA provenance, and the packaged LLVM
  identity;
- consumer acceptance per the re-pin rule in
  [ARM64E_STATUS.md](ARM64E_STATUS.md): a forced fresh download through the
  semantic validator, a full XCFramework rebuild, the Cargo suite plus the
  focused scripts tests, and the local app test plans.

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
