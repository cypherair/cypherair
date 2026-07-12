# CypherAir arm64e Toolchain Upstreaming Plan

> Status: Planning / strategy companion to [ARM64E_STATUS.md](ARM64E_STATUS.md). Not the source of truth.
> Purpose: Enumerate every patch carried by the forked Rust stage1 toolchain, assess where each belongs upstream (LLVM / rustc / keep-carrying), and give a carry-set minimization plan, a rebase strategy, and a first-upstream-candidate shortlist.
> Audience: Toolchain maintainers weighing the long-term maintenance risk tracked in issue #504.
> Scope boundary: This document covers the **Rust compiler fork only** (`cypherair/rust`, branch `carry/cypherair-arm64e-toolchain-stable-1.96`). The separate `openssl-src` / `openssl` arm64e carry chain is owned by [ARM64E_STATUS.md](ARM64E_STATUS.md) §OpenSSL Carry Chain and is out of scope here.
> Update triggers: A rebase onto a new Rust stable base, an upstream (LLVM or rust-lang) merge that lets a carried patch be dropped, or a re-pin that changes the carried commit set.
> Last reviewed: 2026-07-11.

## 1. Scope and Method

The fork's stable base is Rust `1.96.0` (`ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96`), as recorded in [ARM64E_STATUS.md](ARM64E_STATUS.md) §Pinned Rust stage1 Toolchain. The carry-set is the commit range `ac68faa20c58..<carry tip>`, enumerated with `git log --reverse` and classified by reading each `git show`.

`git merge-base carry/cypherair-arm64e-toolchain-stable-1.96 1.96.0` resolves to exactly `ac68faa20c58`, confirming a clean linear stack on the stable tag with no upstream drift folded in.

**Carry tip vs. pinned commit — a discrepancy to reconcile.** As checked out, both the local and `origin`-tracking `carry/cypherair-arm64e-toolchain-stable-1.96` tip is `f6367e3754b3` ("Merge pull request #17 … host-specific stage1 assets"), which carries **28 non-merge patches**. The pinned stage1 source commit named in [ARM64E_STATUS.md](ARM64E_STATUS.md) — `abeb8459f2b459704c1d698c01d8b8c0df8ffffd` — is **two commits ahead** of that tip: it adds one more CI patch (`2759c050dc34` "ci: verify stage1 release attestations after publish") plus its merge (PR #18), for **29 non-merge patches** total. `abeb845` is currently **not reachable from any local or origin branch ref** (detached). Either the local mirror predates the branch's advance to `abeb845`, or the branch was rolled back after the pin was cut. This must be resolved before the next re-pin so the pinned artifact is always reachable from the carry branch (see §6). This document enumerates the **full 29-patch pinned superset**, marking the pinned-only patch.

## 2. Classification Summary

"Where the fix belongs" is the repository where the durable upstream change would land, not merely the file a patch touches:

- **rustc** — belongs in `rust-lang/rust` (target specs, target-feature validation, codegen front-end in `rustc_codegen_llvm`, bootstrap robustness, compiler test suite).
- **LLVM** — the durable fix belongs in upstream LLVM (AArch64 ptrauth lowering / operand-bundle canonicalization); the fork carries a downstream compensation in `llvm-wrapper/`.
- **keep** — fork-only release automation with no upstream home (stage1 packaging/publish CI, fork-shape validation workflows).

| Bucket | Count | Patches |
| --- | --- | --- |
| rustc  | 15 | target specs (3), ptrauth feature model + codegen (6), bootstrap (2), Mach-O subtype (1), ptrauth IR-gap fixes (1), tests (2) |
| LLVM   | 2  | serialized-output ptrauth-bundle strip/keep pair |
| keep   | 12 | stage1 publish + fork validation CI (incl. 1 pinned-only) |
| **Total** | **29** | |

Caveat: ~6 of the 15 rustc-bucket patches are the arm64e ptrauth **codegen** group. They land in rustc mechanically, but their *near-term* upstream feasibility is low (arm64e is a Tier-3/experimental ABI upstream) and each has an LLVM-facing dimension. They are counted rustc but discussed as the carry heart in §3.2 and §4.

## 3. Per-Patch Enumeration

Commits are listed in stack order (base → tip). Effort is upstream-review effort, not lines changed. "Feas." = near-term upstream feasibility.

### 3.1 Target definitions — rustc, high feasibility

Adds the `arm64e-apple-visionos` Tier-3 target, mirroring the already-upstream `arm64e-apple-ios` / `arm64e-apple-tvos` Tier-3 targets. Internal order: `1b3d8853` is the substantive add; `b34d21ad` and `46da820b` are fixups of it (maintainer-entry correction and a tidy trailing newline) and should squash into it before upstreaming.

| Commit | Subject | (a) Gap | (b) Home | (c) Feas. · Effort |
| --- | --- | --- | --- | --- |
| `1b3d8853` | target: add arm64e-apple-visionos | No upstream arm64e visionOS target spec | rustc | High · Low |
| `b34d21ad` | target: correct arm64e visionOS maintainer and docs | Fixup of `1b3d8853` (unagreed maintainer) | rustc | — (squash) |
| `46da820b` | target: add trailing newline required by tidy | Fixup of `1b3d8853` (tidy) | rustc | — (squash) |

(d) Self-contained (`rustc_target` spec + `bootstrap/sanity.rs` + platform-support docs); depends only on committing a target maintainer. Independent of the ptrauth codegen group.

### 3.2 Ptrauth feature model + codegen — rustc (the carry heart), low near-term feasibility

The substantive work: teaching `rustc_codegen_llvm` to emit Apple arm64e pointer authentication the way clang's front-end does, because Rust has no other front-end to emit it. Internal order is strict — `e5eeab87` models the feature defaults and the `is_apple_arm64e()` predicate everything else keys off; `1a4c19c5` sets the clang-compatible module flag; `98c04c76` / `e2009504` add the actual signing of calls and function-pointer data; `88546cd4` / `e63ffa3e` reject disabling the ABI-mandatory features.

| Commit | Subject | (a) Gap | (b) Home | (c) Feas. · Effort |
| --- | --- | --- | --- | --- |
| `e5eeab87` | arm64e: model default Apple ptrauth features | rustc doesn't model `+v8.3a,+paca,+pacg` as arm64e defaults; no `is_apple_arm64e()` | rustc | Med · Low |
| `1a4c19c5` | arm64e: emit clang-compatible ptrauth metadata | rustc emits no `ptrauth.abi-version` module flag; loader/ABI mismatch vs clang | rustc | Med · Low |
| `98c04c76` | arm64e: authenticate indirect function calls | rustc emits no `ptrauth` call operand bundles for indirect calls | rustc | Low · High |
| `e2009504` | arm64e: authenticate function pointers used as data | Function pointers stored as data aren't signed (`LLVMConstantPtrAuth`) | rustc | Low · High |
| `88546cd4` | arm64e: reject incompatible ptrauth flag overrides | `-Ctarget-feature=-paca/-pacg` silently produces a broken ABI | rustc | High · Low |
| `e63ffa3e` | Reject -Ctarget-feature=-pauth on Apple arm64e | Same, via the LLVM `pauth` spelling that `flag_to_backend_features` still forwarded | rustc | High · Low |

(b) nuance: `1a4c19c5` and the two signing patches reach LLVM through thin `llvm-wrapper/RustWrapper.cpp` C-API shims (e.g. `LLVMRustAddModuleFlagMetadata`), but the logic — *decide what to sign, emit the bundle/constant* — is front-end work that belongs in `rustc_codegen_llvm`. (c) nuance: `98c04c76` / `e2009504` are the hardest to upstream: rust-lang has historically deferred arm64e ptrauth codegen as experimental, so landing them needs design buy-in and a committed target maintainer, not just review. (d) `88546cd4` → `e63ffa3e` is a hard dependency (the second extends the first's forbidden-disable check); both depend on `e5eeab87` for the feature model but **not** on the signing patches, which is what makes them separable (see §7). The signing patches (`98c04c76`, `e2009504`) additionally depend on `ba4f1852` (§3.4) for correctness.

### 3.3 Bootstrap robustness — rustc, medium feasibility

| Commit | Subject | (a) Gap | (b) Home | (c) Feas. · Effort |
| --- | --- | --- | --- | --- |
| `edd113bf` | bootstrap: handle fork shallow upstream detection | `build_helper::git` upstream detection breaks on shallow fork clones | rustc | Med · Low |
| `55651c15` | bootstrap: tolerate missing upstream in shallow fork CI | Missing `origin/main` falls through to a panic instead of `MissingUpstream` | rustc | Med · Low |

(d) `55651c15` refines `edd113bf`. Fork-motivated but framable as general `build_helper::git` robustness (handle shallow clones / absent upstream conservatively), which is how upstream would want them. Both carry regression tests already.

### 3.4 Ptrauth IR-gap fixes + Mach-O metadata — rustc

| Commit | Subject | (a) Gap | (b) Home | (c) Feas. · Effort |
| --- | --- | --- | --- | --- |
| `ba4f1852` | arm64e: fix ptrauth prep IR gaps | §3.2 paths miss InlineAsm exclusion, `@main`/`__rust_try` attrs, metadata preservation on rebuilt calls | rustc | Low · Med |
| `ecc85bfa` | arm64e: version metadata Mach-O subtype | rmeta Mach-O object carries the wrong CPU subtype for arm64e | rustc | Med · Low |

(d) `ba4f1852` is a correctness dependency of the §3.2 signing patches and must travel with them upstream. `ecc85bfa` (a 5-line `rustc_codegen_ssa/back/metadata.rs` change) is nearly standalone — it only needs the `is_apple_arm64e()` predicate from `e5eeab87`.

### 3.5 Compiler tests — rustc (ride-along)

| Commit | Subject | (a) Gap | (b) Home | (c) Feas. · Effort |
| --- | --- | --- | --- | --- |
| `df93416f` | arm64e: cover visionOS ptrauth integration | visionOS not exercised by the ptrauth codegen/UI tests | rustc | — (with feature) |
| `c6de391a` | test: update visionOS arm64e ptrauth diagnostic | Snapshot refresh for `df93416f` | rustc | — (squash) |

(d) Not independently upstreamable — they extend the test suites introduced by §3.1/§3.2 to visionOS and are upstreamed together with whichever feature they cover. `c6de391a` squashes into `df93416f`.

### 3.6 Serialized-output ptrauth-bundle compensation — LLVM, low near-term feasibility

| Commit | Subject | (a) Gap | (b) Home | (c) Feas. · Effort |
| --- | --- | --- | --- | --- |
| `6f895c2d` | Strip `ptrauth` operand bundles before serialized output | LLVM doesn't canonicalize/lower `ptrauth` operand bundles on the affected call shapes, so they leak into serialized output and break consumers | LLVM (AArch64 ptrauth canonicalization/lowering) | Low · Med |
| `394813b6` | Keep direct-call bundles out of serialization (follow-up) | Same root cause on direct calls; its own commit message names the durable fix — prevention by LLVM canonicalization, not downstream repair | LLVM | Low · Med |

(d) The pair is interdependent (the follow-up extends the strip pass) and is carried as a downstream compensation in `llvm-wrapper/`. Both drop the moment upstream LLVM canonicalizes the bundles (§4 step 3), but LLVM's release cadence means that fix reaches the Rust fork only with a much later LLVM bump — keep-carrying until then.

### 3.7 Fork release + validation CI — keep (no upstream home)

All twelve are fork-only automation: they build, package, attest, smoke-test, and publish the `rust-arm64e-stage1-*` prerelease the app pins ([ARM64E_STATUS.md](ARM64E_STATUS.md) §Pinned Rust stage1 Toolchain), and run fork-shape arm64e validation. None has an upstream destination; "minimization" here means consolidating history, not shrinking carry surface (§4).

| Commit | Subject | (b) Home |
| --- | --- | --- |
| `fb7c18e2` | ci: add fork arm64e validation workflow | keep |
| `39c5fdb6` | ci: publish arm64e stage1 prereleases | keep |
| `a69fecf2` | ci: fix arm64e stage1 attestation | keep (fixup of `39c5fdb6`) |
| `0e3a0bde` | ci: avoid stage1 release tag fetch | keep (fixup of `39c5fdb6`) |
| `5beb3daa` | ci: package rust-src in arm64e stage1 | keep |
| `967d9bbc` | ci: retarget arm64e workflows to carry branch | keep |
| `04cbb277` | ci: broaden fork arm64e validation | keep |
| `12f074a3` | ci: smoke test packaged arm64e stage1 cargo builds | keep |
| `34eefe0e` | ci: smoke test arm64e stage1 apple targets | keep |
| `4e505e37` | ci: publish stable 1.96 arm64e stage1 | keep |
| `a5c65009` | ci: publish host-specific arm64e stage1 assets | keep |
| `2759c050` | ci: verify stage1 release attestations after publish | keep · **pinned-only** (§1) |

(d) A single interdependent workflow chain (mostly edits to `arm64e-stage1-prerelease.yml` and `fork-arm64e.yml`); several are fixups of `39c5fdb6`. `2759c050` is present in the pinned artifact but not on the current carry tip.

## 4. Carry-Set Minimization Plan

1. **Squash the bookkeeping.** Fold each fixup into its parent before the next rebase: `b34d21ad` + `46da820b` → `1b3d8853`; `c6de391a` → `df93416f`; `a69fecf2` + `0e3a0bde` → `39c5fdb6`. This collapses 29 commits to roughly a dozen logically-distinct patches. It reduces rebase and review friction, not runtime risk.
2. **Retire the self-contained rustc patches by upstreaming them.** The flag-rejection pair (`88546cd4` + `e63ffa3e`), the visionOS target (`1b3d8853` squashed), the bootstrap pair (`edd113bf` + `55651c15`), and `ecc85bfa` each leave the carry-set permanently once merged upstream and a stable release containing them becomes the new base. None depends on the contentious codegen group.
3. **Push the LLVM-bucket pair to its root cause.** `6f895c2d` + `394813b6` strip `ptrauth` operand bundles before serialized output because LLVM doesn't canonicalize/lower them on the affected call shapes. `394813b6`'s own commit message states the durable fix: *"Direct-call bundles should be prevented by LLVM canonicalization instead of repaired here before serialization."* Upstreaming the canonicalization/lowering to LLVM's AArch64 ptrauth path eliminates both carry patches — but LLVM's release cadence means the fix won't reach the Rust fork until a much later LLVM bump, so keep the strip pass until then.
4. **Accept the irreducible remainder.** After steps 2–3 the carry surface is: the arm64e ptrauth **codegen** group (`e5eeab87`, `1a4c19c5`, `98c04c76`, `e2009504`, `ba4f1852`, + tests) until rust-lang accepts arm64e ptrauth codegen, plus the entire **keep** CI set. Consolidate the CI history into the two maintained workflow files so the *surface* (not the commit count) is what the maintainer reasons about.

Realistic end state: from 29 carried commits down to a codegen core of ~5–6 patches + fork CI, with every self-contained rustc patch and (eventually) the LLVM pair upstreamed.

## 5. Rebase Strategy for Future Rust Releases

- **Ordered patch series on the stable tag.** Keep the carry branch as a rebased series on top of each new stable tag, following the naming already in use (`carry/cypherair-arm64e-toolchain-stable-<major.minor>`). For 1.97: branch from the `1.97.0` tag and re-apply the series in the §3 order (targets → feature model → codegen → IR-gap fixes → Mach-O → tests → bootstrap → CI). Dependency order matters so an early conflict doesn't cascade.
- **Keep the subsystem prefixes.** The existing `target:` / `arm64e:` / `bootstrap:` / `ci:` prefixes let a whole group be dropped in one step once it lands upstream — grep the prefix, drop the range.
- **Expect conflicts to concentrate in two files.** `compiler/rustc_codegen_llvm/src/**` and `compiler/rustc_llvm/llvm-wrapper/RustWrapper.cpp` are the highest-churn surfaces because the codegen patches call LLVM C++ APIs directly; every Rust stable pulls a new bundled LLVM, so the `llvm-wrapper` C++ (`RustWrapper.cpp`, `PtrauthUtils.h`, `PassWrapper.cpp`) is where an LLVM bump breaks first. Rebase those groups first and build early.
- **Drop-on-upstream discipline.** When a carried patch (or the LLVM canonicalization behind `6f895c2d`/`394813b6`) lands in the new base, delete it from the series in the same rebase and record the removal here. When the bundled LLVM gains native arm64e ptrauth handling, delete the corresponding codegen carry.
- **Re-pin reconciliation.** After each rebase, cut a new stage1 prerelease and re-pin per `.claude/skills/repin-arm64e`; [ARM64E_STATUS.md](ARM64E_STATUS.md) remains the pin's source of truth. Before cutting, reconcile the branch-tip/pinned-commit gap noted in §1 so the pinned source commit is always an ancestor of the carry tip.

## 6. Recommended First Upstream Candidates

The two best first proposals maximize (feasibility × low effort × zero LLVM entanglement × already test/doc-complete) and are independent of the contentious codegen heart:

1. **`88546cd4` + `e63ffa3e` — reject disabling ptrauth (`-paca` / `-pacg` / `-pauth`) on Apple arm64e.** Self-contained in `rustc_codegen_ssa` / `rustc_session`, no LLVM dependency, and shipped with full UI-test coverage and stderr snapshots across Darwin/iOS/tvOS/visionOS. It is pure fail-closed hardening — it prevents silently building an arm64e binary with the ABI-mandatory authentication turned off. The Darwin/iOS/tvOS targets it protects already exist upstream; the **visionOS stderr snapshots reference `arm64e-apple-visionos`, which does not** — trim those snapshots from the upstream proposal (or sequence it after candidate 2) so the PR stands on its own without either the codegen group or the target addition. Low-controversy diagnostics like this are what upstream accepts without a design discussion; merging it removes two patches from carry at near-zero cost.

2. **`1b3d8853` (squashed with `b34d21ad` + `46da820b`) — add the `arm64e-apple-visionos` Tier-3 target.** It mechanically mirrors the upstream `arm64e-apple-ios` / `arm64e-apple-tvos` Tier-3 targets — a spec file, a `sanity.rs` entry, and platform-support docs, with no codegen and no LLVM surface. Tier-3 has the lowest upstream bar (no CI guarantee required, just a target maintainer plus the docs already written in the patch), and it retires a whole target definition from the carry-set. The only prerequisite is committing a target maintainer — the `b34d21ad` fixup exists precisely because the maintainer slot must be filled by someone who agrees.

`e5eeab87` (model default ptrauth features) is the natural third: a clean `rustc_target` change that unblocks the codegen group's upstream story, though it reads best alongside at least the module-flag patch. The codegen signing patches (`98c04c76`, `e2009504`) are explicitly **not** first candidates — highest value to upstream, lowest near-term feasibility — and should follow only after a target maintainer and a design agreement are in hand.
