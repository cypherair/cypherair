---
name: repin-arm64e
description: Rotate the pinned arm64e stage1 Rust toolchain tag everywhere it is pinned. Use when updating ARM64E_STAGE1_RELEASE_TAG to a newly published rust-stage1-arm64e-toolchain-* release.
---

The re-pin rule is docs/BUILD.md Section 3 — read it first; it holds the two
non-derivable steps (confirm API digests against a real download; revisit the
semantic constants only on a semantic change). This skill carries the
enumeration: every location below rotates in ONE commit.

1. `.github/workflows/pr-checks.yml`, `nightly-full.yml`,
   `xcframework-edge-release.yml` — `ARM64E_STAGE1_RELEASE_TAG` env values.
2. `scripts/build_apple_arm64e_xcframework.sh` and
   `scripts/download_arm64e_stage1_toolchain.sh` —
   `DEFAULT_ARM64E_STAGE1_RELEASE_TAG`.
3. `docs/ARM64E_STATUS.md` — the pinned-tag bullet. Keep its format
   byte-identical; the App Store candidate gate parses it.
4. `third_party/arm64e-stage1-toolchain.pin.json` — the full release identity
   (tag, url, commit, source ref, run id, publishedAt) AND every per-asset
   SHA-256 and byte size for both host triples.
5. `scripts/tests/test_report_dependency_freshness.py` — its fixtures pin the
   current tag literally.
6. `scripts/validate_arm64e_stage1_toolchain.py` — only when the new release
   changes a semantic contract (tag-family prefix, stable base, schema, bundled
   LLVM identity) rather than only rotating the build identity; update its tests
   with it.
7. **The tag-family prefix — only when the fork renames its publishing family**,
   which is a separate event from rotating the tag. These pin the prefix, never
   a full tag: `scripts/build_apple_arm64e_xcframework.sh` and
   `scripts/download_arm64e_stage1_toolchain.sh`
   (`ARM64E_STAGE1_RELEASE_PREFIX`), `scripts/report_dependency_freshness.py`
   (`STAGE1_TAG_PREFIX`), `scripts/validate_arm64e_stage1_toolchain.py`
   (`EXPECTED_RELEASE_TAG_PREFIX`), this file's own `description`, and the
   synthetic fixture tags in `scripts/tests/test_validate_arm64e_stage1_toolchain.py`,
   `test_validate_app_store_candidate_release.py`, and
   `test_xcframework_source_fingerprint.py` — a fixture tag outside the new
   family fails the prefix guard.

`third_party/arm64e-stage1-toolchain.pin.json`'s `dependencyName`
(`rust-arm64e-stage1-toolchain`) is a **local** identifier mirroring the pin
filename, and is published as the compliance dependency name. It does not
rotate with the tag family. It differs from the tag prefix only by word order,
so it reads like a missed rename — leave it alone.

**Verify:**

- Every sweep needs `rg --hidden`. Without it `rg` skips dotted directories, so
  the three `.github/workflows/` env values and this skill file are invisible —
  half the tag sites, silently reported clean.
- `rg --hidden <old-tag>` → zero hits; on a family rename, also sweep the old
  prefix and the old fork branch name to zero.
- `rg --hidden <new-tag>` → exactly locations 1–5 above (locations 6–7 pin only the tag *prefix*, never a full tag).
- `scripts/download_arm64e_stage1_toolchain.sh <tmp-dir>` succeeds against the
  refreshed pin, and `scripts/verify_arm64e_stage1_release.sh <tmp-dir>/download`
  passes (immutability + tag→commit binding + asset attestations).
- The App Store candidate gate cross-checks the human pin in
  `docs/ARM64E_STATUS.md` against the machine pin and accepts the new semantic
  manifest identity.
- One pinned rebuild (`./build-xcframework.sh --release` with the new tag)
  completes and the macOS unit lane passes against the produced artifact.
