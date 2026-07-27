---
name: repin-arm64e
description: Rotate the pinned arm64e stage1 Rust toolchain tag everywhere it is pinned. Use when updating ARM64E_STAGE1_RELEASE_TAG to a newly published rust-arm64e-stage1-* release.
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
   changes a semantic contract (stable series/base, schema, bundled LLVM
   identity) rather than only rotating the build identity; update its tests
   with it.

**Verify:**

- `rg <old-tag>` → zero hits.
- `rg <new-tag>` → exactly the files enumerated above.
- `scripts/download_arm64e_stage1_toolchain.sh <tmp-dir>` succeeds against the
  refreshed pin, and `scripts/verify_arm64e_stage1_release.sh <tmp-dir>/download`
  passes (immutability + tag→commit binding + asset attestations).
- The App Store candidate gate cross-checks the human pin in
  `docs/ARM64E_STATUS.md` against the machine pin and accepts the new semantic
  manifest identity.
- One pinned rebuild (`./build-xcframework.sh --release` with the new tag)
  completes and the macOS unit lane passes against the produced artifact.
