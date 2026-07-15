---
name: repin-arm64e
description: Rotate the pinned arm64e stage1 Rust toolchain tag everywhere it is pinned. Use when updating ARM64E_STAGE1_RELEASE_TAG to a newly published rust-arm64e-stage1-* release.
---

docs/ARM64E_STATUS.md owns the pin and enumerates every pinned location —
follow its re-pin rule and update ALL locations it lists in one commit. That
includes `third_party/arm64e-stage1-toolchain.pin.json`: refresh the release
identity and all per-asset SHA-256 digests (both host triples), confirming
API-reported digests against a real download.

**Verify:**

- `rg <old-tag>` → zero hits outside immutable history/evidence lines.
- `rg <new-tag>` → exactly the locations ARM64E_STATUS.md enumerates.
- `scripts/download_arm64e_stage1_toolchain.sh <tmp-dir>` succeeds against the
  refreshed pin, and `scripts/verify_arm64e_stage1_release.sh <tmp-dir>/download`
  passes (immutability + tag→commit binding + asset attestations).
- One pinned rebuild (`./build-xcframework.sh --release` with the new tag)
  completes and the macOS unit lane passes against the produced artifact.
