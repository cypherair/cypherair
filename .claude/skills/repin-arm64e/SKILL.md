---
name: repin-arm64e
description: Rotate the pinned arm64e stage1 Rust toolchain tag everywhere it is pinned. Use when updating ARM64E_STAGE1_RELEASE_TAG to a newly published rust-arm64e-stage1-* release.
---

docs/ARM64E_STATUS.md owns the pin and enumerates every pinned location —
follow its re-pin rule. Update ALL locations in one commit (CI workflow env,
script default, hardening tests, ARM64E_STATUS.md, CLAUDE.md Build Commands,
docs/TESTING.md Section 2.4C — per the current list in ARM64E_STATUS.md).

**Verify:**

- `rg <old-tag>` → zero hits outside immutable history/evidence lines.
- `rg <new-tag>` → exactly the locations ARM64E_STATUS.md enumerates.
- One pinned rebuild (`./build-xcframework.sh --release` with the new tag)
  completes and the macOS unit lane passes against the produced artifact.
