# Apple arm64e Stage1 Pin

*A machine-parsed contract, not a narrative document. `scripts/validate_app_store_candidate_release.py` requires this file to contain exactly one pinned-tag bullet and fails the App Store candidate gate unless it equals the tag in `third_party/arm64e-stage1-toolchain.pin.json`. Keep that line's format byte-identical.*

- **Pinned prerelease tag:** `rust-stage1-arm64e-toolchain-20260810T072951Z-717ad05-r31366067106-a1`

**`latest` is never allowed.**

Everything else about arm64e — the packaging policy, the re-pin rule, the owned carry chains, the artifact and release contract — lives in [BUILD.md](BUILD.md).
