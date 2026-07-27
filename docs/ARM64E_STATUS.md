# Apple arm64e Stage1 Pin

*A machine-parsed contract, not a narrative document. `scripts/validate_app_store_candidate_release.py` requires this file to contain exactly one pinned-tag bullet and fails the App Store candidate gate unless it equals the tag in `third_party/arm64e-stage1-toolchain.pin.json`. Keep that line's format byte-identical.*

- **Pinned prerelease tag:** `rust-arm64e-stage1-stable197-20260715T051054Z-c405db8-r29390775624-a1`

**`latest` is never allowed.** Every consumer force-downloads this exact tag against the digests in the machine pin.

Everything else about arm64e — the packaging policy, the re-pin rule, the owned carry chains, the artifact and release contract — lives in [BUILD.md](BUILD.md).
