#!/usr/bin/env bash
set -euo pipefail

# repro_arm64e_rust_host_crashes.sh
#
# Host-side arm64 vs arm64e reproduction matrix for the macOS unit-test crash
# investigation. This script avoids Xcode test-host restarts and focuses on the
# smallest Rust-only reproductions we have so far:
#   1. Existing pgp-mobile integration tests that hit selector discovery /
#      certificate merge paths.
#   2. A standalone scratch Cargo binary outside the repo.
#
# Expected current behavior on the experiment branch:
#   - arm64 host Rust tests pass
#   - arm64e-apple-darwin Rust tests SIGSEGV
#   - even a standalone arm64e hello-world binary exits 139

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/pgp-mobile/Cargo.toml"

run_cmd() {
    echo
    echo "+ $*"
    "$@"
}

echo "== arm64 host control cases =="
run_cmd cargo test \
    --manifest-path "$MANIFEST_PATH" \
    --test certificate_merge_tests \
    test_merge_public_certificate_expiry_refresh_profile_a \
    -- --exact

run_cmd cargo test \
    --manifest-path "$MANIFEST_PATH" \
    --test selector_discovery_tests \
    test_discover_certificate_selectors_profile_a_generated_cert_exposes_selectors \
    -- --exact

echo
echo "== arm64e host repro cases =="
set +e

cargo +nightly test -Zbuild-std \
    --target arm64e-apple-darwin \
    --manifest-path "$MANIFEST_PATH" \
    --test certificate_merge_tests \
    test_merge_public_certificate_expiry_refresh_profile_a \
    -- --exact
merge_status=$?

cargo +nightly test -Zbuild-std \
    --target arm64e-apple-darwin \
    --manifest-path "$MANIFEST_PATH" \
    --test selector_discovery_tests \
    test_discover_certificate_selectors_profile_a_generated_cert_exposes_selectors \
    -- --exact
selector_status=$?

echo
echo "== standalone scratch binary check =="
scratch_dir="$(mktemp -d /tmp/arm64e-rust-host-repro-XXXXXX)"
(
    cd "$scratch_dir"
    cargo init --bin --quiet
    cat > src/main.rs <<'EOF'
fn main() {
    println!("hello");
}
EOF
    cargo +nightly build -Zbuild-std --target arm64e-apple-darwin
    "./target/arm64e-apple-darwin/debug/$(basename "$scratch_dir")"
)
scratch_status=$?

set -e

echo
echo "merge_status=$merge_status"
echo "selector_status=$selector_status"
echo "scratch_status=$scratch_status"

if [[ "$merge_status" -ne 0 || "$selector_status" -ne 0 || "$scratch_status" -ne 0 ]]; then
    echo "Observed non-zero arm64e host repro status in at least one path."
else
    echo "No arm64e host repro failure observed; inspect command output above."
fi
