#!/usr/bin/env bash
set -euo pipefail

# sample_arm64e_darwin_toolchains.sh
#
# Samples a small set of nightly toolchains to determine whether the observed
# arm64e-apple-darwin host crash is target-wide or looks like a recent
# regression. The matrix is intentionally small:
#   1. scratch Cargo hello-world on arm64e-apple-darwin
#   2. pgp-mobile's smallest certificate-merge test on arm64e-apple-darwin
#
# The script auto-installs rust-src for the requested toolchains because
# -Zbuild-std requires it.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/pgp-mobile/Cargo.toml"
TOOLCHAINS=("$@")

if [[ "${#TOOLCHAINS[@]}" -eq 0 ]]; then
    TOOLCHAINS=(
        nightly
        nightly-2026-04-01
        nightly-2026-03-15
        nightly-2026-02-15
    )
fi

scratch_dir="$(mktemp -d /tmp/arm64e-toolchain-sample-XXXXXX)"
scratch_name="$(basename "$scratch_dir")"

cleanup() {
    rm -rf "$scratch_dir"
}
trap cleanup EXIT

(
    cd "$scratch_dir"
    cargo init --bin --quiet
    cat > src/main.rs <<'EOF'
fn main() {
    println!("hello");
}
EOF
)

echo "toolchain,scratch_build_status,scratch_run_status,merge_test_status"
for tc in "${TOOLCHAINS[@]}"; do
    rustup component add rust-src --toolchain "$tc" >/dev/null 2>&1 || true

    set +e
    (
        cd "$scratch_dir"
        cargo +"$tc" build -Zbuild-std --target arm64e-apple-darwin
    ) >/tmp/${tc//[^A-Za-z0-9_-]/_}-scratch-build.log 2>&1
    scratch_build_status=$?

    scratch_run_status=999
    if [[ "$scratch_build_status" -eq 0 ]]; then
        "$scratch_dir/target/arm64e-apple-darwin/debug/$scratch_name" \
            >/tmp/${tc//[^A-Za-z0-9_-]/_}-scratch-run.log 2>&1
        scratch_run_status=$?
    fi

    cargo +"$tc" test -Zbuild-std --target arm64e-apple-darwin \
        --manifest-path "$MANIFEST_PATH" \
        --test certificate_merge_tests \
        test_merge_public_certificate_expiry_refresh_profile_a -- --exact \
        >/tmp/${tc//[^A-Za-z0-9_-]/_}-merge-test.log 2>&1
    merge_test_status=$?
    set -e

    echo "$tc,$scratch_build_status,$scratch_run_status,$merge_test_status"
done
