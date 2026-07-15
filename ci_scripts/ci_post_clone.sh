#!/bin/bash
# Xcode Cloud post-clone hook for CypherAir.
#
# Runs after Xcode Cloud clones the primary repository, before xcodebuild. Two
# release workflows share this script and branch on $CI_WORKFLOW:
#
#   "PgpMobile XCFramework" (WF1): build the arm64e PgpMobile.xcframework from
#       source so the app build action links the freshly built dependency, and
#       gate the build on the Rust dependency audit + arm64e freshness checks.
#
#   "CypherAir Release"    (WF2): download the exact attested xcframework that
#       WF1 published to the (draft) stable GitHub Release, verify its checksum,
#       extract it for linking, and run the App Store candidate gate.
#
# The arm64e stage1 toolchain pin is owned by build_apple_arm64e_xcframework.sh
# (DEFAULT_ARM64E_STAGE1_RELEASE_TAG), the digest pin file
# third_party/arm64e-stage1-toolchain.pin.json, and docs/ARM64E_STATUS.md; this
# script does not re-pin it. WF1 downloads the stage1 token-free (digest-pinned
# in the download script), then verifies release immutability and asset
# attestations with gh before the stage1 compiler executes.
# Workflow secrets (GITHUB_PAT, ASC_*) are captured and scrubbed
# from the environment at the top of main(), so brew/rustup/curl/cargo and the
# Rust/xcframework build subprocesses never inherit them; the build script also
# unsets GitHub tokens itself as a second belt. gh authentication is scoped the
# same way: the token is written only to a throwaway GH_CONFIG_DIR, and WF1
# wipes it after the pre-build stage1 verification, so the PAT is neither in
# the environment nor on disk while the stage1 compiler and cargo build
# subprocesses execute. WF1 re-authenticates after the build for the SQLCipher
# restore, matching the pre-verification flow where gh auth was post-build only.

set -euo pipefail

XCFRAMEWORK_WORKFLOW_NAME="${XCFRAMEWORK_WORKFLOW_NAME:-PgpMobile XCFramework}"
RELEASE_WORKFLOW_NAME="${RELEASE_WORKFLOW_NAME:-CypherAir Release}"
GITHUB_REPOSITORY_SLUG="${GITHUB_REPOSITORY_SLUG:-cypherair/cypherair}"

XCFRAMEWORK_ZIP="PgpMobile.xcframework.zip"
XCFRAMEWORK_CHECKSUM="PgpMobile.xcframework.sha256"
ARM64E_MANIFEST="PgpMobile.arm64e-build-manifest.json"

log() { echo "[ci_post_clone] $*"; }
fail() { echo "[ci_post_clone] error: $*" >&2; exit 1; }

# Xcode Cloud exports workflow secrets into the hook environment, where every
# child process would inherit them. Capture what this script needs into an
# unexported shell variable, scrub the rest, and reinject per call site.
CAPTURED_GITHUB_PAT=""
capture_and_scrub_secrets() {
    CAPTURED_GITHUB_PAT="${GITHUB_PAT:-}"
    unset GITHUB_PAT ASC_ISSUER_ID ASC_KEY_ID ASC_PRIVATE_KEY ASC_PRIVATE_KEY_PATH
}

# gh credentials live only in this throwaway config dir, never in gh's default
# store or the host keyring, so clear_gh_auth can destroy every on-disk trace
# of the PAT before untrusted-adjacent subprocesses run. Defined before the
# EXIT/INT/TERM trap below installs, so the handler never references an
# undefined function.
GH_SCOPED_CONFIG_DIR=""
clear_gh_auth() {
    if [ -n "$GH_SCOPED_CONFIG_DIR" ]; then
        rm -rf "$GH_SCOPED_CONFIG_DIR"
        GH_SCOPED_CONFIG_DIR=""
        unset GH_CONFIG_DIR
    fi
}

# Keep stdout active so Xcode Cloud's ~30 minute inactivity timeout does not
# cancel the long, deliberately uncached Rust build.
HEARTBEAT_PID=""
start_heartbeat() {
    ( while true; do sleep 240; echo "[ci_post_clone] heartbeat $(date -u +%Y-%m-%dT%H:%M:%SZ)"; done ) &
    HEARTBEAT_PID=$!
}
stop_heartbeat() {
    if [ -n "$HEARTBEAT_PID" ]; then
        kill "$HEARTBEAT_PID" 2>/dev/null || true
        HEARTBEAT_PID=""
    fi
}
cleanup_on_exit() {
    stop_heartbeat
    clear_gh_auth
}
trap cleanup_on_exit EXIT INT TERM

require_repo_path() {
    [ -n "${CI_PRIMARY_REPOSITORY_PATH:-}" ] || fail "CI_PRIMARY_REPOSITORY_PATH is not set"
    cd "$CI_PRIMARY_REPOSITORY_PATH"
}

ensure_homebrew_formula() {
    # Xcode Cloud forbids sudo; Homebrew is available and installs to a
    # user-writable prefix.
    local formula="$1"
    if ! command -v "$formula" >/dev/null 2>&1; then
        log "Installing $formula via Homebrew"
        brew install "$formula"
    fi
}

require_gh_auth() {
    ensure_homebrew_formula gh
    [ -n "$CAPTURED_GITHUB_PAT" ] || fail "GITHUB_PAT secret is required for stage1/SQLCipher release verification"
    if [ -z "$GH_SCOPED_CONFIG_DIR" ]; then
        GH_SCOPED_CONFIG_DIR="$(mktemp -d)"
        export GH_CONFIG_DIR="$GH_SCOPED_CONFIG_DIR"
        log "authenticating gh (scoped config dir)"
        # --insecure-storage is deliberate: it forces the token into hosts.yml
        # inside the scoped dir (deterministically removable by clear_gh_auth)
        # instead of the runner's keyring, where rm -rf could not reach it and
        # the PAT would silently outlive its intended window.
        printf '%s' "$CAPTURED_GITHUB_PAT" | gh auth login --with-token --insecure-storage
    fi
}

ensure_rust_stable() {
    if ! command -v rustup >/dev/null 2>&1; then
        log "Installing rustup (stable, minimal)"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain stable
    fi
    # shellcheck disable=SC1090
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    rustup toolchain install stable --profile minimal
    rustup component add rustfmt --toolchain stable
}

project_setting() {
    # Read a resolved Xcode build setting (MARKETING_VERSION / CURRENT_PROJECT_VERSION).
    local key="$1"
    xcodebuild -showBuildSettings -scheme CypherAir -project CypherAir.xcodeproj 2>/dev/null \
        | sed -n "s/^[[:space:]]*${key} = //p" | head -n1
}

build_xcframework_workflow() {
    log "WF1: building arm64e PgpMobile.xcframework from source"
    ensure_homebrew_formula zstd
    ensure_rust_stable

    log "WF1: Rust dependency audit gate"
    cargo +stable install cargo-audit --version 0.22.2 --locked
    cargo audit --file pgp-mobile/Cargo.lock --deny warnings

    log "WF1: arm64e dependency-chain freshness gate"
    python3 scripts/arm64e_release_metadata.py \
        --cargo-lock pgp-mobile/Cargo.lock \
        --output arm64e-dependency-chain.json \
        --freshness-level "${ARM64E_DEPENDENCY_FRESHNESS_LEVEL:-error}"

    log "WF1: downloading pinned arm64e stage1 toolchain (token-free, digest-pinned)"
    local stage1_env_file
    stage1_env_file="$(mktemp)"
    GITHUB_ENV="$stage1_env_file" scripts/download_arm64e_stage1_toolchain.sh \
        "$PWD/pgp-mobile/target/apple-arm64e-stage1"

    log "WF1: verifying stage1 release immutability and asset attestations"
    require_gh_auth
    scripts/verify_arm64e_stage1_release.sh "$PWD/pgp-mobile/target/apple-arm64e-stage1/download"
    # Last pre-build step that needs the PAT. Wipe the gh credential store so
    # the stage1 compiler and cargo build scripts/proc-macros below cannot read
    # the token from disk (the environment was already scrubbed in main()).
    clear_gh_auth

    log "WF1: building xcframework (verified pinned stage1, no Cargo cache)"
    # The download script emits ARM64E_STAGE1_DIR / ARM64E_RUST_STAGE1_MANIFEST /
    # ARM64E_STAGE1_FORCE_DOWNLOAD=0 in GITHUB_ENV format (KEY=VALUE lines, no
    # quoting; the Xcode Cloud workspace path contains no spaces). Export them
    # so the build consumes the exact verified bytes instead of re-downloading.
    # shellcheck disable=SC1090
    set -a; . "$stage1_env_file"; set +a
    rm -f "$stage1_env_file"
    ./build-xcframework.sh --release

    [ -f "PgpMobile.xcframework/Info.plist" ] || fail "xcframework build did not produce PgpMobile.xcframework"
    [ -f "$ARM64E_MANIFEST" ] || fail "xcframework build did not produce $ARM64E_MANIFEST"
    log "WF1: restoring pinned SQLCipher.xcframework for app link preflight"
    require_gh_auth
    scripts/restore_sqlcipher_xcframework.sh --require-attestation
    log "WF1: xcframework build complete"
}

release_consumer_workflow() {
    log "WF2: consuming the published xcframework for the App Store archive"
    [ -n "${CI_TAG:-}" ] || fail "WF2 must be started for a stable tag (CI_TAG is empty)"
    require_gh_auth

    log "WF2: downloading attested xcframework assets for $CI_TAG"
    gh release download "$CI_TAG" -R "$GITHUB_REPOSITORY_SLUG" \
        --pattern "$XCFRAMEWORK_ZIP" \
        --pattern "$XCFRAMEWORK_CHECKSUM" \
        --pattern "$ARM64E_MANIFEST"

    log "WF2: verifying checksum"
    shasum -a 256 -c "$XCFRAMEWORK_CHECKSUM"

    log "WF2: extracting xcframework"
    rm -rf PgpMobile.xcframework
    ditto -x -k "$XCFRAMEWORK_ZIP" .
    [ -f "PgpMobile.xcframework/Info.plist" ] || fail "extracted xcframework is missing Info.plist"
    log "WF2: restoring pinned SQLCipher.xcframework for app archive"
    scripts/restore_sqlcipher_xcframework.sh --require-attestation

    local marketing_version build_number
    marketing_version="$(project_setting MARKETING_VERSION)"
    build_number="$(project_setting CURRENT_PROJECT_VERSION)"

    log "WF2: App Store candidate gate (tag/commit/manifest)"
    SOURCE_COMPLIANCE_REQUIRE_STABLE_RELEASE=YES \
    SOURCE_COMPLIANCE_REQUIRE_ARM64E_RELEASE_MANIFEST=YES \
    python3 scripts/validate_app_store_candidate_release.py \
        --repo-root "$PWD" \
        --marketing-version "$marketing_version" \
        --build-number "$build_number" \
        --github-repository "$GITHUB_REPOSITORY_SLUG" \
        --require-stable-release YES
    log "WF2: candidate gate passed"
}

main() {
    capture_and_scrub_secrets
    require_repo_path
    start_heartbeat
    log "workflow=${CI_WORKFLOW:-<unset>} tag=${CI_TAG:-<none>} commit=${CI_COMMIT:-<none>}"

    case "${CI_WORKFLOW:-}" in
        "$XCFRAMEWORK_WORKFLOW_NAME") build_xcframework_workflow ;;
        "$RELEASE_WORKFLOW_NAME") release_consumer_workflow ;;
        *)
            log "no release-specific post-clone work for workflow '${CI_WORKFLOW:-<unset>}'"
            ;;
    esac
}

main "$@"
