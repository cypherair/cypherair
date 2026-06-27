#!/bin/bash
# Xcode Cloud post-xcodebuild hook for CypherAir.
#
#   "PgpMobile XCFramework" (WF1): package the six stable SDK/compliance assets,
#       create the immutable stable GitHub Release as a DRAFT for the signed tag,
#       then start the "CypherAir Release" workflow (WF2) for the same tag via
#       the App Store Connect API. The draft keeps "immutable once published"
#       intact: WF2 finishes the asset set and flips the draft to published.
#
#   "CypherAir Release"    (WF2): attach the App Store-signed .ipa/.pkg produced
#       by each archive action to the draft release, then publish the release
#       once all platform artifacts are present (order-independent).
#
# Runs even when xcodebuild fails, so every path guards on CI_XCODEBUILD_EXIT_CODE.

set -euo pipefail

XCFRAMEWORK_WORKFLOW_NAME="${XCFRAMEWORK_WORKFLOW_NAME:-PgpMobile XCFramework}"
RELEASE_WORKFLOW_NAME="${RELEASE_WORKFLOW_NAME:-CypherAir Release}"
GITHUB_REPOSITORY_SLUG="${GITHUB_REPOSITORY_SLUG:-cypherair/cypherair}"
# App Store-signed upload artifacts WF2 attaches before the draft release is
# published. These are App Store Connect upload payloads (Transporter): NOT
# directly installable and NOT notarized (notarization is for Developer ID only).
XCODE_CLOUD_RELEASE_ARTIFACTS="${XCODE_CLOUD_RELEASE_ARTIFACTS:-CypherAir-iOS-AppStore.ipa CypherAir-visionOS-AppStore.ipa CypherAir-macOS-AppStore.pkg}"

XCFRAMEWORK_ZIP="PgpMobile.xcframework.zip"
XCFRAMEWORK_CHECKSUM="PgpMobile.xcframework.sha256"
ARM64E_MANIFEST="PgpMobile.arm64e-build-manifest.json"
SOURCE_BUNDLE="CypherAir-source-bundle.tar.zst"
COMPLIANCE_MANIFEST="CypherAir-compliance-manifest.json"
RELINK_KIT="PgpMobile-relink-kit.tar.zst"
SQLCIPHER_PIN_FILE="third_party/sqlcipher-xcframework.pin.json"

log() { echo "[ci_post_xcodebuild] $*"; }
fail() { echo "[ci_post_xcodebuild] error: $*" >&2; exit 1; }

require_repo_path() {
    [ -n "${CI_PRIMARY_REPOSITORY_PATH:-}" ] || fail "CI_PRIMARY_REPOSITORY_PATH is not set"
    cd "$CI_PRIMARY_REPOSITORY_PATH"
}

require_build_succeeded() {
    if [ "${CI_XCODEBUILD_EXIT_CODE:-0}" != "0" ]; then
        log "xcodebuild failed (exit ${CI_XCODEBUILD_EXIT_CODE:-?}); skipping release work"
        exit 0
    fi
}

require_gh_auth() {
    [ -n "${GITHUB_PAT:-}" ] || fail "GITHUB_PAT secret is required"
    command -v gh >/dev/null 2>&1 || brew install gh
    printf '%s' "$GITHUB_PAT" | gh auth login --with-token
}

project_setting() {
    local key="$1"
    xcodebuild -showBuildSettings -scheme CypherAir -project CypherAir.xcodeproj 2>/dev/null \
        | sed -n "s/^[[:space:]]*${key} = //p" | head -n1
}

# Reject a tag that is not an SSH-signed annotated tag pointing at CI_COMMIT.
# Mirrors the publish-time revalidation that previously lived in
# stable-build-release.yml.
revalidate_signed_tag() {
    local tag="$1" commit="$2"
    GITHUB_TOKEN="$GITHUB_PAT" python3 - "$GITHUB_REPOSITORY_SLUG" "$tag" "$commit" <<'PY'
import json
import subprocess
import sys

repo, tag, commit = sys.argv[1], sys.argv[2], sys.argv[3]


def gh_api(path):
    out = subprocess.run(["gh", "api", path], check=True, text=True, capture_output=True).stdout
    return json.loads(out)

ref = gh_api(f"repos/{repo}/git/ref/tags/{tag}")
obj = ref.get("object") or {}
if obj.get("type") != "tag":
    sys.exit(f"error: stable tag {tag} must be an annotated signed tag, got {obj.get('type')}")

tag_obj = gh_api(f"repos/{repo}/git/tags/{obj['sha']}")
errors = []
if tag_obj.get("tag") != tag:
    errors.append(f"tag object name {tag_obj.get('tag')!r} does not match {tag!r}")
target = tag_obj.get("object") or {}
if target.get("type") != "commit":
    errors.append(f"stable tag peels to {target.get('type')!r}, not commit")
elif target.get("sha") != commit:
    errors.append(f"stable tag resolves to {target.get('sha')}, expected {commit}")
verification = tag_obj.get("verification") or {}
if verification.get("verified") is not True:
    errors.append(f"stable tag signature not verified: {verification.get('reason')}")
if verification.get("reason") != "valid":
    errors.append(f"stable tag verification reason is {verification.get('reason')!r}")
if not (verification.get("signature") or "").startswith("-----BEGIN SSH SIGNATURE-----"):
    errors.append("stable tag must be SSH-signed")
if errors:
    sys.exit("error: " + "; ".join(errors))
print(f"stable tag {tag} is an SSH-signed annotated tag for {commit}")
PY
}

upload_release_asset_once() {
    local tag="$1" repo="$2" asset_path="$3" asset_name local_digest existing_asset_line existing_digest
    asset_name="$(basename "$asset_path")"
    local_digest="sha256:$(shasum -a 256 "$asset_path" | awk '{print $1}')"
    existing_asset_line="$(
        gh release view "$tag" -R "$repo" --json assets \
            --jq ".assets[] | select(.name == \"${asset_name}\") | [.name, (.digest // \"\")] | @tsv" 2>/dev/null || true
    )"

    if [ -n "$existing_asset_line" ]; then
        existing_digest="${existing_asset_line#*$'\t'}"
        [ -n "$existing_digest" ] || fail "release $tag already has $asset_name but GitHub did not return its digest; cannot safely retry upload"
        if [ "$existing_digest" = "$local_digest" ]; then
            log "release $tag already has $asset_name with matching digest; skipping upload"
            return
        fi
        fail "release $tag already has $asset_name with digest $existing_digest, expected $local_digest; create a fresh draft or clean the bad draft before retrying"
    fi

    log "uploading $asset_name ($local_digest)"
    gh release upload "$tag" -R "$repo" "$asset_path"
}

package_and_publish_draft() {
    require_build_succeeded
    [ -n "${CI_TAG:-}" ] || fail "WF1 must run for a stable tag (CI_TAG empty)"
    [ -n "${CI_COMMIT:-}" ] || fail "CI_COMMIT is empty"
    [ -f "PgpMobile.xcframework/Info.plist" ] || fail "PgpMobile.xcframework missing (WF1 post-clone build did not run?)"
    require_gh_auth

    # shellcheck disable=SC1090
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

    local marketing_version build_number built_at xcode_version rustc_version
    marketing_version="$(project_setting MARKETING_VERSION)"
    build_number="$(project_setting CURRENT_PROJECT_VERSION)"
    built_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    xcode_version="$(xcodebuild -version | tr '\n' ' ' | sed 's/  */ /g; s/ $//')"
    rustc_version="$(rustc +stable --version 2>/dev/null || echo 'rustc (unavailable)')"

    log "WF1: validating tag/version match"
    [ "$CI_TAG" = "cypherair-v${marketing_version}-build${build_number}" ] \
        || fail "tag $CI_TAG does not match cypherair-v${marketing_version}-build${build_number}"
    revalidate_signed_tag "$CI_TAG" "$CI_COMMIT"

    log "WF1: packaging stable SDK + compliance assets"
    ditto -c -k --sequesterRsrc --keepParent PgpMobile.xcframework "$XCFRAMEWORK_ZIP"
    shasum -a 256 "$XCFRAMEWORK_ZIP" > "$XCFRAMEWORK_CHECKSUM"

    python3 scripts/build_xcframework_relink_kit.py \
        --release-tag "$CI_TAG" \
        --marketing-version "$marketing_version" \
        --build-number "$build_number" \
        --commit-sha "$CI_COMMIT" \
        --xcframework-zip "$XCFRAMEWORK_ZIP" \
        --arm64e-manifest "$ARM64E_MANIFEST" \
        --output "$RELINK_KIT"

    python3 scripts/build_compliance_release_assets.py \
        --release-tag "$CI_TAG" \
        --channel stable \
        --marketing-version "$marketing_version" \
        --build-number "$build_number" \
        --commit-sha "$CI_COMMIT" \
        --source-bundle-output "$SOURCE_BUNDLE" \
        --manifest-output "$COMPLIANCE_MANIFEST" \
        --arm64e-manifest "$ARM64E_MANIFEST" \
        --external-binary-dependency "$SQLCIPHER_PIN_FILE" \
        --binary-asset "$XCFRAMEWORK_ZIP" \
        --binary-asset "$XCFRAMEWORK_CHECKSUM" \
        --binary-asset "$ARM64E_MANIFEST" \
        --binary-asset "$RELINK_KIT"

    cat > release-notes.md <<EOF
Exact source and compliance materials for stable build \`$CI_TAG\`.

- Release tag: \`$CI_TAG\`
- Commit: \`$CI_COMMIT\`
- Built at (UTC): \`$built_at\`
- App marketing version: \`$marketing_version\`
- App build number: \`$build_number\`
- Xcode: \`$xcode_version\`
- Rust: \`$rustc_version\`
- Built by: Xcode Cloud workflow \`$CI_WORKFLOW\` (build $CI_BUILD_NUMBER)

This stable build page is the exact source and compliance landing page for the
tagged App build and the stable \`PgpMobile.xcframework\` assets.

The \`CypherAir-*-AppStore.ipa\`/\`.pkg\` files are **App Store Connect upload
artifacts** (Transporter) attached by the "CypherAir Release" workflow before the
release is published. They are App-Store-signed: not directly installable and not
notarized (Apple reviews App Store builds; notarization applies only to
Developer ID distribution). Use them only to upload to App Store Connect.
EOF

    if gh release view "$CI_TAG" -R "$GITHUB_REPOSITORY_SLUG" >/dev/null 2>&1; then
        fail "release $CI_TAG already exists; stable assets are immutable"
    fi

    log "WF1: creating DRAFT stable release"
    gh release create "$CI_TAG" -R "$GITHUB_REPOSITORY_SLUG" \
        --draft \
        --verify-tag \
        --target "$CI_COMMIT" \
        --title "CypherAir Stable Build ($CI_TAG)" \
        --notes-file release-notes.md \
        "$SOURCE_BUNDLE" \
        "$COMPLIANCE_MANIFEST" \
        "$XCFRAMEWORK_ZIP" \
        "$XCFRAMEWORK_CHECKSUM" \
        "$ARM64E_MANIFEST" \
        "$RELINK_KIT"

    log "WF1: starting '$RELEASE_WORKFLOW_NAME' for $CI_TAG via App Store Connect API"
    python3 -m pip install --user --quiet 'pyjwt[crypto]>=2.8'
    python3 scripts/asc_start_build.py \
        --workflow-name "$RELEASE_WORKFLOW_NAME" \
        --git-tag "$CI_TAG"
}

attach_app_artifact_and_maybe_publish() {
    require_build_succeeded
    [ -n "${CI_TAG:-}" ] || fail "WF2 must run for a stable tag (CI_TAG empty)"
    require_gh_auth

    local platform ext signed_path artifact_path asset_name staging_dir staged_artifact
    case "${CI_PRODUCT_PLATFORM:-}" in
        iOS) platform="iOS"; ext="ipa" ;;
        macOS) platform="macOS"; ext="pkg" ;;
        xrOS|visionOS) platform="visionOS"; ext="ipa" ;;
        *) platform="${CI_PRODUCT_PLATFORM:-unknown}"; ext="ipa" ;;
    esac
    # The -AppStore suffix marks these as App Store Connect upload payloads
    # (Transporter): App-Store-signed, not directly installable, not notarized.
    asset_name="CypherAir-${platform}-AppStore.${ext}"

    # App Store package from the archive's "TestFlight & App Store" deployment.
    # This is NOT a Developer ID build and cannot be notarized.
    signed_path="${CI_APP_STORE_SIGNED_APP_PATH:-}"
    [ -d "$signed_path" ] || fail "CI_APP_STORE_SIGNED_APP_PATH is not a directory: $signed_path"
    artifact_path="$(find "$signed_path" -maxdepth 2 -name "*.${ext}" -print -quit)"
    [ -n "$artifact_path" ] || fail "no .${ext} found under $signed_path"

    staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/cypherair-release-asset.XXXXXX")"
    staged_artifact="$staging_dir/$asset_name"
    cp "$artifact_path" "$staged_artifact"

    log "WF2: attaching $asset_name from $artifact_path"
    upload_release_asset_once "$CI_TAG" "$GITHUB_REPOSITORY_SLUG" "$staged_artifact"

    # Publish only once every expected platform artifact is present, so the
    # last archive action to finish flips the draft regardless of action order.
    local present
    present="$(gh release view "$CI_TAG" -R "$GITHUB_REPOSITORY_SLUG" --json assets --jq '[.assets[].name] | join(" ")')"
    local missing=0 expected
    for expected in $XCODE_CLOUD_RELEASE_ARTIFACTS; do
        case " $present " in
            *" $expected "*) ;;
            *) missing=1; log "WF2: still waiting for $expected" ;;
        esac
    done

    if [ "$missing" = "0" ]; then
        log "WF2: all platform artifacts present; publishing release $CI_TAG"
        gh release edit "$CI_TAG" -R "$GITHUB_REPOSITORY_SLUG" --draft=false --latest
    fi
}

main() {
    require_repo_path
    log "workflow=${CI_WORKFLOW:-<unset>} platform=${CI_PRODUCT_PLATFORM:-<none>} action=${CI_XCODEBUILD_ACTION:-<none>}"
    case "${CI_WORKFLOW:-}" in
        "$XCFRAMEWORK_WORKFLOW_NAME") package_and_publish_draft ;;
        "$RELEASE_WORKFLOW_NAME") attach_app_artifact_and_maybe_publish ;;
        *) log "no release-specific post-xcodebuild work for workflow '${CI_WORKFLOW:-<unset>}'" ;;
    esac
}

main "$@"
