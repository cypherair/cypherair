#!/usr/bin/env bash
# Generate `sq` (sequoia-sq) cross-tool interoperability fixtures for CypherAir.
# These fixtures preserve the real-`sq` evidence for issue #567: another
# OpenPGP implementation's certificates, encrypted messages, and signatures
# across every portable key family, including the RFC 9980 post-quantum tiers.
#
# Requirements: sequoia-sq 1.4.x or later (fixtures last generated with sq 1.4.0
# on sequoia-openpgp 2.4.0; the exact versions are recorded in sq_version.txt).
# Output: All fixtures written to the same directory as this script.
#
# IMPORTANT: This script creates a temporary `sq --home` and cleans it up.
# It does NOT touch your real sq cert store or key store.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQ_HOME_TMP="$(mktemp -d)"

cleanup() {
    rm -rf "$SQ_HOME_TMP"
}
trap cleanup EXIT

if ! command -v sq > /dev/null 2>&1; then
    echo "error: sq not found on PATH (brew install sequoia-sq)" >&2
    exit 1
fi

echo "=== Generating sq interoperability fixtures ==="
sq version
echo "sq home (temporary): $SQ_HOME_TMP"
echo ""

# Shared plaintext for every encrypted/signed fixture (no trailing newline).
printf '%s' "Hello from sq! This is a CypherAir cross-tool interop fixture (issue #567)." \
    > "$SCRIPT_DIR/sq_plaintext.txt"
echo "Exported: sq_plaintext.txt"

# ── Per-suite generation ────────────────────────────────────────────────────
# Suites mirror the portable key families (docs/TESTING.md §3):
#   legacy      v4 Ed25519/X25519 (sq default profile, RFC 4880)
#   modern      v6 Ed25519/X25519 (RFC 9580)
#   modernhigh  v6 Ed448/X448 (RFC 9580)
#   pq          v6 ML-DSA-65+Ed25519 / ML-KEM-768+X25519 (RFC 9980)
#   pqhigh      v6 ML-DSA-87+Ed448 / ML-KEM-1024+X448 (RFC 9980)
#
# Per suite: armored public cert, armored secret key (TSK), an encrypted
# message to its own key (unsigned), an inline-signed message, and an
# armored detached signature — all over sq_plaintext.txt.
generate_suite() {
    local name="$1"
    local label="$2"
    local cipher_suite="$3"
    local profile_flag="${4:-}"
    local email="sq-${name}-test@example.com"

    echo "--- Suite: ${name} (${cipher_suite}${profile_flag:+ ${profile_flag}}) ---"

    # shellcheck disable=SC2086  # profile_flag is deliberately word-split
    sq --home "$SQ_HOME_TMP" key generate \
        --own-key --without-password \
        --name "SQ ${label} Test User" --email "$email" \
        --cipher-suite "$cipher_suite" $profile_flag \
        --expiration never

    sq --home "$SQ_HOME_TMP" cert export --cert-email "$email" \
        --output "$SCRIPT_DIR/sq_${name}_pubkey.asc"
    echo "Exported: sq_${name}_pubkey.asc"

    sq --home "$SQ_HOME_TMP" key export --cert-email "$email" \
        --output "$SCRIPT_DIR/sq_${name}_secretkey.asc"
    echo "Exported: sq_${name}_secretkey.asc"

    # Encrypt to the suite's own certificate. --for-file bypasses the cert
    # store trust gate; --without-signature keeps the fixture recipient-only.
    sq --home "$SQ_HOME_TMP" encrypt \
        --for-file "$SCRIPT_DIR/sq_${name}_pubkey.asc" \
        --without-signature \
        --output "$SCRIPT_DIR/sq_${name}_encrypted.asc" \
        "$SCRIPT_DIR/sq_plaintext.txt"
    echo "Exported: sq_${name}_encrypted.asc"

    sq --home "$SQ_HOME_TMP" sign --message \
        --signer-file "$SCRIPT_DIR/sq_${name}_secretkey.asc" \
        --output "$SCRIPT_DIR/sq_${name}_inline_signed.asc" \
        "$SCRIPT_DIR/sq_plaintext.txt"
    echo "Exported: sq_${name}_inline_signed.asc"

    sq --home "$SQ_HOME_TMP" sign \
        --signature-file "$SCRIPT_DIR/sq_${name}_detached_sig.asc" \
        --signer-file "$SCRIPT_DIR/sq_${name}_secretkey.asc" \
        "$SCRIPT_DIR/sq_plaintext.txt"
    echo "Exported: sq_${name}_detached_sig.asc"

    echo ""
}

generate_suite legacy     "Legacy"          cv25519
generate_suite modern     "Modern"          cv25519         "--profile rfc9580"
generate_suite modernhigh "Modern High"     cv448           "--profile rfc9580"
generate_suite pq         "Post-Quantum"    mldsa65-ed25519 "--profile rfc9580"
generate_suite pqhigh     "Post-Quantum High" mldsa87-ed448 "--profile rfc9580"

# ── Record sq / sequoia versions ────────────────────────────────────────────
sq version > "$SCRIPT_DIR/sq_version.txt" 2>&1
echo "sq version recorded in sq_version.txt"

echo ""
echo "=== Fixture generation complete ==="
ls -la "$SCRIPT_DIR"/sq_*.asc "$SCRIPT_DIR"/sq_*.txt
