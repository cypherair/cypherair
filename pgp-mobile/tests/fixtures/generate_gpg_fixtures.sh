#!/usr/bin/env bash
# Generate GnuPG interoperability test fixtures for Cypher Air POC.
# These fixtures validate C3.1–C3.8 (GnuPG interop) and C2A.9/C2B.10 (DEFLATE).
#
# Requirements: GnuPG 2.4.x
# Output: All fixtures written to the same directory as this script.
#
# IMPORTANT: This script creates a temporary GNUPGHOME and cleans it up.
# It does NOT touch your real GnuPG keyring.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GNUPGHOME_TMP="$(mktemp -d)"
export GNUPGHOME="$GNUPGHOME_TMP"

cleanup() {
    rm -rf "$GNUPGHOME_TMP"
}
trap cleanup EXIT

# Configure gpg for non-interactive use
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
cat > "$GNUPGHOME/gpg.conf" <<'GPGCONF'
no-tty
batch
yes
trust-model always
force-mdc
GPGCONF

cat > "$GNUPGHOME/gpg-agent.conf" <<'AGENTCONF'
allow-preset-passphrase
AGENTCONF

# Kill any existing gpg-agent for this GNUPGHOME
gpgconf --kill gpg-agent 2>/dev/null || true

echo "=== Generating GnuPG test fixtures ==="
echo "GnuPG version: $(gpg --version | head -1)"
echo "GNUPGHOME: $GNUPGHOME"
echo ""

# ── 1. Generate a GnuPG Ed25519 key (compatible with Profile A) ──
echo "--- Generating GnuPG Ed25519 key ---"
cat > "$GNUPGHOME/keygen-params" <<'PARAMS'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign,cert
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: GnuPG Test User
Name-Email: gnupg-test@example.com
Expire-Date: 0
# Explicitly set preferences WITHOUT AEAD algorithms.
# GnuPG 2.4.x automatically adds AEAD preferences (pref-aead-algos) and sets
# the AEAD feature bit, causing it to produce AEAD Encrypted Data Packet v0
# (a pre-RFC 9580 draft format). Sequoia correctly rejects this as insecure
# because v0 AEAD is NOT the same as RFC 9580 SEIPDv2.
# By specifying preferences without AEAD, the key will only advertise SEIPDv1
# (MDC) support, ensuring GnuPG produces standard encrypted data packets (tag 18).
Preferences: AES256 AES192 AES SHA512 SHA384 SHA256 ZLIB BZIP2 ZIP
%commit
PARAMS

gpg --gen-key --batch "$GNUPGHOME/keygen-params"
GPG_FPR=$(gpg --list-keys --with-colons gnupg-test@example.com | grep '^fpr' | head -1 | cut -d: -f10)
echo "Generated key: $GPG_FPR"

# Export GnuPG public key (for C3.1: App imports gpg pubkey)
gpg --export --armor gnupg-test@example.com > "$SCRIPT_DIR/gpg_pubkey.asc"
echo "Exported: gpg_pubkey.asc"

# Export GnuPG public key in binary (for direct Rust consumption)
gpg --export gnupg-test@example.com > "$SCRIPT_DIR/gpg_pubkey.gpg"
echo "Exported: gpg_pubkey.gpg"

# ── 2. GnuPG encrypts a message (for C3.4: App decrypts gpg-encrypted message) ──
# We need to encrypt TO a Sequoia-generated key. But since we can't run Sequoia here,
# we encrypt to the gpg key itself (self-encrypt). The Rust test will generate a
# Sequoia Profile A key, export it, and we provide gpg-encrypted-to-gpg-key fixtures
# that demonstrate gpg's output format.
#
# Strategy: encrypt to gpg's own key. The Rust test will:
# 1. Import gpg's public key into Sequoia
# 2. Use Sequoia to decrypt (needs the private key)
# Instead, we'll encrypt to gpg's own key AND export the private key so Rust tests
# can import it and decrypt.

echo "--- Encrypting test messages with GnuPG ---"

# Plain text message
echo -n "Hello from GnuPG! This is a test message for Cypher Air interop testing." > "$GNUPGHOME/plaintext.txt"

# Encrypt (armored, for text)
gpg --encrypt --armor --recipient gnupg-test@example.com \
    --output "$SCRIPT_DIR/gpg_encrypted_message.asc" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_encrypted_message.asc"

# Encrypt (binary, for file interop)
gpg --encrypt --recipient gnupg-test@example.com \
    --output "$SCRIPT_DIR/gpg_encrypted_message.gpg" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_encrypted_message.gpg"

# Save the plaintext for verification
cp "$GNUPGHOME/plaintext.txt" "$SCRIPT_DIR/gpg_plaintext.txt"
echo "Exported: gpg_plaintext.txt"

# ── 3. GnuPG signs a message (for C3.5: App verifies gpg signature) ──
echo "--- Signing test messages with GnuPG ---"

# Cleartext signature
gpg --clearsign --armor --local-user gnupg-test@example.com \
    --output "$SCRIPT_DIR/gpg_cleartext_signed.asc" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_cleartext_signed.asc"

# Detached signature (armored)
gpg --detach-sign --armor --local-user gnupg-test@example.com \
    --output "$SCRIPT_DIR/gpg_detached_sig.asc" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_detached_sig.asc"

# Detached signature (binary)
gpg --detach-sign --local-user gnupg-test@example.com \
    --output "$SCRIPT_DIR/gpg_detached_sig.sig" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_detached_sig.sig"

# ── 4. Export GnuPG secret key (for Rust tests to decrypt gpg-encrypted messages) ──
echo "--- Exporting GnuPG secret key ---"
gpg --export-secret-keys --armor gnupg-test@example.com > "$SCRIPT_DIR/gpg_secretkey.asc"
echo "Exported: gpg_secretkey.asc"

# ── 5. GnuPG encrypts with DEFLATE compression (for C2A.9) ──
echo "--- Generating DEFLATE compressed encrypted message ---"

# Force compression with DEFLATE (algo 1 = ZIP/DEFLATE)
gpg --encrypt --armor --recipient gnupg-test@example.com \
    --compress-algo 1 --compress-level 6 \
    --output "$SCRIPT_DIR/gpg_encrypted_compressed_deflate.asc" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_encrypted_compressed_deflate.asc"

# Also with ZLIB (algo 2) for broader test coverage
gpg --encrypt --armor --recipient gnupg-test@example.com \
    --compress-algo 2 --compress-level 6 \
    --output "$SCRIPT_DIR/gpg_encrypted_compressed_zlib.asc" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_encrypted_compressed_zlib.asc"

# ── 6. GnuPG cleartext signed + compressed (for completeness) ──
echo "--- Generating compressed signed message ---"
gpg --sign --armor --recipient gnupg-test@example.com \
    --compress-algo 1 --compress-level 6 \
    --output "$SCRIPT_DIR/gpg_signed_compressed.asc" \
    "$GNUPGHOME/plaintext.txt"
echo "Exported: gpg_signed_compressed.asc"

# ── 7. Tampered ciphertext (for C3.6: tamper 1 bit → gpg fails) ──
# We create a tampered version of the encrypted message for verification
echo "--- Generating tampered ciphertext ---"
cp "$SCRIPT_DIR/gpg_encrypted_message.gpg" "$SCRIPT_DIR/gpg_encrypted_tampered.gpg"
# Flip one bit near the middle of the binary ciphertext
python3 -c "
import os
data = bytearray(open('$SCRIPT_DIR/gpg_encrypted_tampered.gpg', 'rb').read())
mid = len(data) * 4 // 5
data[mid] ^= 0x01
open('$SCRIPT_DIR/gpg_encrypted_tampered.gpg', 'wb').write(data)
print(f'Tampered byte at offset {mid} (file size: {len(data)} bytes)')
"
echo "Exported: gpg_encrypted_tampered.gpg"

# ── 8. Test GnuPG rejection of Profile B v6 key (for C3.8) ──
# The v6 public key fixture must be pre-generated by Sequoia (run the
# `test_generate_v6_fixture` ignored test before running this script).
if [ -f "$SCRIPT_DIR/profile_b_v6_pubkey.gpg" ]; then
    echo "--- Testing GnuPG rejection of v6 key ---"
    # GnuPG 2.4.x cannot import v6 keys. Capture the exact error output.
    if gpg --import "$SCRIPT_DIR/profile_b_v6_pubkey.gpg" > "$SCRIPT_DIR/gpg_v6_import_rejection.txt" 2>&1; then
        echo "WARNING: GnuPG unexpectedly accepted v6 key import!"
        echo "gpg_import_exit_code=0" >> "$SCRIPT_DIR/gpg_v6_import_rejection.txt"
    else
        echo "gpg_import_exit_code=$?" >> "$SCRIPT_DIR/gpg_v6_import_rejection.txt"
        echo "GnuPG correctly rejected v6 key import (expected behavior)"
    fi
    echo "Exported: gpg_v6_import_rejection.txt"
else
    echo "--- Skipping v6 rejection test (profile_b_v6_pubkey.gpg not found) ---"
    echo "Run 'cargo test test_generate_v6_fixture -- --ignored' first to generate it."
fi

# ── 9. Record GnuPG version info ──
echo ""
echo "=== Fixture generation complete ==="
gpg --version > "$SCRIPT_DIR/gpg_version.txt"
echo "GnuPG version recorded in gpg_version.txt"

echo ""
echo "Generated fixtures:"
ls -la "$SCRIPT_DIR"/*.asc "$SCRIPT_DIR"/*.gpg "$SCRIPT_DIR"/*.sig "$SCRIPT_DIR"/*.txt 2>/dev/null
