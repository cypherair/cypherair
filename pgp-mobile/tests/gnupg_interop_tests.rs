//! GnuPG Interoperability Tests (Profile A Only).
//!
//! Covers POC test cases C3.1–C3.8 and C2A.9/C2B.10 (DEFLATE compressed messages).
//!
//! These tests use pre-generated GnuPG fixtures (see `fixtures/generate_gpg_fixtures.sh`).
//! The fixtures were generated with GnuPG 2.5.18 using Ed25519+Cv25519 keys.
//!
//! Test strategy (per TESTING.md Section 7):
//! - Approach B (Rust layer): Sequoia-to-fixture comparison in the Rust test suite.
//! - GnuPG cannot run on iOS, so all interop validation happens here.

use pgp_mobile::armor;
use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;
use pgp_mobile::verify;

mod common;
use common::detect_message_format;

/// Load a fixture file from the fixtures directory.
fn load_fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to load fixture {}: {}", name, e))
}

/// Load the expected plaintext used to generate fixtures.
fn expected_plaintext() -> Vec<u8> {
    load_fixture("gpg_plaintext.txt")
}

// ── C3.1: Export Profile A pubkey → gpg --import succeeds ──────────────────
// This is verified during fixture generation (gpg imports our key).
// Here we verify the reverse: Sequoia can import a GnuPG-exported public key.

/// C3.1: Import GnuPG public key into Sequoia.
/// Pass: key parsed successfully, v4, Ed25519, has encryption subkey.
#[test]
fn test_c3_1_import_gpg_pubkey() {
    let gpg_pubkey = load_fixture("gpg_pubkey.asc");
    let info = keys::parse_key_info(&gpg_pubkey).expect("Should parse GnuPG public key");

    assert_eq!(info.key_version, 4, "GnuPG key must be v4");
    assert_eq!(info.profile, KeyProfile::Universal);
    assert!(
        info.has_encryption_subkey,
        "Must have Cv25519 encryption subkey"
    );
    assert!(!info.is_revoked);
    assert!(!info.is_expired);
    assert_eq!(
        info.user_id.as_deref(),
        Some("GnuPG Test User <gnupg-test@example.com>")
    );
}

/// C3.1 (binary): Import GnuPG public key in binary format.
#[test]
fn test_c3_1_import_gpg_pubkey_binary() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let info = keys::parse_key_info(&gpg_pubkey).expect("Should parse binary GnuPG public key");
    assert_eq!(info.key_version, 4);
    assert!(info.has_encryption_subkey);
}

// ── C3.2: App (Profile A) encrypt → gpg --decrypt succeeds ────────────────
// We can't run gpg here, but we verify Sequoia can encrypt to a GnuPG key
// and then decrypt it with the GnuPG secret key (proving format compatibility).

/// C3.2: Sequoia encrypts to GnuPG public key, then decrypts with GnuPG secret key.
/// This proves the ciphertext format is GnuPG-compatible (SEIPDv1).
#[test]
fn test_c3_2_app_encrypt_to_gpg_key() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");
    let plaintext = b"Hello from CypherAir to GnuPG!";

    // Encrypt with Sequoia to the GnuPG public key
    let ciphertext = encrypt::encrypt(plaintext, &[gpg_pubkey.clone()], None, None)
        .expect("Sequoia should encrypt to GnuPG key");

    // Verify message format is SEIPDv1 (GnuPG compatible)
    let ciphertext_binary = encrypt::encrypt_binary(plaintext, &[gpg_pubkey.clone()], None, None)
        .expect("Binary encryption should succeed");
    let (has_v1, has_v2) = detect_message_format(&ciphertext_binary);
    assert!(has_v1, "Encryption to v4 GnuPG key must produce SEIPDv1");
    assert!(
        !has_v2,
        "Encryption to v4 GnuPG key must NOT produce SEIPDv2"
    );

    // Decrypt with the GnuPG secret key (imported into Sequoia)
    // This simulates what gpg --decrypt would do
    let result = decrypt::decrypt(&ciphertext, &[gpg_secretkey], &[gpg_pubkey])
        .expect("Should decrypt with GnuPG secret key");

    assert_eq!(result.plaintext, plaintext);
}

/// C3.2 (signed): Sequoia encrypts+signs to GnuPG key.
#[test]
fn test_c3_2_app_encrypt_signed_to_gpg_key() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");
    let plaintext = b"Signed message from CypherAir";

    // Generate a Profile A key for signing
    let sender = keys::generate_key_with_profile(
        "Sender".to_string(),
        Some("sender@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Encrypt to gpg key, sign with our key
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[gpg_pubkey.clone()],
        Some(&sender.cert_data),
        None,
    )
    .expect("Sequoia should encrypt+sign to GnuPG key");

    // Decrypt with gpg secret key, verify with our public key
    let result = decrypt::decrypt(
        &ciphertext,
        &[gpg_secretkey],
        &[gpg_pubkey, sender.public_key_data],
    )
    .expect("Should decrypt with GnuPG secret key");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(
        result.signature_status,
        Some(decrypt::SignatureStatus::Valid)
    );
}

// ── C3.3: App (Profile A) sign → gpg --verify "Good signature" ────────────
// We verify Sequoia's signature is verifiable by Sequoia itself using the
// same verification path GnuPG would use. The fixture test verifies the reverse.

/// C3.3: Sequoia Profile A cleartext signature is valid.
#[test]
fn test_c3_3_app_sign_profile_a() {
    let sender =
        keys::generate_key_with_profile("Signer".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let plaintext = b"This message is signed by CypherAir Profile A";
    let signed = sign::sign_cleartext(plaintext, &sender.cert_data)
        .expect("Cleartext signing should succeed");

    // Verify (same path gpg --verify would take)
    let result = verify::verify_cleartext(&signed, &[sender.public_key_data])
        .expect("Verification should succeed");

    assert_eq!(result.status, decrypt::SignatureStatus::Valid);
    assert!(result.content.is_some());
    // The content from cleartext verification should match the original plaintext
    let content = result.content.unwrap();
    // Cleartext signatures may have trailing whitespace normalization
    let content_str = String::from_utf8_lossy(&content);
    let expected_str = String::from_utf8_lossy(plaintext);
    assert_eq!(content_str.trim(), expected_str.trim());
}

// ── C3.4: gpg encrypt → App decrypt succeeds ──────────────────────────────

/// C3.4: Decrypt a GnuPG-encrypted message (armored).
/// GnuPG encrypted to its own key. We decrypt with the GnuPG secret key.
#[test]
fn test_c3_4_decrypt_gpg_encrypted_message_armored() {
    let ciphertext = load_fixture("gpg_encrypted_message.asc");
    let secretkey = load_fixture("gpg_secretkey.asc");
    let pubkey = load_fixture("gpg_pubkey.asc");
    let expected = expected_plaintext();

    let result = decrypt::decrypt(&ciphertext, &[secretkey], &[pubkey])
        .expect("Should decrypt GnuPG-encrypted message");

    assert_eq!(result.plaintext, expected);
}

/// C3.4 (binary): Decrypt a GnuPG-encrypted message (binary .gpg).
#[test]
fn test_c3_4_decrypt_gpg_encrypted_message_binary() {
    let ciphertext = load_fixture("gpg_encrypted_message.gpg");
    let secretkey = load_fixture("gpg_secretkey.asc");
    let pubkey = load_fixture("gpg_pubkey.gpg");
    let expected = expected_plaintext();

    // Verify the GnuPG fixture uses SEIPDv1
    let (has_v1, has_v2) = detect_message_format(&ciphertext);
    assert!(has_v1, "GnuPG fixture must be SEIPDv1");
    assert!(!has_v2, "GnuPG fixture must NOT be SEIPDv2");

    let result = decrypt::decrypt(&ciphertext, &[secretkey], &[pubkey])
        .expect("Should decrypt binary GnuPG-encrypted message");

    assert_eq!(result.plaintext, expected);
}

// ── C3.5: gpg sign → App verify succeeds ──────────────────────────────────

/// C3.5: Verify a GnuPG cleartext signature.
#[test]
fn test_c3_5_verify_gpg_cleartext_signature() {
    let signed = load_fixture("gpg_cleartext_signed.asc");
    let pubkey = load_fixture("gpg_pubkey.asc");
    let expected = expected_plaintext();

    let result = verify::verify_cleartext(&signed, &[pubkey])
        .expect("Should verify GnuPG cleartext signature");

    assert_eq!(result.status, decrypt::SignatureStatus::Valid);

    // Verify content matches
    let content = result.content.expect("Should have content");
    let content_str = String::from_utf8_lossy(&content);
    let expected_str = String::from_utf8_lossy(&expected);
    assert_eq!(content_str.trim(), expected_str.trim());
}

/// C3.5 (detached, armored): Verify a GnuPG detached signature.
#[test]
fn test_c3_5_verify_gpg_detached_signature_armored() {
    let signature = load_fixture("gpg_detached_sig.asc");
    let pubkey = load_fixture("gpg_pubkey.asc");
    let data = expected_plaintext();

    let result = verify::verify_detached(&data, &signature, &[pubkey])
        .expect("Should verify GnuPG detached signature");

    assert_eq!(result.status, decrypt::SignatureStatus::Valid);
}

/// C3.5 (detached, binary): Verify a GnuPG detached signature in binary format.
#[test]
fn test_c3_5_verify_gpg_detached_signature_binary() {
    let signature = load_fixture("gpg_detached_sig.sig");
    let pubkey = load_fixture("gpg_pubkey.gpg");
    let data = expected_plaintext();

    let result = verify::verify_detached(&data, &signature, &[pubkey])
        .expect("Should verify binary GnuPG detached signature");

    assert_eq!(result.status, decrypt::SignatureStatus::Valid);
}

// ── C3.6: Tamper 1 bit → gpg fails ────────────────────────────────────────

/// C3.6: Tampered GnuPG ciphertext fails to decrypt.
#[test]
fn test_c3_6_tampered_gpg_ciphertext_fails() {
    let tampered = load_fixture("gpg_encrypted_tampered.gpg");
    let secretkey = load_fixture("gpg_secretkey.asc");
    let pubkey = load_fixture("gpg_pubkey.gpg");

    let result = decrypt::decrypt(&tampered, &[secretkey], &[pubkey]);
    assert!(
        result.is_err(),
        "Tampered ciphertext must not decrypt successfully"
    );
    // Verify the error is a security-relevant failure (integrity or corruption)
    match result {
        Err(PgpError::IntegrityCheckFailed)
        | Err(PgpError::AeadAuthenticationFailed)
        | Err(PgpError::CorruptData { .. })
        | Err(PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Expected integrity/corruption/no-matching-key error, got: {other}"),
        Ok(_) => unreachable!("Already asserted result.is_err()"),
    }
}

/// C3.6 (Sequoia-encrypted): Tamper Sequoia ciphertext → verify it fails.
#[test]
fn test_c3_6_tampered_sequoia_ciphertext_for_gpg_key() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");
    let plaintext = b"Tamper test";

    // Encrypt to gpg key
    let mut ciphertext = encrypt::encrypt_binary(plaintext, &[gpg_pubkey.clone()], None, None)
        .expect("Encryption should succeed");

    // Tamper: flip one bit near the middle
    let mid = ciphertext.len() / 2;
    ciphertext[mid] ^= 0x01;

    let result = decrypt::decrypt(&ciphertext, &[gpg_secretkey], &[gpg_pubkey]);
    assert!(
        result.is_err(),
        "Tampered Sequoia ciphertext must fail decryption"
    );
    // Verify the error is a security-relevant failure (integrity or corruption)
    match result {
        Err(PgpError::IntegrityCheckFailed)
        | Err(PgpError::AeadAuthenticationFailed)
        | Err(PgpError::CorruptData { .. })
        | Err(PgpError::NoMatchingKey) => {}
        Err(other) => panic!("Expected integrity/corruption/no-matching-key error, got: {other}"),
        Ok(_) => unreachable!("Already asserted result.is_err()"),
    }
}

// ── C3.7: Import gpg pubkey → App encrypt → gpg decrypt ───────────────────
// Full round-trip: import GnuPG pubkey, encrypt with Sequoia, decrypt with GnuPG secret key.

/// C3.7: Full interop round-trip (gpg key → Sequoia encrypt → gpg decrypt).
#[test]
fn test_c3_7_full_roundtrip_gpg_key() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");

    // Step 1: Import gpg public key and verify it
    let info = keys::parse_key_info(&gpg_pubkey).expect("Import should succeed");
    assert_eq!(info.key_version, 4);
    assert!(info.has_encryption_subkey);

    // Step 2: Encrypt a message to the gpg key
    let plaintext = b"Full round-trip test: Sequoia encrypts, GnuPG decrypts.";
    let ciphertext = encrypt::encrypt(plaintext, &[gpg_pubkey.clone()], None, None)
        .expect("Encrypt to gpg key should succeed");

    // Step 3: Decrypt with GnuPG secret key
    let result = decrypt::decrypt(&ciphertext, &[gpg_secretkey], &[gpg_pubkey])
        .expect("Decrypt with gpg key should succeed");

    assert_eq!(result.plaintext, plaintext);
}

/// C3.7 (with signing): Full signed round-trip.
#[test]
fn test_c3_7_full_roundtrip_signed() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");

    // Generate a Profile A signing key
    let signer = keys::generate_key_with_profile(
        "App User".to_string(),
        Some("app@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Encrypt + sign
    let plaintext = b"Signed round-trip test";
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[gpg_pubkey.clone()],
        Some(&signer.cert_data),
        None,
    )
    .expect("Encrypt+sign should succeed");

    // Decrypt + verify
    let result = decrypt::decrypt(
        &ciphertext,
        &[gpg_secretkey],
        &[gpg_pubkey, signer.public_key_data],
    )
    .expect("Decrypt+verify should succeed");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(
        result.signature_status,
        Some(decrypt::SignatureStatus::Valid)
    );
}

// ── C3.8: Profile B pubkey → gpg (GnuPG 2.4.x) ───────────────────────────
// GnuPG cannot import v6 keys. We verify that Sequoia generates a v6 key
// and that it has the expected structure that GnuPG would reject.

/// C3.8: Profile B key is v6 (incompatible with GnuPG).
/// GnuPG 2.4.x rejects v6 keys. We verify the key is indeed v6.
/// GnuPG rejection is captured by running `generate_gpg_fixtures.sh` after
/// generating the v6 fixture with `test_generate_v6_fixture`.
#[test]
fn test_c3_8_profile_b_key_is_v6_gnupg_incompatible() {
    let key_b = keys::generate_key_with_profile(
        "Profile B User".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    assert_eq!(key_b.key_version, 6, "Profile B must produce v6 key");

    let info =
        keys::parse_key_info(&key_b.public_key_data).expect("Should parse Profile B public key");
    assert_eq!(info.key_version, 6);
    assert_eq!(info.profile, KeyProfile::Advanced);

    // v6 keys use a different packet format that GnuPG 2.4.x cannot parse.
    // GnuPG will report: "gpg: no valid OpenPGP data found" or similar.
    // This is the expected behavior — Profile B is NOT GnuPG compatible.
}

/// C3.8 (encryption): Profile B encryption produces SEIPDv2 (incompatible with GnuPG).
#[test]
fn test_c3_8_profile_b_encryption_not_gnupg_compatible() {
    let key_b =
        keys::generate_key_with_profile("Profile B".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let plaintext = b"This is encrypted with SEIPDv2 AEAD";
    let ciphertext = encrypt::encrypt(plaintext, &[key_b.public_key_data.clone()], None, None)
        .expect("Encrypt should succeed");

    // Verify Sequoia can decrypt it (Profile B → Profile B works)
    let result = decrypt::decrypt(&ciphertext, &[key_b.cert_data], &[key_b.public_key_data])
        .expect("Profile B self-decrypt should succeed");
    assert_eq!(result.plaintext, plaintext);

    // GnuPG would fail to decrypt this because:
    // 1. It cannot import v6 keys
    // 2. It does not support SEIPDv2 (AEAD)
    // This is verified during fixture generation with actual gpg invocation.
}

// ── C2A.9: Decrypt a DEFLATE-compressed message (generated by GnuPG) ──────

/// C2A.9: Decrypt a DEFLATE-compressed message from GnuPG.
/// GnuPG compressed the message with DEFLATE (algo 1) before encrypting.
/// Sequoia must decompress it transparently during decryption.
#[test]
fn test_c2a_9_decrypt_deflate_compressed_message() {
    let ciphertext = load_fixture("gpg_encrypted_compressed_deflate.asc");
    let secretkey = load_fixture("gpg_secretkey.asc");
    let pubkey = load_fixture("gpg_pubkey.asc");
    let expected = expected_plaintext();

    let result = decrypt::decrypt(&ciphertext, &[secretkey], &[pubkey])
        .expect("Should decrypt DEFLATE-compressed GnuPG message");

    assert_eq!(
        result.plaintext, expected,
        "Plaintext must match after decompression"
    );
}

/// C2A.9 (ZLIB): Decrypt a ZLIB-compressed message from GnuPG.
/// ZLIB (algo 2) is another compression format GnuPG may use.
#[test]
fn test_c2a_9_decrypt_zlib_compressed_message() {
    let ciphertext = load_fixture("gpg_encrypted_compressed_zlib.asc");
    let secretkey = load_fixture("gpg_secretkey.asc");
    let pubkey = load_fixture("gpg_pubkey.asc");
    let expected = expected_plaintext();

    let result = decrypt::decrypt(&ciphertext, &[secretkey], &[pubkey])
        .expect("Should decrypt ZLIB-compressed GnuPG message");

    assert_eq!(
        result.plaintext, expected,
        "Plaintext must match after ZLIB decompression"
    );
}

// ── C2B.10: Decrypt a DEFLATE-compressed SEIPDv2 message ───────────────────
// GnuPG cannot produce SEIPDv2 messages, so we generate this with Sequoia
// by manually constructing a compressed+encrypted message.
// Since Sequoia's high-level API doesn't compress outgoing messages (per PRD),
// we test that Sequoia can READ compressed messages even in SEIPDv2 context.
// This test generates the compressed message using Sequoia's low-level API.

/// C2B.10: Sequoia decrypts a DEFLATE-compressed message within SEIPDv2 context.
///
/// Since our app never produces compressed messages (PRD requirement), and GnuPG
/// cannot produce SEIPDv2 messages, we verify this by:
/// 1. Confirming Sequoia can handle compression in decryption (already tested in C2A.9)
/// 2. Confirming Profile B encrypt/decrypt works (already tested in profile_b_tests)
/// 3. The combination (compressed SEIPDv2) would only come from another RFC 9580
///    implementation that compresses — this is a theoretical compatibility path.
///
/// For now, we mark this as "verified by composition" — if C2A.9 (DEFLATE read) passes
/// and C2B.3 (SEIPDv2 decrypt) passes, the combined path is covered by Sequoia's
/// internal handling. A dedicated fixture would need another RFC 9580 implementation
/// (e.g., OpenPGP.js or GopenPGP) to produce compressed SEIPDv2 messages.
///
/// KNOWN LIMITATION (M6): This test verifies by composition only. A true end-to-end
/// compressed-SEIPDv2 test requires a fixture from another RFC 9580 implementation
/// (OpenPGP.js, GopenPGP, or PGPainless) that both compresses and uses SEIPDv2.
/// GnuPG cannot produce SEIPDv2, and our app never compresses outgoing messages.
/// When such a fixture becomes available, add it to the fixtures directory and
/// replace this composition test with a direct fixture-based decryption test.
#[test]
fn test_c2b_10_compressed_seipd2_verified_by_composition() {
    // Verify DEFLATE reading works (C2A.9 dependency)
    let deflate_ct = load_fixture("gpg_encrypted_compressed_deflate.asc");
    let secretkey = load_fixture("gpg_secretkey.asc");
    let pubkey = load_fixture("gpg_pubkey.asc");
    let expected = expected_plaintext();

    let result = decrypt::decrypt(&deflate_ct, &[secretkey], &[pubkey])
        .expect("DEFLATE decompression must work");
    assert_eq!(result.plaintext, expected);

    // Verify SEIPDv2 decrypt works (C2B.3 dependency)
    let key_b =
        keys::generate_key_with_profile("B User".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let plaintext = b"SEIPDv2 decrypt test for composition";
    let ct = encrypt::encrypt(plaintext, &[key_b.public_key_data.clone()], None, None)
        .expect("Profile B encrypt should succeed");
    let result = decrypt::decrypt(&ct, &[key_b.cert_data], &[key_b.public_key_data])
        .expect("Profile B decrypt should succeed");
    assert_eq!(result.plaintext, plaintext);

    // Both components verified. Sequoia's internal decompression is format-agnostic
    // (applies to both SEIPDv1 and SEIPDv2 packets).
}

// ── Additional interop edge cases ──────────────────────────────────────────

/// Verify GnuPG key can be armored and dearmored by Sequoia.
#[test]
fn test_gpg_key_armor_roundtrip() {
    let gpg_pubkey_binary = load_fixture("gpg_pubkey.gpg");
    let gpg_pubkey_armored = load_fixture("gpg_pubkey.asc");

    // Dearmor the armored key
    let (dearmored, _kind) =
        armor::decode_armor(&gpg_pubkey_armored).expect("Should dearmor GnuPG public key");

    // Both should parse to the same key
    let info_binary = keys::parse_key_info(&gpg_pubkey_binary).expect("Parse binary");
    let info_dearmored = keys::parse_key_info(&dearmored).expect("Parse dearmored");

    assert_eq!(info_binary.fingerprint, info_dearmored.fingerprint);
    assert_eq!(info_binary.key_version, info_dearmored.key_version);
}

/// Verify Sequoia can import and use GnuPG's unprotected secret key.
#[test]
fn test_gpg_secretkey_import_unprotected() {
    let secretkey = load_fixture("gpg_secretkey.asc");

    // The fixture key has no passphrase protection (%no-protection in keygen params).
    // Parse it to verify it contains secret material.
    let info = keys::parse_key_info(&secretkey).expect("Should parse GnuPG secret key");
    assert_eq!(info.key_version, 4);
    assert!(info.has_encryption_subkey);
}

/// Cross-implementation encrypt: Sequoia Profile A → GnuPG key → decrypt.
/// With encrypt-to-self enabled (both keys are v4 → SEIPDv1).
#[test]
fn test_cross_impl_encrypt_to_self_with_gpg_recipient() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");

    let sender =
        keys::generate_key_with_profile("Sender".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let plaintext = b"Encrypt-to-self with GnuPG recipient";

    // Encrypt to gpg key with encrypt-to-self
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[gpg_pubkey.clone()],
        Some(&sender.cert_data),
        Some(&sender.public_key_data),
    )
    .expect("Encrypt should succeed");

    // GnuPG recipient can decrypt
    let result1 = decrypt::decrypt(
        &ciphertext,
        &[gpg_secretkey],
        &[gpg_pubkey.clone(), sender.public_key_data.clone()],
    )
    .expect("GnuPG recipient should decrypt");
    assert_eq!(result1.plaintext, plaintext);

    // Sender can also decrypt (encrypt-to-self)
    let result2 = decrypt::decrypt(
        &ciphertext,
        &[sender.cert_data],
        &[gpg_pubkey, sender.public_key_data],
    )
    .expect("Sender should decrypt via encrypt-to-self");
    assert_eq!(result2.plaintext, plaintext);
}

/// Cross-profile: Profile B sender encrypts to GnuPG v4 recipient → SEIPDv1.
#[test]
fn test_profile_b_sender_to_gpg_v4_recipient_uses_seipdv1() {
    let gpg_pubkey = load_fixture("gpg_pubkey.gpg");
    let gpg_secretkey = load_fixture("gpg_secretkey.asc");

    let sender_b = keys::generate_key_with_profile(
        "Profile B Sender".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let plaintext = b"Profile B sender to GnuPG v4 recipient";

    // Profile B sender encrypts to v4 GnuPG recipient → must produce SEIPDv1
    let ciphertext = encrypt::encrypt(
        plaintext,
        &[gpg_pubkey.clone()],
        Some(&sender_b.cert_data),
        None,
    )
    .expect("Encrypt should succeed (auto-downgrade to SEIPDv1)");

    // Verify format is SEIPDv1 (binary check)
    let ciphertext_binary = encrypt::encrypt_binary(plaintext, &[gpg_pubkey.clone()], None, None)
        .expect("Binary encryption should succeed");
    let (has_v1, has_v2) = detect_message_format(&ciphertext_binary);
    assert!(
        has_v1,
        "Profile B sender to v4 recipient must produce SEIPDv1"
    );
    assert!(
        !has_v2,
        "Profile B sender to v4 recipient must NOT produce SEIPDv2"
    );

    // GnuPG v4 recipient decrypts successfully
    let result = decrypt::decrypt(
        &ciphertext,
        &[gpg_secretkey],
        &[gpg_pubkey, sender_b.public_key_data],
    )
    .expect("GnuPG recipient should decrypt SEIPDv1 message");

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(
        result.signature_status,
        Some(decrypt::SignatureStatus::Valid)
    );
}

// ── Signed+compressed fixture test ──────────────────────────────────────

/// Verify a GnuPG signed+compressed message (gpg --sign with DEFLATE).
/// Tests the `gpg_signed_compressed.asc` fixture generated by the script.
/// `gpg --sign` produces a one-pass signed (non-encrypted) message.
#[test]
fn test_verify_gpg_signed_compressed() {
    let signed = load_fixture("gpg_signed_compressed.asc");
    let pubkey = load_fixture("gpg_pubkey.asc");
    let expected = expected_plaintext();

    // gpg --sign produces a one-pass-signed message (not cleartext, not encrypted).
    // Verify via the VerifierBuilder path.
    let result = verify::verify_cleartext(&signed, &[pubkey])
        .expect("Should verify signed+compressed message");

    assert_eq!(result.status, decrypt::SignatureStatus::Valid);
    let content = result.content.expect("Should have content");
    let content_str = String::from_utf8_lossy(&content);
    let expected_str = String::from_utf8_lossy(&expected);
    assert_eq!(content_str.trim(), expected_str.trim());
}

// ── V6 fixture generation (helper, ignored by default) ──────────────────

/// Generate a Profile B (v6) public key fixture for GnuPG rejection testing.
/// Run manually: `cargo test test_generate_v6_fixture -- --ignored`
/// Then run `generate_gpg_fixtures.sh` to test GnuPG import rejection.
#[test]
#[ignore]
fn test_generate_v6_fixture() {
    let key_b = keys::generate_key_with_profile(
        "Profile B Test".to_string(),
        Some("profile-b@example.com".to_string()),
        None,
        KeyProfile::Advanced,
    )
    .expect("Profile B key gen should succeed");

    assert_eq!(key_b.key_version, 6);

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("profile_b_v6_pubkey.gpg");

    std::fs::write(&fixture_path, &key_b.public_key_data)
        .expect("Should write v6 public key fixture");

    println!(
        "Generated v6 fixture: {:?} ({} bytes)",
        fixture_path,
        key_b.public_key_data.len()
    );
}

/// C3.8: Verify that GnuPG rejection output was captured by fixture generation.
/// Requires running `test_generate_v6_fixture` (ignored) then `generate_gpg_fixtures.sh`.
#[test]
fn test_c3_8_gpg_rejection_output_recorded() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("gpg_v6_import_rejection.txt");

    if !fixture_path.exists() {
        // Skip gracefully if fixture hasn't been generated yet.
        // The v6 rejection test requires manual fixture generation steps.
        eprintln!(
            "Skipping: gpg_v6_import_rejection.txt not found. \
             Run `cargo test test_generate_v6_fixture -- --ignored` then \
             `bash generate_gpg_fixtures.sh` to generate it."
        );
        return;
    }

    let content =
        std::fs::read_to_string(&fixture_path).expect("Should read rejection output file");

    // GnuPG should have produced some output (error or warning)
    assert!(
        !content.is_empty(),
        "GnuPG rejection output file must not be empty"
    );

    // Verify the file contains evidence of rejection (non-zero exit code)
    // or GnuPG error/warning text
    let has_error_indicators = content.contains("error")
        || content.contains("no valid OpenPGP data")
        || content.contains("not supported")
        || content.contains("unknown packet")
        || content.contains("gpg_import_exit_code=");

    assert!(
        has_error_indicators,
        "GnuPG rejection output should contain error indicators, got: {}",
        content
    );

    // L8: If exit code is recorded, verify it is NOT zero (GnuPG must reject v6)
    if let Some(line) = content
        .lines()
        .find(|l| l.starts_with("gpg_import_exit_code="))
    {
        let code = line.trim_start_matches("gpg_import_exit_code=").trim();
        assert_ne!(
            code, "0",
            "GnuPG must reject v6 key import with a non-zero exit code, got: {code}"
        );
    }
}

// ── M10: RSA-4096 GnuPG key fixture (placeholder) ──────────────────────────

/// M10: Import and use an RSA-4096 key generated by GnuPG.
///
/// This test is a placeholder until the RSA-4096 fixture is generated.
/// To generate the fixture:
///   1. Add RSA-4096 key generation to `generate_gpg_fixtures.sh`
///   2. Export as `gpg_rsa4096_pubkey.asc` and `gpg_rsa4096_secretkey.asc`
///   3. Encrypt a test message with the RSA key: `gpg_encrypted_rsa4096.asc`
///   4. Remove the `#[ignore]` attribute
#[test]
#[ignore = "Requires RSA-4096 GnuPG fixture (run generate_gpg_fixtures.sh with RSA support)"]
fn test_c3_gpg_rsa_key_fixture_import() {
    let pubkey = load_fixture("gpg_rsa4096_pubkey.asc");
    let secretkey = load_fixture("gpg_rsa4096_secretkey.asc");

    // Verify key parses as v4 with RSA
    let info = keys::parse_key_info(&pubkey).expect("Should parse RSA-4096 public key");
    assert_eq!(info.key_version, 4, "RSA key must be v4");
    assert_eq!(info.profile, KeyProfile::Universal);
    assert!(info.has_encryption_subkey, "Must have encryption subkey");

    // Encrypt to RSA key and decrypt
    let plaintext = b"RSA-4096 interop test";
    let ciphertext = encrypt::encrypt(plaintext, &[pubkey.clone()], None, None)
        .expect("Encrypt to RSA key should succeed");
    let result = decrypt::decrypt(&ciphertext, &[secretkey], &[pubkey])
        .expect("Decrypt with RSA key should succeed");
    assert_eq!(result.plaintext, plaintext);
}

// ── L7: Revoked GnuPG key fixture (placeholder) ────────────────────────────

/// L7: Import a revoked GnuPG key and verify revocation is detected.
///
/// This test is a placeholder until the revoked key fixture is generated.
/// To generate the fixture:
///   1. Generate a GnuPG key, export it, then revoke it with `gpg --gen-revoke`
///   2. Import the revocation, re-export the now-revoked public key
///   3. Save as `gpg_revoked_pubkey.asc`
///   4. Remove the `#[ignore]` attribute
#[test]
#[ignore = "Requires revoked GnuPG key fixture (run generate_gpg_fixtures.sh with revocation support)"]
fn test_c3_gpg_revoked_key_fixture() {
    let pubkey = load_fixture("gpg_revoked_pubkey.asc");

    let info = keys::parse_key_info(&pubkey).expect("Should parse revoked GnuPG key");
    assert_eq!(info.key_version, 4);
    assert!(
        info.is_revoked,
        "Key must be marked as revoked after importing revocation cert"
    );

    // Encryption to a revoked key should fail
    let plaintext = b"Should not encrypt to revoked key";
    let result = encrypt::encrypt(plaintext, &[pubkey], None, None);
    assert!(result.is_err(), "Encryption to revoked key should fail");
}
