//! QR / URL Scheme validation tests.
//! Covers POC test cases C9.1–C9.3.

use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::PgpEngine;

/// C9.1: v4 public key → base64url encode → cypherair:// URL → decode → byte-identical.
#[test]
fn test_qr_url_roundtrip_v4() {
    let engine = PgpEngine::new();

    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        Some("alice@example.com".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let url = engine
        .encode_qr_url(key.public_key_data.clone())
        .expect("URL encoding should succeed");

    assert!(url.starts_with("cypherair://import/v1/"));

    let decoded = engine
        .decode_qr_url(url)
        .expect("URL decoding should succeed");

    // Parse both and compare fingerprints
    let original_info = keys::parse_key_info(&key.public_key_data).unwrap();
    let decoded_info = keys::parse_key_info(&decoded).unwrap();
    assert_eq!(original_info.fingerprint, decoded_info.fingerprint);
    assert_eq!(decoded_info.key_version, 4);
}

/// C9.2: v6 public key → same round-trip.
#[test]
fn test_qr_url_roundtrip_v6() {
    let engine = PgpEngine::new();

    let key = keys::generate_key_with_profile(
        "Bob".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    let url = engine
        .encode_qr_url(key.public_key_data.clone())
        .expect("URL encoding should succeed");

    assert!(url.starts_with("cypherair://import/v1/"));

    let decoded = engine
        .decode_qr_url(url)
        .expect("URL decoding should succeed");

    let original_info = keys::parse_key_info(&key.public_key_data).unwrap();
    let decoded_info = keys::parse_key_info(&decoded).unwrap();
    assert_eq!(original_info.fingerprint, decoded_info.fingerprint);
    assert_eq!(decoded_info.key_version, 6);
}

/// C9.3: Malformed base64url data → parse returns clear error.
#[test]
fn test_qr_url_malformed_data() {
    let engine = PgpEngine::new();

    // Invalid base64url
    let result = engine.decode_qr_url("cypherair://import/v1/!!!invalid!!!".to_string());
    assert!(result.is_err(), "Malformed base64url should fail");

    // Valid base64url but not a valid key
    let result = engine.decode_qr_url("cypherair://import/v1/aGVsbG8".to_string());
    assert!(result.is_err(), "Valid base64url but not a key should fail");

    // Wrong URL scheme
    let result = engine.decode_qr_url("https://example.com/key".to_string());
    assert!(result.is_err(), "Wrong URL scheme should fail");

    // Missing version prefix
    let result = engine.decode_qr_url("cypherair://import/aGVsbG8".to_string());
    assert!(result.is_err(), "Missing version prefix should fail");
}

/// Secret key material in QR URL should be rejected.
/// Only public keys should be exchanged via QR codes.
#[test]
fn test_qr_url_rejects_secret_key() {
    let engine = PgpEngine::new();

    let key = keys::generate_key_with_profile(
        "Alice".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    // Encode the FULL cert (with secret keys) as a QR URL — this should be rejected on decode
    let url = engine
        .encode_qr_url(key.cert_data.clone())
        .expect("URL encoding should succeed (it's just base64url)");

    // decode_qr_url should reject secret key material
    let result = engine.decode_qr_url(url);
    assert!(result.is_err(), "QR URL containing secret key should be rejected");
    let err = result.unwrap_err();
    match err {
        pgp_mobile::error::PgpError::InvalidKeyData { reason } => {
            assert!(reason.contains("secret key"), "Error should mention secret key: {reason}");
        }
        other => panic!("Expected InvalidKeyData, got: {other:?}"),
    }
}

/// QR URL length check — should be reasonable for QR encoding.
#[test]
fn test_qr_url_length_reasonable() {
    let engine = PgpEngine::new();

    // Profile A key
    let key_a = keys::generate_key_with_profile(
        "A".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");
    let url_a = engine.encode_qr_url(key_a.public_key_data.clone()).unwrap();
    // Full certificate (primary key + User ID + self-sig + encryption subkey + binding sig)
    // is larger than bare key bytes. v4 certs with Ed25519+X25519 are typically ~1200-1800
    // chars in base64url. QR codes at Level M can encode up to 2331 alphanumeric chars.
    assert!(
        url_a.len() < 2500,
        "Profile A QR URL too long for QR encoding: {} chars",
        url_a.len()
    );

    // Profile B key
    let key_b = keys::generate_key_with_profile(
        "B".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");
    let url_b = engine.encode_qr_url(key_b.public_key_data.clone()).unwrap();
    // Profile B keys (Ed448+X448, v6 format) have larger signatures and key material.
    assert!(
        url_b.len() < 3000,
        "Profile B QR URL too long: {} chars",
        url_b.len()
    );
}
