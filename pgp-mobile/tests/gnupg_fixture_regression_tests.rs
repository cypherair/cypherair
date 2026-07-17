//! GnuPG v6 rejection fixture generator.
//!
//! Produces `tests/fixtures/modern_high_v6_pubkey.gpg`, the v6 public key that
//! `tests/fixtures/generate_gpg_fixtures.sh` imports to capture GnuPG's
//! rejection of RFC 9580 v6 keys. Ignored by default; run explicitly to
//! regenerate the fixture.

use pgp_mobile::keys::{self, KeySuite};

/// Generate a Modern High (v6) public key fixture for GnuPG rejection testing.
/// Run manually: `cargo test test_generate_v6_fixture -- --ignored`
/// Then run `generate_gpg_fixtures.sh` to test GnuPG import rejection.
#[test]
#[ignore]
fn test_generate_v6_fixture() {
    let key_b = keys::generate_key_with_suite(
        "Modern High Test".to_string(),
        Some("modern-high@example.com".to_string()),
        None,
        KeySuite::Ed448X448,
    )
    .expect("Modern High key gen should succeed");

    assert_eq!(key_b.key_version, 6);

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("modern_high_v6_pubkey.gpg");

    std::fs::write(&fixture_path, &key_b.public_key_data)
        .expect("Should write v6 public key fixture");

    println!(
        "Generated v6 fixture: {:?} ({} bytes)",
        fixture_path,
        key_b.public_key_data.len()
    );
}
