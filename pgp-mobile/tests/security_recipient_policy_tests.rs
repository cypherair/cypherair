//! Security policy tests for recipient handling and recipient-facing encryption rules.

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::sign;

/// parse_recipients() returns valid hex key IDs for a Legacy message.
#[test]
fn test_parse_recipients_valid_message_legacy() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let ciphertext =
        encrypt::encrypt_binary(b"Phase 1 test", &[key.public_key_data.clone()], None, None)
            .expect("Encrypt should succeed");

    let recipients =
        decrypt::parse_recipients(&ciphertext).expect("parse_recipients should succeed");

    assert!(!recipients.is_empty(), "Must have at least one recipient");
    for rid in &recipients {
        assert!(
            rid.chars().all(|c| c.is_ascii_hexdigit()),
            "Recipient ID must be hex, got: {rid}"
        );
    }
}

/// parse_recipients() returns valid key IDs for a Modern High message.
#[test]
fn test_parse_recipients_valid_message_modern_high() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Phase 1 test B",
        &[key.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let recipients =
        decrypt::parse_recipients(&ciphertext).expect("parse_recipients should succeed");

    assert!(!recipients.is_empty(), "Must have at least one recipient");
}

/// parse_recipients() returns multiple IDs for multi-recipient messages.
#[test]
fn test_parse_recipients_multi_recipient() {
    let alice =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let bob = keys::generate_key_with_profile("Bob".to_string(), None, None, KeyProfile::Universal)
        .expect("Key gen should succeed");

    let ciphertext = encrypt::encrypt_binary(
        b"Multi-recipient test",
        &[alice.public_key_data.clone(), bob.public_key_data.clone()],
        None,
        None,
    )
    .expect("Encrypt should succeed");

    let recipients =
        decrypt::parse_recipients(&ciphertext).expect("parse_recipients should succeed");

    assert!(
        recipients.len() >= 2,
        "Multi-recipient message must have >= 2 PKESKs, got {}",
        recipients.len()
    );
}

/// parse_recipients() fails on non-OpenPGP data.
#[test]
fn test_parse_recipients_corrupt_data() {
    let garbage = b"This is not an OpenPGP message at all.";
    let result = decrypt::parse_recipients(garbage);
    assert!(
        result.is_err(),
        "parse_recipients must fail on non-OpenPGP data"
    );
}

/// parse_recipients() fails on a cleartext-signed message (no PKESK).
#[test]
fn test_parse_recipients_signed_not_encrypted() {
    let key =
        keys::generate_key_with_profile("Alice".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let signed = sign::sign_cleartext(b"Just signed, not encrypted", &key.cert_data)
        .expect("Sign should succeed");

    let result = decrypt::parse_recipients(&signed);
    assert!(
        result.is_err(),
        "parse_recipients must fail on signed-only message (no PKESK)"
    );
}

/// Encrypting to an expired key must fail (Legacy).
/// Uses 1-second expiry + sleep to create a genuinely expired key.
#[test]
fn test_encrypt_to_expired_key_rejected_legacy() {
    let key = keys::generate_key_with_profile(
        "Expiring".to_string(),
        None,
        Some(1),
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result =
        encrypt::encrypt_binary(b"Should fail", &[key.public_key_data.clone()], None, None);

    assert!(result.is_err(), "Encrypting to an expired v4 key must fail");
}

/// Encrypting to an expired key must fail (Modern High).
#[test]
fn test_encrypt_to_expired_key_rejected_modern_high() {
    let key = keys::generate_key_with_profile(
        "Expiring".to_string(),
        None,
        Some(1),
        KeyProfile::Advanced,
    )
    .expect("Key gen should succeed");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result =
        encrypt::encrypt_binary(b"Should fail", &[key.public_key_data.clone()], None, None);

    assert!(result.is_err(), "Encrypting to an expired v6 key must fail");
}

/// Encrypting to a revoked key must fail.
/// Applies the auto-generated revocation cert to the key, then attempts encryption.
#[test]
fn test_encrypt_to_revoked_key_rejected() {
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let key =
        keys::generate_key_with_profile("Revoked".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let cert =
        openpgp::Cert::from_bytes(&key.public_key_data).expect("Parse public key should succeed");
    let rev_sig = openpgp::Packet::from_bytes(&key.revocation_cert)
        .expect("Parse revocation cert should succeed");
    let (revoked_cert, _) = cert
        .insert_packets(vec![rev_sig])
        .expect("Insert revocation should succeed");

    let mut revoked_pubkey = Vec::new();
    revoked_cert
        .serialize(&mut revoked_pubkey)
        .expect("Serialize revoked cert should succeed");

    let result = encrypt::encrypt_binary(b"Should fail", &[revoked_pubkey], None, None);
    assert!(result.is_err(), "Encrypting to a revoked key must fail");
}

/// Encrypting to a revoked Modern High key must fail.
/// Complements test_encrypt_to_revoked_key_rejected (Legacy).
#[test]
fn test_encrypt_to_revoked_key_modern_high_rejected() {
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let key =
        keys::generate_key_with_profile("Revoked-v6".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let cert =
        openpgp::Cert::from_bytes(&key.public_key_data).expect("Parse public key should succeed");
    let rev_sig = openpgp::Packet::from_bytes(&key.revocation_cert)
        .expect("Parse revocation cert should succeed");
    let (revoked_cert, _) = cert
        .insert_packets(vec![rev_sig])
        .expect("Insert revocation should succeed");

    let mut revoked_pubkey = Vec::new();
    revoked_cert
        .serialize(&mut revoked_pubkey)
        .expect("Serialize revoked cert should succeed");

    let result = encrypt::encrypt_binary(b"Should fail", &[revoked_pubkey], None, None);
    assert!(
        result.is_err(),
        "Encrypting to a revoked Modern High key must fail"
    );
}

/// Encrypting with no recipients and no encrypt-to-self must fail.
#[test]
fn test_encrypt_empty_recipients_rejected() {
    let result = encrypt::encrypt_binary(b"Should fail", &[], None, None);
    assert!(
        result.is_err(),
        "Encrypting with no recipients and no encrypt-to-self must fail"
    );
}

/// Encrypting with no recipients but with encrypt-to-self should succeed.
#[test]
fn test_encrypt_empty_recipients_but_encrypt_to_self_succeeds() {
    let self_key =
        keys::generate_key_with_profile("Self".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let result = encrypt::encrypt_binary(
        b"Self-only message",
        &[],
        None,
        Some(&self_key.public_key_data),
    );
    assert!(
        result.is_ok(),
        "encrypt-to-self should allow empty recipient list"
    );
}

/// A cert whose ONLY encryption subkey carries a hard revocation (KeyCompromised)
/// must be rejected: `.alive()` checks expiry only, so recipient selection also
/// filters revoked subkeys via `.revoked(false)`. The primary key is
/// live, so this isolates subkey revocation from key-level revocation.
#[test]
fn test_encrypt_rejects_cert_with_only_revoked_encryption_subkey() {
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;
    use openpgp::types::ReasonForRevocation;
    use sequoia_openpgp as openpgp;

    let (cert, _rev) = CertBuilder::new()
        .add_userid("RevokedSubkey <revoked-subkey@example.com>")
        .add_transport_encryption_subkey()
        .generate()
        .expect("Cert gen should succeed");

    // Hard-revoke the sole encryption subkey (KeyCompromised).
    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("primary key should have secret parts")
        .into_keypair()
        .expect("keypair conversion should succeed");
    let subkey = cert
        .keys()
        .subkeys()
        .next()
        .expect("encryption subkey should exist");
    let revocation = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"compromised")
        .expect("revocation reason should configure")
        .build(&mut signer, &cert, subkey.key(), None)
        .expect("subkey revocation should build");
    let (revoked_cert, _) = cert
        .insert_packets(vec![openpgp::Packet::from(revocation)])
        .expect("revocation packet should insert");

    let mut pubkey_data = Vec::new();
    revoked_cert
        .serialize(&mut pubkey_data)
        .expect("Serialize should succeed");

    let result = encrypt::encrypt(b"Should fail", &[pubkey_data], None, None);
    assert!(
        result.is_err(),
        "encrypt must reject a cert whose only encryption subkey is revoked (KeyCompromised)"
    );
}

/// A cert with a revoked encryption subkey PLUS a second live encryption subkey
/// must still encrypt: the filter skips the revoked subkey rather than rejecting
/// the whole cert.
#[test]
fn test_encrypt_skips_revoked_subkey_but_uses_live_subkey() {
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;
    use openpgp::types::ReasonForRevocation;
    use sequoia_openpgp as openpgp;

    let (cert, _rev) = CertBuilder::new()
        .add_userid("MixedSubkeys <mixed-subkeys@example.com>")
        .add_transport_encryption_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .expect("Cert gen should succeed");

    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("primary key should have secret parts")
        .into_keypair()
        .expect("keypair conversion should succeed");
    // Revoke exactly one of the two encryption subkeys.
    let target_subkey = cert
        .keys()
        .subkeys()
        .next()
        .expect("first encryption subkey should exist");
    let revocation = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"compromised")
        .expect("revocation reason should configure")
        .build(&mut signer, &cert, target_subkey.key(), None)
        .expect("subkey revocation should build");
    let (mixed_cert, _) = cert
        .insert_packets(vec![openpgp::Packet::from(revocation)])
        .expect("revocation packet should insert");

    let mut pubkey_data = Vec::new();
    mixed_cert
        .serialize(&mut pubkey_data)
        .expect("Serialize should succeed");

    let ciphertext = encrypt::encrypt(b"Should succeed", &[pubkey_data], None, None)
        .expect("encrypt must succeed when a live encryption subkey remains");

    // Exactly one PKESK must be built — for the live subkey only, not the revoked one.
    let recipients =
        decrypt::parse_recipients(&ciphertext).expect("parse_recipients should succeed");
    assert_eq!(
        recipients.len(),
        1,
        "exactly one PKESK expected (the live subkey), not the revoked one; got {recipients:?}"
    );
}

/// The key_info capability mirror must agree with the engine: a cert whose only
/// encryption subkey is hard-revoked reports `has_encryption_subkey == false`
/// (matching test_encrypt_rejects_cert_with_only_revoked_encryption_subkey).
#[test]
fn test_key_info_reports_not_encryptable_for_revoked_only_subkey() {
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;
    use openpgp::types::ReasonForRevocation;
    use sequoia_openpgp as openpgp;

    let (cert, _rev) = CertBuilder::new()
        .add_userid("RevokedSubkeyInfo <revoked-subkey-info@example.com>")
        .add_transport_encryption_subkey()
        .generate()
        .expect("Cert gen should succeed");

    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("primary key should have secret parts")
        .into_keypair()
        .expect("keypair conversion should succeed");
    let subkey = cert
        .keys()
        .subkeys()
        .next()
        .expect("encryption subkey should exist");
    let revocation = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"compromised")
        .expect("revocation reason should configure")
        .build(&mut signer, &cert, subkey.key(), None)
        .expect("subkey revocation should build");
    let (revoked_cert, _) = cert
        .insert_packets(vec![openpgp::Packet::from(revocation)])
        .expect("revocation packet should insert");

    let mut pubkey_data = Vec::new();
    revoked_cert
        .serialize(&mut pubkey_data)
        .expect("Serialize should succeed");

    let info = keys::parse_key_info(&pubkey_data).expect("parse_key_info should succeed");
    assert!(
        !info.has_encryption_subkey,
        "key_info must report not-encryptable when the only encryption subkey is revoked"
    );
    assert!(
        !info.is_revoked,
        "primary key is live, so cert-level is_revoked must remain false"
    );
}

/// Encrypting to a signing-only cert (no encryption subkey) must fail (Modern High / v6).
/// Complements test_encrypt_binary_rejects_no_encryption_subkey (Legacy) in
/// legacy_message_tests.rs.
#[test]
fn test_encrypt_rejects_signing_only_cert_modern_high() {
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv448)
        .set_profile(openpgp::Profile::RFC9580)
        .expect("set_profile should succeed")
        .add_userid("SignOnly-v6")
        .add_signing_subkey()
        .generate()
        .expect("Cert gen should succeed");

    assert_eq!(cert.primary_key().key().version(), 6, "Must be v6 cert");

    let mut pubkey_data = Vec::new();
    cert.serialize(&mut pubkey_data)
        .expect("Serialize should succeed");

    let result = encrypt::encrypt(b"Should fail", &[pubkey_data.clone()], None, None);
    assert!(
        result.is_err(),
        "encrypt should reject v6 recipient without encryption subkey"
    );

    let result_binary = encrypt::encrypt_binary(b"Should fail", &[pubkey_data], None, None);
    assert!(
        result_binary.is_err(),
        "encrypt_binary should reject v6 recipient without encryption subkey"
    );
}
