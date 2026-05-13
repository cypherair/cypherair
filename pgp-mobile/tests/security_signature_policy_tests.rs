//! Security policy tests for signature verification and signer lifecycle edge cases.

use pgp_mobile::decrypt::{self, SignatureStatus};
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, GeneratedKey, KeyProfile};
use pgp_mobile::sign;
use pgp_mobile::verify;

/// Tampered cleartext-signed message must produce SignatureStatus::Bad.
#[test]
fn test_verify_tampered_cleartext_returns_bad() {
    let key =
        keys::generate_key_with_profile("Signer".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let text = b"Original cleartext message";
    let signed = sign::sign_cleartext(text, &key.cert_data).expect("Signing should succeed");

    let mut tampered = signed.clone();
    let signed_str = String::from_utf8_lossy(&tampered);
    if let Some(pos) = signed_str.find("Original") {
        tampered[pos] ^= 0x01;
    } else {
        panic!("Could not find message text in cleartext-signed output");
    }

    let result = verify::verify_cleartext_detailed(&tampered, &[key.public_key_data.clone()])
        .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Bad,
        "Tampered cleartext message must produce Bad signature status"
    );
}

/// Tampered data with detached signature must produce SignatureStatus::Bad.
#[test]
fn test_verify_tampered_detached_returns_bad() {
    let key =
        keys::generate_key_with_profile("Signer".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let data = b"Original file content for detached signing";
    let signature =
        sign::sign_detached(data, &key.cert_data).expect("Detached signing should succeed");

    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0x01;

    let result =
        verify::verify_detached_detailed(&tampered_data, &signature, &[key.public_key_data.clone()])
            .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Bad,
        "Tampered data with detached signature must produce Bad status"
    );
}

/// Helper: generate a key with 1-second expiry, sign immediately (while valid),
/// then return the signed artifact and the key. The caller sleeps before verifying.
fn make_expired_signer(profile: KeyProfile) -> (GeneratedKey, Vec<u8>, Vec<u8>) {
    let signer = keys::generate_key_with_profile(
        "Expiring Signer".to_string(),
        None,
        Some(1),
        profile,
    )
    .expect("Key gen should succeed");

    let cleartext_signed = sign::sign_cleartext(b"Signed while key was valid", &signer.cert_data)
        .expect("Cleartext signing should succeed while key is valid");

    let detached_sig = sign::sign_detached(b"Data for detached sig", &signer.cert_data)
        .expect("Detached signing should succeed while key is valid");

    (signer, cleartext_signed, detached_sig)
}

/// Verify cleartext signed by an expired Profile A key → SignatureStatus::Expired.
#[test]
fn test_verify_cleartext_expired_signer_profile_a() {
    let (signer, cleartext_signed, _) = make_expired_signer(KeyProfile::Universal);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_cleartext_detailed(&cleartext_signed, &[signer.public_key_data.clone()])
        .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Expired,
        "Cleartext verification with expired Profile A signer key must produce Expired status"
    );
}

/// Verify cleartext signed by an expired Profile B key → SignatureStatus::Expired.
#[test]
fn test_verify_cleartext_expired_signer_profile_b() {
    let (signer, cleartext_signed, _) = make_expired_signer(KeyProfile::Advanced);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_cleartext_detailed(&cleartext_signed, &[signer.public_key_data.clone()])
        .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Expired,
        "Cleartext verification with expired Profile B signer key must produce Expired status"
    );
}

/// Verify detached signature by an expired Profile A key → SignatureStatus::Expired.
#[test]
fn test_verify_detached_expired_signer_profile_a() {
    let (signer, _, detached_sig) = make_expired_signer(KeyProfile::Universal);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_detached_detailed(
        b"Data for detached sig",
        &detached_sig,
        &[signer.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Expired,
        "Detached verification with expired Profile A signer key must produce Expired status"
    );
}

/// Verify detached signature by an expired Profile B key → SignatureStatus::Expired.
#[test]
fn test_verify_detached_expired_signer_profile_b() {
    let (signer, _, detached_sig) = make_expired_signer(KeyProfile::Advanced);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify::verify_detached_detailed(
        b"Data for detached sig",
        &detached_sig,
        &[signer.public_key_data.clone()],
    )
    .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Expired,
        "Detached verification with expired Profile B signer key must produce Expired status"
    );
}

/// Decrypt message signed by an expired signer → SignatureStatus::Expired.
/// Uses a non-expiring recipient key and an expired signer key.
#[test]
fn test_decrypt_expired_signer_profile_a() {
    let signer = keys::generate_key_with_profile(
        "Expiring Signer A".to_string(),
        None,
        Some(1),
        KeyProfile::Universal,
    )
    .expect("Signer key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Recipient A".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Recipient key gen should succeed");

    let ciphertext = encrypt::encrypt(
        b"Signed by soon-to-expire key",
        &[recipient.public_key_data.clone()],
        Some(&signer.cert_data),
        None,
    )
    .expect("Encrypt+sign should succeed while signer key is valid");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[signer.public_key_data.clone()],
    )
    .expect("Decryption should succeed (content is still valid)");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Expired,
        "Decrypt with expired Profile A signer must produce Expired signature status"
    );
}

/// Decrypt message signed by an expired Profile B signer → SignatureStatus::Expired.
#[test]
fn test_decrypt_expired_signer_profile_b() {
    let signer = keys::generate_key_with_profile(
        "Expiring Signer B".to_string(),
        None,
        Some(1),
        KeyProfile::Advanced,
    )
    .expect("Signer key gen should succeed");

    let recipient = keys::generate_key_with_profile(
        "Recipient B".to_string(),
        None,
        None,
        KeyProfile::Advanced,
    )
    .expect("Recipient key gen should succeed");

    let ciphertext = encrypt::encrypt(
        b"Signed by soon-to-expire v6 key",
        &[recipient.public_key_data.clone()],
        Some(&signer.cert_data),
        None,
    )
    .expect("Encrypt+sign should succeed while signer key is valid");

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[signer.public_key_data.clone()],
    )
    .expect("Decryption should succeed (content is still valid)");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Expired,
        "Decrypt with expired Profile B signer must produce Expired signature status"
    );
}

/// Tampered cleartext-signed message must produce SignatureStatus::Bad (Profile B).
/// Complements test_verify_tampered_cleartext_returns_bad (Profile A only).
#[test]
fn test_verify_tampered_cleartext_returns_bad_profile_b() {
    let key =
        keys::generate_key_with_profile("Signer".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let text = b"Original cleartext message";
    let signed = sign::sign_cleartext(text, &key.cert_data).expect("Signing should succeed");

    let mut tampered = signed.clone();
    let signed_str = String::from_utf8_lossy(&tampered);
    if let Some(pos) = signed_str.find("Original") {
        tampered[pos] ^= 0x01;
    } else {
        panic!("Could not find message text in cleartext-signed output");
    }

    let result = verify::verify_cleartext_detailed(&tampered, &[key.public_key_data.clone()])
        .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Bad,
        "Tampered cleartext message must produce Bad signature status (Profile B)"
    );
}

/// Tampered data with detached signature must produce SignatureStatus::Bad (Profile A).
/// Complements test_verify_tampered_detached_returns_bad (Profile B only).
#[test]
fn test_verify_tampered_detached_returns_bad_profile_a() {
    let key =
        keys::generate_key_with_profile("Signer".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let data = b"Original file content for detached signing";
    let signature =
        sign::sign_detached(data, &key.cert_data).expect("Detached signing should succeed");

    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0x01;

    let result =
        verify::verify_detached_detailed(&tampered_data, &signature, &[key.public_key_data.clone()])
            .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.legacy_status,
        SignatureStatus::Bad,
        "Tampered data with detached signature must produce Bad status (Profile A)"
    );
}

/// Signing with an expired key: either the signing operation itself fails,
/// or (if Sequoia allows it) the resulting signature is detected as expired
/// at verification time. Both outcomes are acceptable — what matters is that
/// expired-key signatures are never accepted as Valid.
#[test]
fn test_sign_with_expired_key_not_accepted_as_valid() {
    for (profile, label) in [
        (KeyProfile::Universal, "Profile A"),
        (KeyProfile::Advanced, "Profile B"),
    ] {
        let key = keys::generate_key_with_profile(
            "Expiring Signer".to_string(),
            None,
            Some(1),
            profile,
        )
        .expect("Key gen should succeed");

        std::thread::sleep(std::time::Duration::from_secs(3));

        let result = sign::sign_cleartext(b"Should not produce a Valid signature", &key.cert_data);
        match result {
            Err(_) => {}
            Ok(signed) => {
                let verify_result =
                    verify::verify_cleartext_detailed(&signed, &[key.public_key_data.clone()])
                        .expect("Verification should return a graded result");
                assert_ne!(
                    verify_result.legacy_status,
                    SignatureStatus::Valid,
                    "Expired-key signature must not verify as Valid ({label})"
                );
            }
        }
    }
}

/// Verify that a signature made by a key that is later revoked
/// is handled appropriately during verification.
#[test]
fn test_verify_signature_from_revoked_key() {
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let key = keys::generate_key_with_profile(
        "Revoked Signer".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("Key gen should succeed");

    let text = b"Signed before revocation";
    let signed = sign::sign_cleartext(text, &key.cert_data)
        .expect("Signing should succeed before revocation");

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

    let result = verify::verify_cleartext_detailed(&signed, &[revoked_pubkey]);
    match result {
        Ok(vr) => {
            assert_ne!(
                vr.legacy_status,
                SignatureStatus::Valid,
                "Signature from revoked key should not be reported as Valid"
            );
        }
        Err(_) => {}
    }
}
