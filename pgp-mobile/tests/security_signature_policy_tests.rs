//! Security policy tests for signature verification and signer lifecycle edge cases.

use pgp_mobile::decrypt;
use pgp_mobile::encrypt;
use pgp_mobile::keys::{self, GeneratedKey, KeyProfile};
use pgp_mobile::sign;
use pgp_mobile::signature_details::{FileVerifyDetailedResult, SignatureVerificationState};
use pgp_mobile::streaming;
use pgp_mobile::verify;
use tempfile::NamedTempFile;

fn write_temp_data_file(data: &[u8]) -> NamedTempFile {
    let input = NamedTempFile::new().expect("temp input should be created");
    std::fs::write(input.path(), data).expect("temp input should be written");
    input
}

fn sign_detached_file_for_test(data: &[u8], signer_cert: &[u8]) -> Vec<u8> {
    let input = write_temp_data_file(data);
    streaming::sign_detached_file(input.path().to_str().unwrap(), signer_cert, None)
        .expect("Detached file signing should succeed")
}

fn verify_detached_file_for_test(
    data: &[u8],
    signature: &[u8],
    verification_keys: &[Vec<u8>],
) -> FileVerifyDetailedResult {
    let input = write_temp_data_file(data);
    streaming::verify_detached_file_detailed(
        input.path().to_str().unwrap(),
        signature,
        verification_keys,
        None,
    )
    .expect("Detached file verification should return a graded result, not throw")
}

/// Tampered cleartext-signed message must produce an Invalid summary.
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
        result.summary_state,
        SignatureVerificationState::Invalid,
        "Tampered cleartext message must produce an Invalid summary state"
    );
}

/// Tampered data with detached signature must produce an Invalid summary.
#[test]
fn test_verify_tampered_detached_returns_bad() {
    let key =
        keys::generate_key_with_profile("Signer".to_string(), None, None, KeyProfile::Advanced)
            .expect("Key gen should succeed");

    let data = b"Original file content for detached signing";
    let signature = sign_detached_file_for_test(data, &key.cert_data);

    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0x01;

    let result =
        verify_detached_file_for_test(&tampered_data, &signature, &[key.public_key_data.clone()]);

    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Invalid,
        "Tampered data with detached signature must produce an Invalid summary state"
    );
}

/// Helper: generate a key with 1-second expiry, sign immediately (while valid),
/// then return the signed artifact and the key. The caller sleeps before verifying.
fn make_expired_signer(profile: KeyProfile) -> (GeneratedKey, Vec<u8>, Vec<u8>) {
    let signer =
        keys::generate_key_with_profile("Expiring Signer".to_string(), None, Some(1), profile)
            .expect("Key gen should succeed");

    let cleartext_signed = sign::sign_cleartext(b"Signed while key was valid", &signer.cert_data)
        .expect("Cleartext signing should succeed while key is valid");

    let detached_sig = sign_detached_file_for_test(b"Data for detached sig", &signer.cert_data);

    (signer, cleartext_signed, detached_sig)
}

/// Verify cleartext signed by an expired Profile A key → an Expired summary.
#[test]
fn test_verify_cleartext_expired_signer_profile_a() {
    let (signer, cleartext_signed, _) = make_expired_signer(KeyProfile::Universal);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result =
        verify::verify_cleartext_detailed(&cleartext_signed, &[signer.public_key_data.clone()])
            .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Expired,
        "Cleartext verification with expired Profile A signer key must produce an Expired summary state"
    );
}

/// Verify cleartext signed by an expired Profile B key → an Expired summary.
#[test]
fn test_verify_cleartext_expired_signer_profile_b() {
    let (signer, cleartext_signed, _) = make_expired_signer(KeyProfile::Advanced);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result =
        verify::verify_cleartext_detailed(&cleartext_signed, &[signer.public_key_data.clone()])
            .expect("Verification should return a graded result, not throw");

    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Expired,
        "Cleartext verification with expired Profile B signer key must produce an Expired summary state"
    );
}

/// Verify detached signature by an expired Profile A key → an Expired summary.
#[test]
fn test_verify_detached_expired_signer_profile_a() {
    let (signer, _, detached_sig) = make_expired_signer(KeyProfile::Universal);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify_detached_file_for_test(
        b"Data for detached sig",
        &detached_sig,
        &[signer.public_key_data.clone()],
    );

    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Expired,
        "Detached verification with expired Profile A signer key must produce an Expired summary state"
    );
}

/// Verify detached signature by an expired Profile B key → an Expired summary.
#[test]
fn test_verify_detached_expired_signer_profile_b() {
    let (signer, _, detached_sig) = make_expired_signer(KeyProfile::Advanced);

    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = verify_detached_file_for_test(
        b"Data for detached sig",
        &detached_sig,
        &[signer.public_key_data.clone()],
    );

    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Expired,
        "Detached verification with expired Profile B signer key must produce an Expired summary state"
    );
}

/// Decrypt message signed by an expired signer → an Expired summary.
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
        result.summary_state,
        SignatureVerificationState::Expired,
        "Decrypt with expired Profile A signer must produce an Expired summary state"
    );
}

/// Decrypt message signed by an expired Profile B signer → an Expired summary.
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
        result.summary_state,
        SignatureVerificationState::Expired,
        "Decrypt with expired Profile B signer must produce an Expired summary state"
    );
}

/// Tampered cleartext-signed message must produce an Invalid summary (Profile B).
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
        result.summary_state,
        SignatureVerificationState::Invalid,
        "Tampered cleartext message must produce an Invalid summary state (Profile B)"
    );
}

/// Tampered data with detached signature must produce an Invalid summary (Profile A).
/// Complements test_verify_tampered_detached_returns_bad (Profile B only).
#[test]
fn test_verify_tampered_detached_returns_bad_profile_a() {
    let key =
        keys::generate_key_with_profile("Signer".to_string(), None, None, KeyProfile::Universal)
            .expect("Key gen should succeed");

    let data = b"Original file content for detached signing";
    let signature = sign_detached_file_for_test(data, &key.cert_data);

    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0x01;

    let result =
        verify_detached_file_for_test(&tampered_data, &signature, &[key.public_key_data.clone()]);

    assert_eq!(
        result.summary_state,
        SignatureVerificationState::Invalid,
        "Tampered data with detached signature must produce an Invalid summary state (Profile A)"
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
        let key =
            keys::generate_key_with_profile("Expiring Signer".to_string(), None, Some(1), profile)
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
                    verify_result.summary_state,
                    SignatureVerificationState::Verified,
                    "Expired-key signature must not verify as Verified ({label})"
                );
            }
        }
    }
}

// ── Own-signing-key revocation (signing side of WCR-01, follow-up to #589) ──
//
// Recipient selection filters revoked encryption subkeys via `.revoked(false)`.
// The own-signing-key selection chains (`sign.rs::extract_signing_keypair`,
// `sign.rs::select_external_signing_key`, `encrypt.rs::setup_signer`) must mirror
// that: a hard-revoked signing subkey is skipped, a live one is used, and only
// when none remains does signing fail with the no-valid-signing-key error.
//
// These fixtures force *subkey*-based signing: the primary is certification-only
// (no signing capability), so `.for_signing()` can only match a subkey. Without
// that, CertBuilder's default primary is signing-capable and the negative case
// would not bite (the primary would sign even with every signing subkey revoked).

/// Build a full secret cert whose primary is certification-only, with signing
/// subkey(s). The first `revoked_subkeys` signing subkeys **in selection order**
/// are hard-revoked (KeyCompromised). Returns the serialized TSK (secret) cert
/// bytes plus the per-subkey fingerprints in that same selection order.
///
/// Ordering matters for the bite check: revoking the subkey(s) the *unfixed*
/// `.for_signing().next()` chain would reach first means the positive test also
/// fails when the fix is reverted (the wrong, revoked subkey would sign).
fn signing_subkey_fixture(
    total_signing_subkeys: usize,
    revoked_subkeys: usize,
) -> (Vec<u8>, Vec<String>) {
    use openpgp::cert::prelude::*;
    use openpgp::serialize::Serialize;
    use openpgp::types::{KeyFlags, ReasonForRevocation};
    use sequoia_openpgp as openpgp;

    let mut builder = CertBuilder::new()
        // Certification-only primary: it can bind/self-sign the subkeys but is not
        // itself selectable via `.for_signing()`, forcing subkey-based signing.
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        .add_userid("Signing Subkey Fixture <signing-subkey-fixture@example.test>");
    for _ in 0..total_signing_subkeys {
        builder = builder.add_signing_subkey();
    }
    let (mut cert, _rev) = builder.generate().expect("fixture cert should generate");

    // Signing subkey fingerprints in the order the selection chain yields them —
    // the same iteration order the production `.for_signing().next()` sees.
    let policy = openpgp::policy::StandardPolicy::new();
    let subkey_fingerprints: Vec<String> = cert
        .keys()
        .subkeys()
        .with_policy(&policy, None)
        .for_signing()
        .map(|ka| ka.key().fingerprint().to_hex().to_lowercase())
        .collect();

    if revoked_subkeys > 0 {
        let mut signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .expect("primary key should have secret parts")
            .into_keypair()
            .expect("primary keypair conversion should succeed");

        // Revoke the first `revoked_subkeys` signing subkeys in selection order.
        let mut revocations = Vec::new();
        for target in subkey_fingerprints.iter().take(revoked_subkeys) {
            let subkey = cert
                .keys()
                .subkeys()
                .find(|ka| ka.key().fingerprint().to_hex().to_lowercase() == *target)
                .expect("target signing subkey should exist");
            let revocation = SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"compromised")
                .expect("revocation reason should configure")
                .build(&mut signer, &cert, subkey.key(), None)
                .expect("subkey revocation should build");
            revocations.push(openpgp::Packet::from(revocation));
        }
        let (revoked_cert, _) = cert
            .insert_packets(revocations)
            .expect("revocation packets should insert");
        cert = revoked_cert;
    }

    let mut tsk_bytes = Vec::new();
    cert.as_tsk()
        .serialize(&mut tsk_bytes)
        .expect("fixture TSK should serialize");
    (tsk_bytes, subkey_fingerprints)
}

/// Extract the issuer fingerprints advertised by the first Signature packet in a
/// cleartext-signed message.
fn cleartext_signature_issuers(signed: &[u8]) -> Vec<sequoia_openpgp::KeyHandle> {
    use sequoia_openpgp as openpgp;

    use openpgp::parse::Parse;
    use openpgp::Packet;
    use openpgp::PacketPile;

    let pile = PacketPile::from_bytes(signed).expect("cleartext-signed message should parse");
    for packet in pile.descendants() {
        if let Packet::Signature(sig) = packet {
            return sig.get_issuers();
        }
    }
    panic!("cleartext-signed message contained no Signature packet");
}

fn issuers_alias(issuers: &[sequoia_openpgp::KeyHandle], fingerprint_hex: &str) -> bool {
    let fingerprint: sequoia_openpgp::Fingerprint =
        fingerprint_hex.parse().expect("fingerprint should parse");
    let handle = sequoia_openpgp::KeyHandle::from(fingerprint);
    issuers.iter().any(|issuer| issuer.aliases(&handle))
}

/// NEGATIVE (plain sign): a cert whose ONLY signing subkey is hard-revoked
/// (KeyCompromised) with a live certification-only primary must fail to sign via
/// the public `sign_cleartext` entry point with the no-valid-signing-key error.
#[test]
fn test_sign_cleartext_rejects_cert_with_only_revoked_signing_subkey() {
    let (tsk_bytes, _fingerprints) = signing_subkey_fixture(1, 1);

    let result = sign::sign_cleartext(b"Should not be signed", &tsk_bytes);

    match result {
        Err(pgp_mobile::error::PgpError::SigningFailed { .. }) => {}
        Err(other) => panic!("expected SigningFailed, got {other:?}"),
        Ok(_) => panic!(
            "sign_cleartext must reject a cert whose only signing subkey is revoked (KeyCompromised)"
        ),
    }
}

/// POSITIVE (plain sign): a cert with a revoked signing subkey PLUS a live signing
/// subkey must still sign, and the produced signature's issuer must be the LIVE
/// subkey — never the revoked one.
#[test]
fn test_sign_cleartext_skips_revoked_signing_subkey_and_uses_live_one() {
    // Two signing subkeys, the lexicographically-first revoked; the second is live.
    let (tsk_bytes, fingerprints) = signing_subkey_fixture(2, 1);
    let revoked_fingerprint = fingerprints[0].clone();
    let live_fingerprint = fingerprints[1].clone();

    let signed = sign::sign_cleartext(b"Should be signed by the live subkey", &tsk_bytes)
        .expect("sign_cleartext must succeed when a live signing subkey remains");

    let issuers = cleartext_signature_issuers(&signed);
    assert!(
        issuers_alias(&issuers, &live_fingerprint),
        "signature issuer must be the live signing subkey {live_fingerprint}, got {issuers:?}"
    );
    assert!(
        !issuers_alias(&issuers, &revoked_fingerprint),
        "signature issuer must NOT be the revoked signing subkey {revoked_fingerprint}, got {issuers:?}"
    );
}

/// NEGATIVE (sign-while-encrypt): a signing cert whose ONLY signing subkey is
/// hard-revoked must fail the sign-while-encrypt path (`encrypt` with a signing
/// key) with the no-valid-signing-key error, even though the recipient is valid.
#[test]
fn test_encrypt_sign_rejects_cert_with_only_revoked_signing_subkey() {
    let recipient =
        keys::generate_key_with_profile("Recipient".to_string(), None, None, KeyProfile::Universal)
            .expect("recipient key gen should succeed");
    let (signer_tsk, _fingerprints) = signing_subkey_fixture(1, 1);

    let result = encrypt::encrypt(
        b"Should not be signed",
        &[recipient.public_key_data.clone()],
        Some(&signer_tsk),
        None,
    );

    match result {
        Err(pgp_mobile::error::PgpError::SigningFailed { .. }) => {}
        Err(other) => panic!("expected SigningFailed, got {other:?}"),
        Ok(_) => panic!(
            "encrypt+sign must reject a signing cert whose only signing subkey is revoked"
        ),
    }
}

/// POSITIVE (sign-while-encrypt): a signing cert with a revoked signing subkey
/// PLUS a live one must produce a signed+encrypted message, and on decrypt the
/// signature must verify against the LIVE subkey but not against the revoked one.
#[test]
fn test_encrypt_sign_skips_revoked_signing_subkey_and_uses_live_one() {
    use openpgp::parse::Parse;
    use openpgp::serialize::Serialize;
    use sequoia_openpgp as openpgp;

    let recipient =
        keys::generate_key_with_profile("Recipient".to_string(), None, None, KeyProfile::Universal)
            .expect("recipient key gen should succeed");
    let (signer_tsk, fingerprints) = signing_subkey_fixture(2, 1);
    let revoked_fingerprint = fingerprints[0].clone();
    let live_fingerprint = fingerprints[1].clone();

    let ciphertext = encrypt::encrypt(
        b"Should be signed by the live subkey",
        &[recipient.public_key_data.clone()],
        Some(&signer_tsk),
        None,
    )
    .expect("encrypt+sign must succeed when a live signing subkey remains");

    // Build two public verification certs: one retaining only the LIVE signing
    // subkey, one retaining only the REVOKED signing subkey. The message must
    // verify against the live-only cert and fail to verify against the
    // revoked-only cert — proving the live subkey issued the signature.
    let signer_cert = openpgp::Cert::from_bytes(&signer_tsk).expect("signer cert should parse");

    let live_only = signer_cert.clone().retain_subkeys(|ka| {
        ka.key().fingerprint().to_hex().to_lowercase() == live_fingerprint
    });
    let mut live_only_pub = Vec::new();
    live_only
        .serialize(&mut live_only_pub)
        .expect("live-only verification cert should serialize");

    let revoked_only = signer_cert.retain_subkeys(|ka| {
        ka.key().fingerprint().to_hex().to_lowercase() == revoked_fingerprint
    });
    let mut revoked_only_pub = Vec::new();
    revoked_only
        .serialize(&mut revoked_only_pub)
        .expect("revoked-only verification cert should serialize");

    let live_result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[live_only_pub],
    )
    .expect("decrypt should return a graded result");
    assert_eq!(
        live_result.summary_state,
        SignatureVerificationState::Verified,
        "signature must verify against the live signing subkey"
    );

    let revoked_result = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[revoked_only_pub],
    )
    .expect("decrypt should return a graded result");
    assert_ne!(
        revoked_result.summary_state,
        SignatureVerificationState::Verified,
        "signature must NOT verify against the revoked signing subkey (it did not issue it)"
    );
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
                vr.summary_state,
                SignatureVerificationState::Verified,
                "Signature from revoked key should not be reported as Verified"
            );
        }
        Err(_) => {}
    }
}
