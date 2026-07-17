use super::helpers::*;
use super::*;

#[test]
fn test_verify_user_id_binding_signature_signer_missing_empty_candidates() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "MissingSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "MissingTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[],
    )
    .expect("signer-missing User ID verification should return a result");

    assert_eq!(result.status, CertificateSignatureStatus::SignerMissing);
    assert_eq!(result.certification_kind, Some(CertificationKind::Positive));
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_user_id_binding_signature_invalid_matching_user_id_returns_invalid() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "InvalidSigner");
    let target = generated_key_with_identity(
        KeySuite::Ed25519LegacyCurve25519Legacy,
        "Shared Identity",
        "shared-identity@example.com",
    );
    let wrong_target = generated_key_with_identity(
        KeySuite::Ed25519LegacyCurve25519Legacy,
        "Shared Identity",
        "shared-identity@example.com",
    );
    let user_id_data = first_user_id_bytes(&target.public_key_data);

    assert_eq!(
        user_id_data,
        first_user_id_bytes(&wrong_target.public_key_data)
    );

    let target_selector = user_id_selector(&user_id_data, 0);
    let wrong_target_selector =
        user_id_selector(&first_user_id_bytes(&wrong_target.public_key_data), 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &target_selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &wrong_target.public_key_data,
        &wrong_target_selector,
        &[signer.public_key_data.clone()],
    )
    .expect("invalid User ID verification should still return a result");

    assert_eq!(result.status, CertificateSignatureStatus::Invalid);
    assert_eq!(result.certification_kind, Some(CertificationKind::Positive));
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_user_id_binding_signature_missing_issuer_fallback_succeeds_with_subkey_signer() {
    let (signer_cert, signer_secret_bytes, subkey_fingerprint) = certification_subkey_signer();
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "FallbackTarget");
    let target_cert = parse_cert(&target.public_key_data);
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = positive_certification_without_issuer(&signer_cert, &target_cert);

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[signer_secret_bytes],
    )
    .expect("fallback verification should succeed");

    assert_eq!(result.status, CertificateSignatureStatus::Valid);
    assert_eq!(result.certification_kind, Some(CertificationKind::Positive));
    assert_eq!(
        result.signer_primary_fingerprint,
        Some(signer_cert.fingerprint().to_hex().to_lowercase())
    );
    assert_eq!(result.signing_key_fingerprint, Some(subkey_fingerprint));
}

#[test]
fn test_verify_user_id_binding_signature_issuer_guided_rejects_signing_only_subkey() {
    let (signer_cert, signer_public_bytes) = signing_only_subkey_signer();
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "IssuerGuidedUserIdTarget");
    let target_cert = parse_cert(&target.public_key_data);
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature_with_issuer =
        positive_certification_from_signing_only_subkey(&signer_cert, &target_cert, false);
    let signature_without_issuer =
        positive_certification_from_signing_only_subkey(&signer_cert, &target_cert, true);

    let with_issuer_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature_with_issuer,
        &target.public_key_data,
        &selector,
        &[signer_public_bytes.clone()],
    )
    .expect("issuer-guided verification should return a result");
    let without_issuer_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature_without_issuer,
        &target.public_key_data,
        &selector,
        &[signer_public_bytes],
    )
    .expect("fallback verification should return a result");

    assert_eq!(
        with_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(
        with_issuer_result.certification_kind,
        Some(CertificationKind::Positive)
    );
    assert_eq!(with_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(with_issuer_result.signing_key_fingerprint, None);

    assert_eq!(
        without_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(
        without_issuer_result.certification_kind,
        Some(CertificationKind::Positive)
    );
    assert_eq!(without_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(without_issuer_result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_user_id_binding_signature_wrong_signature_type_returns_err() {
    let generated = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "WrongTypeDirect");
    let signature = direct_key_signature_bytes(&generated.public_key_data);
    let user_id_data = first_user_id_bytes(&generated.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &generated.public_key_data,
        &selector,
        &[generated.public_key_data.clone()],
    );

    assert!(matches!(result, Err(PgpError::CorruptData { .. })));
}

#[test]
fn test_verify_user_id_binding_signature_malformed_signature_returns_err() {
    let generated = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "MalformedSig");
    let user_id_data = first_user_id_bytes(&generated.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        b"not a signature packet",
        &generated.public_key_data,
        &selector,
        &[generated.public_key_data.clone()],
    );

    assert!(matches!(result, Err(PgpError::CorruptData { .. })));
}

#[test]
fn test_verify_user_id_binding_signature_by_selector_out_of_range_returns_invalid_key_data() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorRangeSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorRangeTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &user_id_selector(&user_id_data, 99),
        &[signer.public_key_data],
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_verify_user_id_binding_signature_by_selector_mismatch_returns_invalid_key_data() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorVerifyMismatchSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorVerifyMismatchTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let mismatched = [user_id_data.clone(), b"-mismatch".to_vec()].concat();
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &user_id_selector(&mismatched, 0),
        &[signer.public_key_data],
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

// A cryptographically genuine certification from a signer whose certificate is
// later revoked (key compromise) must stop reading as a valid vouch: otherwise a
// compromised contact key could vouch for an attacker-controlled key.
#[test]
fn test_verify_user_id_binding_signature_rejects_revoked_signer() {
    use openpgp::types::ReasonForRevocation;

    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "RevokedVouchSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "RevokedVouchTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    // Baseline: with the live signer the same certification is Valid.
    let live = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[signer.public_key_data.clone()],
    )
    .expect("verification should return a result");
    assert_eq!(live.status, CertificateSignatureStatus::Valid);

    // Hard-revoke the signer certificate and re-verify the identical certification.
    let signer_cert = parse_cert(&signer.cert_data);
    let mut revoker = signer_cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("signer primary key should have secret material")
        .into_keypair()
        .expect("keypair conversion should succeed");
    let revocation = CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"compromised")
        .expect("revocation reason should configure")
        .build(&mut revoker, &signer_cert, None)
        .expect("cert revocation should build");
    let (revoked_signer, _) = signer_cert
        .insert_packets(vec![openpgp::Packet::from(revocation)])
        .expect("revocation packet should insert");
    let mut revoked_signer_public = Vec::new();
    revoked_signer
        .serialize(&mut revoked_signer_public)
        .expect("revoked signer public cert should serialize");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[revoked_signer_public],
    )
    .expect("verification should return a result");

    assert_eq!(
        result.status,
        CertificateSignatureStatus::Invalid,
        "a revoked signer's certification must not verify as Valid"
    );
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

// A cryptographically valid certification that uses the collision-weak SHA-1 hash
// must be rejected for a third-party vouch, even from an otherwise-valid signer.
#[test]
fn test_verify_user_id_binding_signature_rejects_sha1_certification() {
    use openpgp::packet::signature::SignatureBuilder;
    use openpgp::types::HashAlgorithm;

    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "Sha1VouchSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "Sha1VouchTarget");
    let signer_cert = parse_cert(&signer.cert_data);
    let target_cert = parse_cert(&target.public_key_data);
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let mut signer_keypair = signer_cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("signer primary key should have secret material")
        .into_keypair()
        .expect("keypair conversion should succeed");
    let user_id = target_cert
        .userids()
        .next()
        .expect("target cert should have a User ID")
        .userid();
    let sha1_certification = user_id
        .bind(
            &mut signer_keypair,
            &target_cert,
            SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_hash_algo(HashAlgorithm::SHA1),
        )
        .expect("SHA-1 certification should sign");
    let signature = serialize_signature(&sha1_certification);

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[signer.public_key_data],
    )
    .expect("verification should return a result");

    assert_eq!(
        result.status,
        CertificateSignatureStatus::Invalid,
        "a SHA-1 certification must not verify as Valid"
    );
}
