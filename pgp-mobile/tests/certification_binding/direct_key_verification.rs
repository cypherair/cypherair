use super::helpers::*;
use super::*;

#[test]
fn test_verify_direct_key_signature_valid_legacy_and_modern_high() {
    for profile in [KeySuite::Ed25519LegacyCurve25519Legacy, KeySuite::Ed448X448] {
        let generated = generated_key(profile, "DirectValid");
        let signature = direct_key_signature_bytes(&generated.public_key_data);

        let result = cert_signature::verify_direct_key_signature(
            &signature,
            &generated.public_key_data,
            &[generated.public_key_data.clone()],
        )
        .expect("direct-key verification should succeed");

        assert_eq!(result.status, CertificateSignatureStatus::Valid);
        assert_eq!(result.certification_kind, None);
        assert_eq!(
            result.signer_primary_fingerprint,
            Some(generated.fingerprint.clone())
        );
        assert_eq!(result.signing_key_fingerprint, None);
    }
}

#[test]
fn test_verify_direct_key_signature_invalid_returns_invalid() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "DirectSigner");
    let other_target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "OtherTarget");
    let signature = direct_key_signature_bytes(&signer.public_key_data);

    let result = cert_signature::verify_direct_key_signature(
        &signature,
        &other_target.public_key_data,
        &[signer.public_key_data.clone()],
    )
    .expect("invalid direct-key verification should still return a result");

    assert_eq!(result.status, CertificateSignatureStatus::Invalid);
    assert_eq!(result.certification_kind, None);
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_direct_key_signature_signer_missing_empty_candidates() {
    let generated = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "DirectMissing");
    let signature = direct_key_signature_bytes(&generated.public_key_data);

    let result =
        cert_signature::verify_direct_key_signature(&signature, &generated.public_key_data, &[])
            .expect("signer-missing direct-key verification should return a result");

    assert_eq!(result.status, CertificateSignatureStatus::SignerMissing);
    assert_eq!(result.certification_kind, None);
    assert_eq!(result.signer_primary_fingerprint, None);
    assert_eq!(result.signing_key_fingerprint, None);
}

#[test]
fn test_verify_direct_key_signature_wrong_signature_type_returns_err() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "WrongTypeSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "WrongTypeTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);
    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("certification generation should succeed");

    let result = cert_signature::verify_direct_key_signature(
        &signature,
        &target.public_key_data,
        &[signer.public_key_data.clone()],
    );

    assert!(matches!(result, Err(PgpError::CorruptData { .. })));
}
