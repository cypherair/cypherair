use super::helpers::*;
use super::*;

#[test]
fn test_verify_user_id_binding_signature_signer_missing_empty_candidates() {
    let signer = generated_key(KeyProfile::Universal, "MissingSigner");
    let target = generated_key(KeyProfile::Universal, "MissingTarget");
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
    let signer = generated_key(KeyProfile::Universal, "InvalidSigner");
    let target = generated_key_with_identity(
        KeyProfile::Universal,
        "Shared Identity",
        "shared-identity@example.com",
    );
    let wrong_target = generated_key_with_identity(
        KeyProfile::Universal,
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
    let target = generated_key(KeyProfile::Universal, "FallbackTarget");
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
    let target = generated_key(KeyProfile::Universal, "IssuerGuidedUserIdTarget");
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
    let generated = generated_key(KeyProfile::Universal, "WrongTypeDirect");
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
    let generated = generated_key(KeyProfile::Universal, "MalformedSig");
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
    let signer = generated_key(KeyProfile::Universal, "SelectorRangeSigner");
    let target = generated_key(KeyProfile::Universal, "SelectorRangeTarget");
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
    let signer = generated_key(KeyProfile::Universal, "SelectorVerifyMismatchSigner");
    let target = generated_key(KeyProfile::Universal, "SelectorVerifyMismatchTarget");
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
