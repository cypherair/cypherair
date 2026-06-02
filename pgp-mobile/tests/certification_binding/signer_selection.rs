use super::helpers::*;
use super::*;

#[test]
fn test_verify_direct_key_signature_issuer_guided_rejects_signing_only_subkey() {
    let (signer_cert, signer_public_bytes) = signing_only_subkey_signer();
    let target = generated_key(KeyProfile::Universal, "IssuerGuidedDirectTarget");
    let target_cert = parse_cert(&target.public_key_data);
    let signature_with_issuer =
        direct_key_signature_from_signing_only_subkey(&signer_cert, &target_cert, false);
    let signature_without_issuer =
        direct_key_signature_from_signing_only_subkey(&signer_cert, &target_cert, true);

    let with_issuer_result = cert_signature::verify_direct_key_signature(
        &signature_with_issuer,
        &target.public_key_data,
        &[signer_public_bytes.clone()],
    )
    .expect("issuer-guided verification should return a result");
    let without_issuer_result = cert_signature::verify_direct_key_signature(
        &signature_without_issuer,
        &target.public_key_data,
        &[signer_public_bytes],
    )
    .expect("fallback verification should return a result");

    assert_eq!(
        with_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(with_issuer_result.certification_kind, None);
    assert_eq!(with_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(with_issuer_result.signing_key_fingerprint, None);

    assert_eq!(
        without_issuer_result.status,
        CertificateSignatureStatus::Invalid
    );
    assert_eq!(without_issuer_result.certification_kind, None);
    assert_eq!(without_issuer_result.signer_primary_fingerprint, None);
    assert_eq!(without_issuer_result.signing_key_fingerprint, None);
}

#[test]
fn test_generate_user_id_certification_prefers_primary_over_certification_subkey() {
    let (signer_cert, _) = CertBuilder::new()
        .add_userid("Primary Preferred <primary-preferred@example.com>")
        .add_certification_subkey()
        .generate()
        .expect("signer should generate");
    let target = generated_key(KeyProfile::Universal, "PrimaryTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let mut signer_secret_bytes = Vec::new();
    signer_cert
        .as_tsk()
        .serialize(&mut signer_secret_bytes)
        .expect("secret cert should serialize");
    let mut signer_public_bytes = Vec::new();
    signer_cert
        .serialize(&mut signer_public_bytes)
        .expect("public cert should serialize");

    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer_secret_bytes,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    )
    .expect("primary signer should generate certification");

    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &target.public_key_data,
        &selector,
        &[signer_public_bytes],
    )
    .expect("verification should succeed");

    assert_eq!(result.status, CertificateSignatureStatus::Valid);
    assert_eq!(
        result.signer_primary_fingerprint,
        Some(signer_cert.fingerprint().to_hex().to_lowercase())
    );
    assert_eq!(result.signing_key_fingerprint, None);
}
