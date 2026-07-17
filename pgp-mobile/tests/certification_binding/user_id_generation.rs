use super::helpers::*;
use super::*;

#[test]
fn test_generate_and_verify_user_id_certification_preserves_kind_for_all_profiles() {
    for profile in [KeySuite::Ed25519LegacyCurve25519Legacy, KeySuite::Ed448X448] {
        for kind in [
            CertificationKind::Generic,
            CertificationKind::Persona,
            CertificationKind::Casual,
            CertificationKind::Positive,
        ] {
            let signer = generated_key(profile, "KindSigner");
            let target = generated_key(profile, "KindTarget");
            let user_id_data = first_user_id_bytes(&target.public_key_data);
            let selector = user_id_selector(&user_id_data, 0);

            let signature = cert_signature::generate_user_id_certification_by_selector(
                &signer.cert_data,
                &target.public_key_data,
                &selector,
                kind,
            )
            .expect("certification generation should succeed");

            let parsed = openpgp::Packet::from_bytes(&signature).expect("signature should parse");
            let parsed = match parsed {
                openpgp::Packet::Signature(signature) => signature,
                other => panic!("expected signature packet, found {other:?}"),
            };
            assert_eq!(parsed.typ(), kind.signature_type());

            let result = cert_signature::verify_user_id_binding_signature_by_selector(
                &signature,
                &target.public_key_data,
                &selector,
                &[signer.public_key_data.clone()],
            )
            .expect("User ID verification should succeed");

            assert_eq!(result.status, CertificateSignatureStatus::Valid);
            assert_eq!(result.certification_kind, Some(kind));
            assert_eq!(
                result.signer_primary_fingerprint,
                Some(signer.fingerprint.clone())
            );
            assert_eq!(result.signing_key_fingerprint, None);
        }
    }
}

#[test]
fn test_generate_and_verify_user_id_certification_by_selector_accepts_duplicate_occurrence_selector(
) {
    let signer = generated_key(KeySuite::Ed448X448, "SelectorKindSigner");
    let target = generated_key(KeySuite::Ed448X448, "SelectorKindTarget");
    let duplicated = duplicate_userid(
        &target.cert_data,
        "SelectorKindTarget <selectorkindtarget@example.com>",
    );
    let user_id_data = first_user_id_bytes(&duplicated);

    let signature = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &duplicated,
        &user_id_selector(&user_id_data, 1),
        CertificationKind::Persona,
    )
    .expect("selector-based certification generation should succeed");

    let second_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &duplicated,
        &user_id_selector(&user_id_data, 1),
        &[signer.public_key_data.clone()],
    )
    .expect("selected occurrence verification should succeed");
    let first_result = cert_signature::verify_user_id_binding_signature_by_selector(
        &signature,
        &duplicated,
        &user_id_selector(&user_id_data, 0),
        &[signer.public_key_data.clone()],
    )
    .expect("non-selected occurrence verification should return a result");

    assert_eq!(second_result.status, CertificateSignatureStatus::Valid);
    assert_eq!(
        second_result.certification_kind,
        Some(CertificationKind::Persona)
    );
    assert_eq!(first_result.status, CertificateSignatureStatus::Valid);
}

#[test]
fn test_generate_user_id_certification_public_only_input_rejected() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "PublicOnlySigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "PublicOnlyTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer.public_key_data,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_generate_user_id_certification_by_selector_mismatch_returns_invalid_key_data() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorMismatchSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorMismatchTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let mismatched = [user_id_data.clone(), b"-mismatch".to_vec()].concat();

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &user_id_selector(&mismatched, 0),
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_generate_user_id_certification_by_selector_out_of_range_returns_invalid_key_data() {
    let signer = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorRangeGenerateSigner");
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "SelectorRangeGenerateTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer.cert_data,
        &target.public_key_data,
        &user_id_selector(&user_id_data, 99),
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn test_generate_user_id_certification_without_usable_certifier_returns_signing_failed() {
    let signer = unusable_certification_signer();
    let target = generated_key(KeySuite::Ed25519LegacyCurve25519Legacy, "UnusableTarget");
    let user_id_data = first_user_id_bytes(&target.public_key_data);
    let selector = user_id_selector(&user_id_data, 0);

    let result = cert_signature::generate_user_id_certification_by_selector(
        &signer,
        &target.public_key_data,
        &selector,
        CertificationKind::Positive,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}
