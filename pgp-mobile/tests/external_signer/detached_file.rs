use super::*;

#[test]
fn test_external_signer_runtime_detached_file_api_verifies_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let signing_key_fingerprint = signing_key_fingerprint(&material);
        let data = format!("runtime external detached file {}", version.label()).into_bytes();
        let input = write_temp_data_file(&data);

        let signature = streaming::sign_detached_file_with_external_p256_signer(
            input.path().to_str().unwrap(),
            &material.public_cert,
            &signing_key_fingerprint,
            material.runtime_provider(),
            None,
        )
        .expect("runtime external detached file signing should succeed");

        let result = streaming::verify_detached_file_detailed(
            input.path().to_str().unwrap(),
            &signature,
            &[material.public_cert],
            None,
        )
        .expect("runtime external detached signature should verify");
        assert_eq!(result.legacy_status, SignatureStatus::Valid);
    }
}

#[test]
fn test_external_signer_runtime_detached_file_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let input = write_temp_data_file(b"cancel detached runtime signing");

    let result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(CancelledRuntimeSigningProvider),
        None,
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
}

#[test]
fn test_external_signer_runtime_detached_file_progress_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let input = write_temp_data_file(&vec![0x42; 128 * 1024]);

    let result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(UnexpectedRuntimeSigningProvider),
        Some(Arc::new(CancelledProgressReporter)),
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
}

#[test]
fn test_external_signer_runtime_detached_file_sanitizes_callback_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let input = write_temp_data_file(b"fail detached runtime signing");

    let result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(FailingRuntimeSigningProvider {
            category: ExternalP256SigningFailureCategory::PrivateHandleMissing,
        }),
        None,
    );

    match result {
        Err(PgpError::ExternalP256SigningFailed { category }) => {
            assert_eq!(
                category,
                ExternalP256SigningFailureCategory::PrivateHandleMissing
            );
        }
        other => panic!("expected sanitized ExternalP256SigningFailed, got {other:?}"),
    }
}

#[test]
fn test_external_signer_runtime_detached_file_rejects_invalid_responses() {
    let signing_material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let wrong_digest_material =
        build_candidate(CandidateVersion::V4).expect("candidate should build");
    let input = write_temp_data_file(b"invalid detached runtime response");
    let signing_key_fingerprint = signing_key_fingerprint(&signing_material);

    for provider in [
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![1u8; P256_SCALAR_LENGTH - 1],
            s: vec![1u8; P256_SCALAR_LENGTH],
        }) as Arc<dyn ExternalP256SigningProvider>,
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![0u8; P256_SCALAR_LENGTH],
            s: vec![1u8; P256_SCALAR_LENGTH],
        }) as Arc<dyn ExternalP256SigningProvider>,
        Arc::new(WrongDigestRuntimeSigningProvider {
            keypair: wrong_digest_material.keypair.clone(),
        }) as Arc<dyn ExternalP256SigningProvider>,
    ] {
        let result = streaming::sign_detached_file_with_external_p256_signer(
            input.path().to_str().unwrap(),
            &signing_material.public_cert,
            &signing_key_fingerprint,
            provider,
            None,
        );
        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    }
}

#[test]
fn test_external_signer_runtime_detached_file_rejects_wrong_public_key_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let input = write_temp_data_file(b"wrong public key detached file");

    let result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &material.public_cert,
        &signing_key_fingerprint(&material),
        other.runtime_provider(),
        None,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_detached_file_rejects_mismatched_fingerprint() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let input = write_temp_data_file(b"wrong fingerprint detached file");
    let wrong_fingerprint = signing_key_fingerprint(&other);

    let result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &material.public_cert,
        &wrong_fingerprint,
        material.runtime_provider(),
        None,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_detached_file_rejects_secret_non_p256_and_wrong_role_inputs() {
    let input = write_temp_data_file(b"invalid detached file inputs");
    let secret = keys::generate_key_with_profile(
        "Software Secret".to_string(),
        Some("software-secret@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("software key should generate");
    let secret_result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &secret.cert_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
    );
    assert!(matches!(
        secret_result,
        Err(PgpError::InvalidKeyData { .. })
    ));

    let non_p256_result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &secret.public_key_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
    );
    assert!(matches!(
        non_p256_result,
        Err(PgpError::SigningFailed { .. })
    ));

    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let cert = openpgp::Cert::from_bytes(&material.public_cert).expect("candidate parses");
    let key_agreement_fingerprint = cert
        .keys()
        .subkeys()
        .next()
        .expect("candidate has key-agreement subkey")
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();
    let wrong_role_result = streaming::sign_detached_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        &material.public_cert,
        &key_agreement_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
    );
    assert!(matches!(
        wrong_role_result,
        Err(PgpError::SigningFailed { .. })
    ));
}
