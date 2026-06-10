use super::*;

#[test]
fn test_external_signer_cleartext_signatures_verify_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let signed = sign::sign_cleartext_with_external_p256_signer(
            format!("external signer {}", version.label()).as_bytes(),
            &material.public_cert,
            &signing_key_fingerprint(&material),
            material.runtime_provider(),
        )
        .expect("external cleartext signing should succeed");

        let result = verify::verify_cleartext_detailed(&signed, &[material.public_cert])
            .expect("external cleartext signature should verify");
        assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    }
}

#[test]
fn test_external_signer_runtime_cleartext_api_verifies_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let signing_key_fingerprint = signing_key_fingerprint(&material);
        let signed = sign::sign_cleartext_with_external_p256_signer(
            format!("runtime external signer {}", version.label()).as_bytes(),
            &material.public_cert,
            &signing_key_fingerprint,
            material.runtime_provider(),
        )
        .expect("runtime external cleartext signing should succeed");

        let result = verify::verify_cleartext_detailed(&signed, &[material.public_cert])
            .expect("runtime external cleartext signature should verify");
        assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    }
}

#[test]
fn test_external_signer_runtime_cleartext_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let signing_key_fingerprint = signing_key_fingerprint(&material);

    let result = sign::sign_cleartext_with_external_p256_signer(
        b"cancel runtime signing",
        &material.public_cert,
        &signing_key_fingerprint,
        Arc::new(CancelledRuntimeSigningProvider),
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
}

#[test]
fn test_external_signer_runtime_cleartext_sanitizes_callback_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let signing_key_fingerprint = signing_key_fingerprint(&material);

    let result = sign::sign_cleartext_with_external_p256_signer(
        b"fail runtime signing",
        &material.public_cert,
        &signing_key_fingerprint,
        Arc::new(FailingRuntimeSigningProvider {
            category: ExternalP256SigningFailureCategory::PrivateHandleMissing,
        }),
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
fn test_external_signer_runtime_cleartext_rejects_invalid_responses() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let signing_key_fingerprint = signing_key_fingerprint(&material);

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
            keypair: material.keypair.clone(),
        }) as Arc<dyn ExternalP256SigningProvider>,
    ] {
        let result = sign::sign_cleartext_with_external_p256_signer(
            b"invalid runtime response",
            &material.public_cert,
            &signing_key_fingerprint,
            provider,
        );
        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    }
}

#[test]
fn test_external_signer_runtime_cleartext_rejects_wrong_public_key_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let signing_key_fingerprint = signing_key_fingerprint(&material);

    let result = sign::sign_cleartext_with_external_p256_signer(
        b"wrong public key",
        &material.public_cert,
        &signing_key_fingerprint,
        other.runtime_provider(),
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_cleartext_rejects_mismatched_fingerprint() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let wrong_fingerprint = signing_key_fingerprint(&other);

    let result = sign::sign_cleartext_with_external_p256_signer(
        b"wrong fingerprint",
        &material.public_cert,
        &wrong_fingerprint,
        material.runtime_provider(),
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_cleartext_rejects_secret_non_p256_and_wrong_role_inputs() {
    let secret = keys::generate_key_with_profile(
        "Software Secret".to_string(),
        Some("software-secret@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("software key should generate");
    let secret_result = sign::sign_cleartext_with_external_p256_signer(
        b"secret-bearing input",
        &secret.cert_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
    );
    assert!(matches!(
        secret_result,
        Err(PgpError::InvalidKeyData { .. })
    ));

    let non_p256_result = sign::sign_cleartext_with_external_p256_signer(
        b"non-p256 input",
        &secret.public_key_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
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
    let wrong_role_result = sign::sign_cleartext_with_external_p256_signer(
        b"wrong role input",
        &material.public_cert,
        &key_agreement_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
    );
    assert!(matches!(
        wrong_role_result,
        Err(PgpError::SigningFailed { .. })
    ));
}
