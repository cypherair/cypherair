use super::*;

#[test]
fn test_external_signer_runtime_encrypt_api_decrypts_and_verifies_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let recipient = keys::generate_key_with_profile(
            format!("Recipient {}", version.label()),
            Some(format!("recipient-{}@example.test", version.label())),
            None,
            recipient_profile(version),
        )
        .expect("recipient should generate");
        let signing_key_fingerprint = signing_key_fingerprint(&material);
        let plaintext = format!("runtime external sign plus encrypt {}", version.label());

        let ciphertext = encrypt::encrypt_with_external_p256_signer(
            plaintext.as_bytes(),
            &[recipient.public_key_data.clone()],
            &material.public_cert,
            &signing_key_fingerprint,
            material.runtime_provider(),
            None,
        )
        .expect("runtime external sign-plus-encrypt should succeed");

        match version {
            CandidateVersion::V4 => assert_message_format(&ciphertext, true, false),
            CandidateVersion::V6 => assert_message_format(&ciphertext, false, true),
        }

        let result =
            decrypt::decrypt_detailed(&ciphertext, &[recipient.cert_data], &[material.public_cert])
                .expect("recipient should decrypt signed message");
        assert_eq!(result.plaintext, plaintext.as_bytes());
        assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    }
}

#[test]
fn test_external_signer_runtime_encrypt_mixed_recipients_downgrades_to_seipdv1() {
    let material = build_candidate(CandidateVersion::V6).expect("candidate should build");
    let recipient_v4 = keys::generate_key_with_profile(
        "Recipient v4".to_string(),
        Some("recipient-v4@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("v4 recipient should generate");
    let recipient_v6 = keys::generate_key_with_profile(
        "Recipient v6".to_string(),
        Some("recipient-v6@example.test".to_string()),
        None,
        keys::KeyProfile::Advanced,
    )
    .expect("v6 recipient should generate");
    let plaintext = b"runtime external mixed recipients";

    let ciphertext = encrypt::encrypt_with_external_p256_signer(
        plaintext,
        &[
            recipient_v4.public_key_data.clone(),
            recipient_v6.public_key_data.clone(),
        ],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        material.runtime_provider(),
        None,
    )
    .expect("runtime external mixed-recipient encrypt should succeed");

    assert_message_format(&ciphertext, true, false);

    for secret in [recipient_v4.cert_data, recipient_v6.cert_data] {
        let result =
            decrypt::decrypt_detailed(&ciphertext, &[secret], &[material.public_cert.clone()])
                .expect("recipient should decrypt mixed-recipient message");
        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    }
}

#[test]
fn test_external_signer_runtime_encrypt_to_self_downgrades_and_self_decrypts() {
    let material = build_candidate(CandidateVersion::V6).expect("candidate should build");
    let recipient_v6 = keys::generate_key_with_profile(
        "Recipient v6".to_string(),
        Some("recipient-v6@example.test".to_string()),
        None,
        keys::KeyProfile::Advanced,
    )
    .expect("v6 recipient should generate");
    let self_v4 = keys::generate_key_with_profile(
        "Self v4".to_string(),
        Some("self-v4@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("v4 self key should generate");
    let plaintext = b"runtime external encrypt to self downgrade";

    let ciphertext = encrypt::encrypt_with_external_p256_signer(
        plaintext,
        &[recipient_v6.public_key_data.clone()],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        material.runtime_provider(),
        Some(&self_v4.public_key_data),
    )
    .expect("runtime external encrypt-to-self should succeed");

    assert_message_format(&ciphertext, true, false);

    for secret in [recipient_v6.cert_data, self_v4.cert_data] {
        let result =
            decrypt::decrypt_detailed(&ciphertext, &[secret], &[material.public_cert.clone()])
                .expect("recipient or self key should decrypt encrypt-to-self message");
        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    }
}

#[test]
fn test_external_signer_runtime_encrypt_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let recipient = keys::generate_key_with_profile(
        "Recipient".to_string(),
        Some("recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");

    let result = encrypt::encrypt_with_external_p256_signer(
        b"cancel sign plus encrypt",
        &[recipient.public_key_data],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(CancelledRuntimeSigningProvider),
        None,
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
}

#[test]
fn test_external_signer_runtime_encrypt_sanitizes_callback_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let recipient = keys::generate_key_with_profile(
        "Recipient".to_string(),
        Some("recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");

    let result = encrypt::encrypt_with_external_p256_signer(
        b"fail sign plus encrypt",
        &[recipient.public_key_data],
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
fn test_external_signer_runtime_encrypt_rejects_invalid_responses() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let recipient = keys::generate_key_with_profile(
        "Recipient".to_string(),
        Some("recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
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
        let result = encrypt::encrypt_with_external_p256_signer(
            b"invalid sign plus encrypt response",
            &[recipient.public_key_data.clone()],
            &material.public_cert,
            &signing_key_fingerprint,
            provider,
            None,
        );
        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    }
}

#[test]
fn test_external_signer_runtime_encrypt_rejects_wrong_public_key_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let recipient = keys::generate_key_with_profile(
        "Recipient".to_string(),
        Some("recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");

    let result = encrypt::encrypt_with_external_p256_signer(
        b"wrong public key sign plus encrypt",
        &[recipient.public_key_data],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        other.runtime_provider(),
        None,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_encrypt_rejects_mismatched_fingerprint() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let recipient = keys::generate_key_with_profile(
        "Recipient".to_string(),
        Some("recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let wrong_fingerprint = signing_key_fingerprint(&other);

    let result = encrypt::encrypt_with_external_p256_signer(
        b"wrong fingerprint sign plus encrypt",
        &[recipient.public_key_data],
        &material.public_cert,
        &wrong_fingerprint,
        material.runtime_provider(),
        None,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_encrypt_rejects_secret_non_p256_and_wrong_role_inputs() {
    let recipient = keys::generate_key_with_profile(
        "Recipient".to_string(),
        Some("recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let secret = keys::generate_key_with_profile(
        "Software Secret".to_string(),
        Some("software-secret@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("software key should generate");

    let secret_result = encrypt::encrypt_with_external_p256_signer(
        b"secret-bearing input",
        &[recipient.public_key_data.clone()],
        &secret.cert_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
    );
    assert!(matches!(
        secret_result,
        Err(PgpError::InvalidKeyData { .. })
    ));

    let non_p256_result = encrypt::encrypt_with_external_p256_signer(
        b"non-p256 input",
        &[recipient.public_key_data.clone()],
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
    let wrong_role_result = encrypt::encrypt_with_external_p256_signer(
        b"wrong role input",
        &[recipient.public_key_data],
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
