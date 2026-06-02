use super::*;

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_decrypts_and_verifies_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let verifier_cert = material.public_cert.clone();
        let recipient = keys::generate_key_with_profile(
            format!("File Recipient {}", version.label()),
            Some(format!("file-recipient-{}@example.test", version.label())),
            None,
            recipient_profile(version),
        )
        .expect("recipient should generate");
        let plaintext = format!(
            "runtime external streaming file sign plus encrypt {}",
            version.label()
        );

        let output = encrypt_streaming_file_with_external_p256_signer(
            plaintext.as_bytes(),
            &[recipient.public_key_data.clone()],
            material,
            None,
            None,
        );
        let ciphertext =
            std::fs::read(output.path()).expect("streaming ciphertext should be readable");

        match version {
            CandidateVersion::V4 => assert_binary_message_format(&ciphertext, true, false),
            CandidateVersion::V6 => assert_binary_message_format(&ciphertext, false, true),
        }

        let result =
            decrypt::decrypt_detailed(&ciphertext, &[recipient.cert_data], &[verifier_cert])
                .expect("recipient should decrypt signed file message");
        assert_eq!(result.plaintext, plaintext.as_bytes());
        assert_eq!(result.legacy_status, SignatureStatus::Valid);
    }
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_mixed_recipients_downgrades_to_seipdv1() {
    let material = build_candidate(CandidateVersion::V6).expect("candidate should build");
    let verifier_cert = material.public_cert.clone();
    let recipient_v4 = keys::generate_key_with_profile(
        "File Recipient v4".to_string(),
        Some("file-recipient-v4@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("v4 recipient should generate");
    let recipient_v6 = keys::generate_key_with_profile(
        "File Recipient v6".to_string(),
        Some("file-recipient-v6@example.test".to_string()),
        None,
        keys::KeyProfile::Advanced,
    )
    .expect("v6 recipient should generate");
    let plaintext = b"runtime external streaming file mixed recipients";

    let output = encrypt_streaming_file_with_external_p256_signer(
        plaintext,
        &[
            recipient_v4.public_key_data.clone(),
            recipient_v6.public_key_data.clone(),
        ],
        material,
        None,
        None,
    );
    let ciphertext = std::fs::read(output.path()).expect("streaming ciphertext should be readable");

    assert_binary_message_format(&ciphertext, true, false);

    for secret in [recipient_v4.cert_data, recipient_v6.cert_data] {
        let result = decrypt::decrypt_detailed(&ciphertext, &[secret], &[verifier_cert.clone()])
            .expect("recipient should decrypt mixed-recipient file message");
        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.legacy_status, SignatureStatus::Valid);
    }
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_to_self_downgrades_and_self_decrypts() {
    let material = build_candidate(CandidateVersion::V6).expect("candidate should build");
    let verifier_cert = material.public_cert.clone();
    let recipient_v6 = keys::generate_key_with_profile(
        "File Recipient v6".to_string(),
        Some("file-recipient-v6@example.test".to_string()),
        None,
        keys::KeyProfile::Advanced,
    )
    .expect("v6 recipient should generate");
    let self_v4 = keys::generate_key_with_profile(
        "File Self v4".to_string(),
        Some("file-self-v4@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("v4 self key should generate");
    let plaintext = b"runtime external streaming file encrypt to self downgrade";

    let output = encrypt_streaming_file_with_external_p256_signer(
        plaintext,
        &[recipient_v6.public_key_data.clone()],
        material,
        Some(&self_v4.public_key_data),
        None,
    );
    let ciphertext = std::fs::read(output.path()).expect("streaming ciphertext should be readable");

    assert_binary_message_format(&ciphertext, true, false);

    for secret in [recipient_v6.cert_data, self_v4.cert_data] {
        let result = decrypt::decrypt_detailed(&ciphertext, &[secret], &[verifier_cert.clone()])
            .expect("recipient or self key should decrypt file message");
        assert_eq!(result.plaintext, plaintext);
        assert_eq!(result.legacy_status, SignatureStatus::Valid);
    }
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let recipient = keys::generate_key_with_profile(
        "File Recipient".to_string(),
        Some("file-recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let input = write_temp_data_file(b"cancel streaming file sign plus encrypt");
    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();

    let result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(CancelledRuntimeSigningProvider),
        None,
        None,
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
    assert!(!output_path.exists(), "partial output should be removed");
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_progress_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let recipient = keys::generate_key_with_profile(
        "File Recipient".to_string(),
        Some("file-recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let input = write_temp_data_file(&vec![0x42; 128 * 1024]);
    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();

    let result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
        Some(Arc::new(CancelledProgressReporter)),
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
    assert!(!output_path.exists(), "partial output should be removed");
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_sanitizes_callback_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let recipient = keys::generate_key_with_profile(
        "File Recipient".to_string(),
        Some("file-recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let input = write_temp_data_file(b"fail streaming file sign plus encrypt");
    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();

    let result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(FailingRuntimeSigningProvider {
            category: ExternalP256SigningFailureCategory::PrivateHandleMissing,
        }),
        None,
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
    assert!(!output_path.exists(), "partial output should be removed");
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_rejects_invalid_responses() {
    let signing_material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let wrong_digest_material =
        build_candidate(CandidateVersion::V4).expect("candidate should build");
    let recipient = keys::generate_key_with_profile(
        "File Recipient".to_string(),
        Some("file-recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let input = write_temp_data_file(b"invalid streaming file sign plus encrypt response");
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
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![1u8; P256_SCALAR_LENGTH],
            s: vec![0u8; P256_SCALAR_LENGTH],
        }) as Arc<dyn ExternalP256SigningProvider>,
        Arc::new(WrongDigestRuntimeSigningProvider {
            keypair: wrong_digest_material.keypair.clone(),
        }) as Arc<dyn ExternalP256SigningProvider>,
    ] {
        let output = NamedTempFile::new().expect("temp output should be created");
        let output_path = output.path().to_path_buf();
        let result = streaming::encrypt_file_with_external_p256_signer(
            input.path().to_str().unwrap(),
            output.path().to_str().unwrap(),
            &[recipient.public_key_data.clone()],
            &signing_material.public_cert,
            &signing_key_fingerprint,
            provider,
            None,
            None,
        );
        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
        assert!(!output_path.exists(), "partial output should be removed");
    }
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_rejects_wrong_public_key_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let recipient = keys::generate_key_with_profile(
        "File Recipient".to_string(),
        Some("file-recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let input = write_temp_data_file(b"wrong public key streaming file sign plus encrypt");
    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();

    let result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data],
        &material.public_cert,
        &signing_key_fingerprint(&material),
        other.runtime_provider(),
        None,
        None,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    assert!(!output_path.exists(), "partial output should be removed");
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_rejects_mismatched_fingerprint() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let recipient = keys::generate_key_with_profile(
        "File Recipient".to_string(),
        Some("file-recipient@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("recipient should generate");
    let input = write_temp_data_file(b"wrong fingerprint streaming file sign plus encrypt");
    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();

    let result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data],
        &material.public_cert,
        &signing_key_fingerprint(&other),
        material.runtime_provider(),
        None,
        None,
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    assert!(!output_path.exists(), "partial output should be removed");
}

#[test]
fn test_external_signer_runtime_streaming_file_encrypt_rejects_secret_non_p256_and_wrong_role_inputs(
) {
    let recipient = keys::generate_key_with_profile(
        "File Recipient".to_string(),
        Some("file-recipient@example.test".to_string()),
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
    let input = write_temp_data_file(b"invalid streaming file sign plus encrypt inputs");

    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();
    let secret_result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data.clone()],
        &secret.cert_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
        None,
    );
    assert!(matches!(
        secret_result,
        Err(PgpError::InvalidKeyData { .. })
    ));
    assert!(!output_path.exists(), "partial output should be removed");

    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();
    let non_p256_result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data.clone()],
        &secret.public_key_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
        None,
    );
    assert!(matches!(
        non_p256_result,
        Err(PgpError::SigningFailed { .. })
    ));
    assert!(!output_path.exists(), "partial output should be removed");

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
    let output = NamedTempFile::new().expect("temp output should be created");
    let output_path = output.path().to_path_buf();
    let wrong_role_result = streaming::encrypt_file_with_external_p256_signer(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data],
        &material.public_cert,
        &key_agreement_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        None,
        None,
    );
    assert!(matches!(
        wrong_role_result,
        Err(PgpError::SigningFailed { .. })
    ));
    assert!(!output_path.exists(), "partial output should be removed");
}
