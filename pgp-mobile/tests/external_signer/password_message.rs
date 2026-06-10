use super::*;

#[test]
fn test_external_signer_runtime_password_encrypt_decrypts_and_verifies_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        for format in [
            password::PasswordMessageFormat::Seipdv1,
            password::PasswordMessageFormat::Seipdv2,
        ] {
            for binary in [false, true] {
                let material = build_candidate(version).expect("candidate should build");
                let signing_key_fingerprint = signing_key_fingerprint(&material);
                let passphrase = Password::from(format!(
                    "runtime password {} {format:?} binary={binary}",
                    version.label()
                ));
                let plaintext = format!(
                    "runtime external password signing {} {format:?} binary={binary}",
                    version.label()
                );

                let ciphertext = if binary {
                    password::encrypt_binary_with_external_p256_signer(
                        plaintext.as_bytes(),
                        &passphrase,
                        format,
                        &material.public_cert,
                        &signing_key_fingerprint,
                        material.runtime_provider(),
                    )
                } else {
                    password::encrypt_with_external_p256_signer(
                        plaintext.as_bytes(),
                        &passphrase,
                        format,
                        &material.public_cert,
                        &signing_key_fingerprint,
                        material.runtime_provider(),
                    )
                }
                .expect("runtime external password signing should succeed");

                assert_password_message_format(&ciphertext, format, binary);

                let result =
                    password::decrypt(&ciphertext, &passphrase, &[material.public_cert.clone()])
                        .expect("password message should decrypt and verify");
                assert_eq!(result.status, password::PasswordDecryptStatus::Decrypted);
                assert_eq!(result.plaintext.as_deref(), Some(plaintext.as_bytes()));
                assert_eq!(result.summary_state, SignatureVerificationState::Verified);
            }
        }
    }
}

#[test]
fn test_external_signer_runtime_password_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let passphrase = Password::from("cancel runtime password signing");

    let result = password::encrypt_with_external_p256_signer(
        b"cancel password signing",
        &passphrase,
        password::PasswordMessageFormat::Seipdv1,
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(CancelledRuntimeSigningProvider),
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
}

#[test]
fn test_external_signer_runtime_password_sanitizes_callback_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let passphrase = Password::from("fail runtime password signing");

    let result = password::encrypt_binary_with_external_p256_signer(
        b"fail password signing",
        &passphrase,
        password::PasswordMessageFormat::Seipdv2,
        &material.public_cert,
        &signing_key_fingerprint(&material),
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
fn test_external_signer_runtime_password_rejects_invalid_responses() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let passphrase = Password::from("invalid runtime password signing");
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
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![1u8; P256_SCALAR_LENGTH],
            s: vec![0u8; P256_SCALAR_LENGTH],
        }) as Arc<dyn ExternalP256SigningProvider>,
        Arc::new(WrongDigestRuntimeSigningProvider {
            keypair: material.keypair.clone(),
        }) as Arc<dyn ExternalP256SigningProvider>,
    ] {
        let result = password::encrypt_binary_with_external_p256_signer(
            b"invalid password signing response",
            &passphrase,
            password::PasswordMessageFormat::Seipdv1,
            &material.public_cert,
            &signing_key_fingerprint,
            provider,
        );
        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    }
}

#[test]
fn test_external_signer_runtime_password_rejects_wrong_public_key_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let passphrase = Password::from("wrong public key password signing");

    let result = password::encrypt_with_external_p256_signer(
        b"wrong public key password signing",
        &passphrase,
        password::PasswordMessageFormat::Seipdv1,
        &material.public_cert,
        &signing_key_fingerprint(&material),
        other.runtime_provider(),
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_password_rejects_mismatched_fingerprint() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let passphrase = Password::from("wrong fingerprint password signing");

    let result = password::encrypt_with_external_p256_signer(
        b"wrong fingerprint password signing",
        &passphrase,
        password::PasswordMessageFormat::Seipdv1,
        &material.public_cert,
        &signing_key_fingerprint(&other),
        material.runtime_provider(),
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_password_rejects_secret_non_p256_and_wrong_role_inputs() {
    let passphrase = Password::from("invalid input password signing");
    let secret = keys::generate_key_with_profile(
        "Software Secret".to_string(),
        Some("software-secret@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("software key should generate");
    let secret_result = password::encrypt_with_external_p256_signer(
        b"secret-bearing input",
        &passphrase,
        password::PasswordMessageFormat::Seipdv1,
        &secret.cert_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
    );
    assert!(matches!(
        secret_result,
        Err(PgpError::InvalidKeyData { .. })
    ));

    let non_p256_result = password::encrypt_with_external_p256_signer(
        b"non-p256 input",
        &passphrase,
        password::PasswordMessageFormat::Seipdv1,
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
    let wrong_role_result = password::encrypt_with_external_p256_signer(
        b"wrong role input",
        &passphrase,
        password::PasswordMessageFormat::Seipdv1,
        &material.public_cert,
        &key_agreement_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
    );
    assert!(matches!(
        wrong_role_result,
        Err(PgpError::SigningFailed { .. })
    ));
}
