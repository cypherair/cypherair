use super::*;

#[test]
fn test_external_signer_runtime_modify_expiry_updates_public_cert_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material =
            build_candidate_with_expiry(version, Some(60)).expect("candidate should build");
        let original_subkey_expiry = first_transport_subkey_expiry(&material.public_cert);
        let after_original_subkey_expiry =
            original_subkey_expiry + std::time::Duration::from_secs(1);
        let original_fingerprint = signing_key_fingerprint(&material);
        let provider = material.runtime_provider();

        let updated = keys::modify_expiry_with_external_p256_signer(
            &material.public_cert,
            &original_fingerprint,
            provider.clone(),
            Some(60 * 60 * 24 * 30),
        )
        .expect("runtime external expiry modification should succeed");
        assert_valid_public_candidate(version, &updated.public_key_data);
        assert!(updated.key_info.expiry_timestamp.is_some());
        assert_eq!(updated.key_info.key_version, version.expected_key_version());
        assert_transport_subkey_live_at(&updated.public_key_data, after_original_subkey_expiry);

        let updated_cert =
            openpgp::Cert::from_bytes(&updated.public_key_data).expect("updated cert parses");
        assert!(!updated_cert.is_tsk());
        assert_eq!(
            updated_cert.primary_key().key().fingerprint().to_hex(),
            original_fingerprint.to_uppercase()
        );

        let removed = keys::modify_expiry_with_external_p256_signer(
            &updated.public_key_data,
            &original_fingerprint,
            provider,
            None,
        )
        .expect("runtime external expiry removal should succeed");
        assert_valid_public_candidate(version, &removed.public_key_data);
        assert_eq!(removed.key_info.expiry_timestamp, None);
        assert_transport_subkey_live_at(&removed.public_key_data, after_original_subkey_expiry);
    }
}

#[test]
fn test_external_signer_runtime_modify_expiry_keeps_sha256_binding_hashes() {
    for version in CandidateVersion::all() {
        let material =
            build_candidate_with_expiry(version, Some(60)).expect("candidate should build");
        let original_fingerprint = signing_key_fingerprint(&material);
        let provider = material.runtime_provider();

        let updated = keys::modify_expiry_with_external_p256_signer(
            &material.public_cert,
            &original_fingerprint,
            provider.clone(),
            Some(60 * 60 * 24 * 30),
        )
        .expect("runtime external expiry modification should succeed");
        assert_expiry_binding_hashes(&updated.public_key_data, HashAlgorithm::SHA256, None);

        let removed = keys::modify_expiry_with_external_p256_signer(
            &updated.public_key_data,
            &original_fingerprint,
            provider,
            None,
        )
        .expect("runtime external expiry removal should succeed");
        assert_expiry_binding_hashes(&removed.public_key_data, HashAlgorithm::SHA256, None);
    }
}

#[test]
fn test_external_signer_runtime_modify_expiry_recovers_expired_public_cert_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material =
            build_candidate_with_expiry(version, Some(1)).expect("candidate should build");
        let original_subkey_expiry = first_transport_subkey_expiry(&material.public_cert);
        sleep_past(original_subkey_expiry);
        assert_primary_expired_now(&material.public_cert);
        assert_no_transport_subkey_live_now(&material.public_cert);

        let original_fingerprint = signing_key_fingerprint(&material);
        let provider = material.runtime_provider();
        let updated = keys::modify_expiry_with_external_p256_signer(
            &material.public_cert,
            &original_fingerprint,
            provider.clone(),
            Some(60 * 60 * 24 * 30),
        )
        .expect("runtime external expiry modification should recover expired public cert");
        assert_valid_public_candidate(version, &updated.public_key_data);
        let after_update = std::time::SystemTime::now() + std::time::Duration::from_secs(1);
        assert_primary_live_at(&updated.public_key_data, after_update);
        assert_transport_subkey_live_at(&updated.public_key_data, after_update);

        let removed = keys::modify_expiry_with_external_p256_signer(
            &updated.public_key_data,
            &original_fingerprint,
            provider,
            None,
        )
        .expect("runtime external expiry removal should recover expired public cert");
        assert_valid_public_candidate(version, &removed.public_key_data);
        assert_eq!(removed.key_info.expiry_timestamp, None);
        let after_removal = std::time::SystemTime::now() + std::time::Duration::from_secs(1);
        assert_primary_live_at(&removed.public_key_data, after_removal);
        assert_transport_subkey_live_at(&removed.public_key_data, after_removal);
    }
}

#[test]
fn test_software_modify_expiry_preserves_profile_binding_hashes() {
    for (label, profile) in [
        ("Legacy", keys::KeySuite::Ed25519LegacyCurve25519Legacy),
        ("Ed448X448", keys::KeySuite::Ed448X448),
    ] {
        let generated = keys::generate_key_with_suite(
            format!("Software Hash Preservation {label}"),
            Some(format!(
                "software-hash-preservation-{}@example.test",
                label.to_lowercase()
            )),
            Some(60),
            profile,
        )
        .expect("software key should generate");
        assert_expiry_binding_hashes(&generated.public_key_data, HashAlgorithm::SHA512, None);

        let updated = keys::modify_expiry(&generated.cert_data, Some(60 * 60 * 24 * 30))
            .expect("software expiry modification should succeed");
        assert_expiry_binding_hashes(&updated.public_key_data, HashAlgorithm::SHA512, None);

        let removed = keys::modify_expiry(&updated.cert_data, None)
            .expect("software expiry removal should succeed");
        assert_expiry_binding_hashes(&removed.public_key_data, HashAlgorithm::SHA512, None);
    }
}

#[test]
fn test_software_modify_expiry_preserves_signing_subkey_backsig_hash() {
    let cert_data = software_signing_subkey_secret_cert();
    let public_cert =
        openpgp::Cert::from_bytes(&cert_data).expect("software signing-subkey cert should parse");
    let mut public_key_data = Vec::new();
    public_cert
        .serialize(&mut public_key_data)
        .expect("public cert should serialize");
    assert_expiry_binding_hashes(&public_key_data, HashAlgorithm::SHA512, Some(1));

    let updated = keys::modify_expiry(&cert_data, Some(60 * 60 * 24 * 30))
        .expect("software expiry modification should succeed");
    assert_expiry_binding_hashes(&updated.public_key_data, HashAlgorithm::SHA512, Some(1));

    let removed = keys::modify_expiry(&updated.cert_data, None)
        .expect("software expiry removal should succeed");
    assert_expiry_binding_hashes(&removed.public_key_data, HashAlgorithm::SHA512, Some(1));
}

#[test]
fn test_software_modify_expiry_refreshes_transport_subkey_binding() {
    let generated = keys::generate_key_with_suite(
        "Expiring Software".to_string(),
        Some("expiring-software@example.test".to_string()),
        Some(60),
        keys::KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("software key should generate");
    let original_subkey_expiry = first_transport_subkey_expiry(&generated.public_key_data);
    let after_original_subkey_expiry = original_subkey_expiry + std::time::Duration::from_secs(1);

    let updated = keys::modify_expiry(&generated.cert_data, Some(60 * 60 * 24 * 30))
        .expect("software expiry modification should succeed");
    assert_transport_subkey_live_at(&updated.public_key_data, after_original_subkey_expiry);

    let removed = keys::modify_expiry(&updated.cert_data, None)
        .expect("software expiry removal should succeed");
    assert_transport_subkey_live_at(&removed.public_key_data, after_original_subkey_expiry);
}

#[test]
fn test_software_modify_expiry_recovers_expired_transport_subkey_binding() {
    for (label, profile) in [
        ("Legacy", keys::KeySuite::Ed25519LegacyCurve25519Legacy),
        ("Ed448X448", keys::KeySuite::Ed448X448),
    ] {
        let generated = keys::generate_key_with_suite(
            format!("Expired Software {label}"),
            Some(format!(
                "expired-software-{}@example.test",
                label.to_lowercase()
            )),
            Some(1),
            profile,
        )
        .expect("software key should generate");
        let original_subkey_expiry = first_transport_subkey_expiry(&generated.public_key_data);
        sleep_past(original_subkey_expiry);
        assert_primary_expired_now(&generated.public_key_data);
        assert_no_transport_subkey_live_now(&generated.public_key_data);

        let updated = keys::modify_expiry(&generated.cert_data, Some(60 * 60 * 24 * 30))
            .expect("software expiry modification should recover expired cert");
        let after_update = std::time::SystemTime::now() + std::time::Duration::from_secs(1);
        assert_primary_live_at(&updated.public_key_data, after_update);
        assert_transport_subkey_live_at(&updated.public_key_data, after_update);

        let removed = keys::modify_expiry(&updated.cert_data, None)
            .expect("software expiry removal should recover expired cert");
        let after_removal = std::time::SystemTime::now() + std::time::Duration::from_secs(1);
        assert_primary_live_at(&removed.public_key_data, after_removal);
        assert_transport_subkey_live_at(&removed.public_key_data, after_removal);
    }
}

#[test]
fn test_modify_expiry_rejects_revoked_software_certificate() {
    let generated = keys::generate_key_with_suite(
        "Revoked Software".to_string(),
        Some("revoked-software@example.test".to_string()),
        Some(60),
        keys::KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("software key should generate");
    let revoked_secret = insert_key_revocation(&generated.cert_data, &generated.revocation_cert);

    let result = keys::modify_expiry(&revoked_secret, Some(60 * 60));

    assert!(matches!(result, Err(PgpError::KeyGenerationFailed { .. })));
}

#[test]
fn test_external_signer_runtime_modify_expiry_rejects_revoked_public_cert_without_callback() {
    let material = build_candidate_with_expiry(CandidateVersion::V4, Some(60))
        .expect("candidate should build");
    let expected_fingerprint = signing_key_fingerprint(&material);
    let revoked_public = insert_key_revocation(&material.public_cert, &material.revocation_cert);

    let result = keys::modify_expiry_with_external_p256_signer(
        &revoked_public,
        &expected_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        Some(60 * 60),
    );

    assert!(matches!(result, Err(PgpError::KeyGenerationFailed { .. })));
}

#[test]
fn test_external_signer_runtime_modify_expiry_cancellation_is_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");

    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(CancelledRuntimeSigningProvider),
        Some(60 * 60),
    );

    assert!(matches!(result, Err(PgpError::OperationCancelled)));
}

#[test]
fn test_external_signer_runtime_modify_expiry_sanitizes_callback_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");

    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(FailingRuntimeSigningProvider {
            category: ExternalP256SigningFailureCategory::PrivateHandleMissing,
        }),
        Some(60 * 60),
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
fn test_external_signer_runtime_modify_expiry_rejects_invalid_responses() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let expected_fingerprint = signing_key_fingerprint(&material);
    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &expected_fingerprint,
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![1u8; P256_SCALAR_LENGTH - 1],
            s: vec![1u8; P256_SCALAR_LENGTH],
        }),
        Some(60 * 60),
    );
    assert!(matches!(result, Err(PgpError::KeyGenerationFailed { .. })));

    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let expected_fingerprint = signing_key_fingerprint(&material);
    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &expected_fingerprint,
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![0u8; P256_SCALAR_LENGTH],
            s: vec![1u8; P256_SCALAR_LENGTH],
        }),
        Some(60 * 60),
    );
    assert!(matches!(result, Err(PgpError::KeyGenerationFailed { .. })));

    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let expected_fingerprint = signing_key_fingerprint(&material);
    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &expected_fingerprint,
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![1u8; P256_SCALAR_LENGTH],
            s: vec![0u8; P256_SCALAR_LENGTH],
        }),
        Some(60 * 60),
    );
    assert!(matches!(result, Err(PgpError::KeyGenerationFailed { .. })));

    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let expected_fingerprint = signing_key_fingerprint(&material);
    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &expected_fingerprint,
        Arc::new(WrongDigestRuntimeSigningProvider {
            keypair: material.keypair.clone(),
        }),
        Some(60 * 60),
    );
    assert!(matches!(result, Err(PgpError::KeyGenerationFailed { .. })));

    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other candidate should build");
    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        other.runtime_provider(),
        Some(60 * 60),
    );
    assert!(matches!(result, Err(PgpError::KeyGenerationFailed { .. })));
}

#[test]
fn test_external_signer_runtime_modify_expiry_rejects_mismatched_fingerprint() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let wrong_fingerprint = signing_key_fingerprint(&other);

    let result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &wrong_fingerprint,
        material.runtime_provider(),
        Some(60 * 60),
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_modify_expiry_rejects_secret_non_p256_and_wrong_role_inputs() {
    let secret = keys::generate_key_with_suite(
        "Software Secret".to_string(),
        Some("software-secret@example.test".to_string()),
        None,
        keys::KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("software key should generate");
    let secret_result = keys::modify_expiry_with_external_p256_signer(
        &secret.cert_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        Some(60 * 60),
    );
    assert!(matches!(
        secret_result,
        Err(PgpError::InvalidKeyData { .. })
    ));

    let non_p256_result = keys::modify_expiry_with_external_p256_signer(
        &secret.public_key_data,
        &secret.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        Some(60 * 60),
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
    let wrong_role_result = keys::modify_expiry_with_external_p256_signer(
        &material.public_cert,
        &key_agreement_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        Some(60 * 60),
    );
    assert!(matches!(
        wrong_role_result,
        Err(PgpError::SigningFailed { .. })
    ));
}

#[test]
fn test_external_signer_runtime_modify_expiry_requires_primary_signer_fingerprint() {
    let (cert, _) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::P256)
        .add_userid("P-256 With Signing Subkey <p256-subkey@example.test>")
        .add_signing_subkey()
        .generate()
        .expect("P-256 signing-subkey cert should generate");
    let mut public_cert = Vec::new();
    cert.serialize(&mut public_cert)
        .expect("public certificate should serialize");
    let policy = StandardPolicy::new();
    let signing_subkey_fingerprint = cert
        .keys()
        .subkeys()
        .with_policy(&policy, None)
        .for_signing()
        .next()
        .expect("certificate should have signing subkey")
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase();

    let result = keys::modify_expiry_with_external_p256_signer(
        &public_cert,
        &signing_subkey_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        Some(60 * 60),
    );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}
