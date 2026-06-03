use super::*;

fn first_user_id_selector(public_cert: &[u8]) -> keys::UserIdSelectorInput {
    let selectors =
        keys::discover_certificate_selectors(public_cert).expect("selectors should discover");
    let user_id = selectors
        .user_ids
        .first()
        .expect("certificate should have a User ID");
    keys::UserIdSelectorInput {
        user_id_data: user_id.user_id_data.clone(),
        occurrence_index: user_id.occurrence_index,
    }
}

fn first_subkey_fingerprint(public_cert: &[u8]) -> String {
    openpgp::Cert::from_bytes(public_cert)
        .expect("public cert should parse")
        .keys()
        .subkeys()
        .next()
        .expect("certificate should have a subkey")
        .key()
        .fingerprint()
        .to_hex()
        .to_lowercase()
}

fn generated_target(version: CandidateVersion) -> keys::GeneratedKey {
    keys::generate_key_with_profile(
        format!("External Certification Target {}", version.label()),
        Some(format!(
            "external-certification-target-{}@example.test",
            version.label()
        )),
        None,
        recipient_profile(version),
    )
    .expect("target key should generate")
}

fn assert_signature_hash(signature: &[u8], expected: HashAlgorithm) {
    let packet = Packet::from_bytes(signature).expect("signature packet should parse");
    match packet {
        Packet::Signature(sig) => assert_eq!(sig.hash_algo(), expected),
        other => panic!("expected signature packet, got {other:?}"),
    }
}

fn assert_callback_not_triggered(result: Result<Vec<u8>, PgpError>) {
    assert!(
        result.is_err(),
        "operation should fail before invoking the runtime signing callback"
    );
}

fn assert_certification_verifies(
    signature: &[u8],
    signer_public_cert: &[u8],
    signer_fingerprint: &str,
    target_public_cert: &[u8],
    selector: &keys::UserIdSelectorInput,
    kind: cert_signature::CertificationKind,
) {
    let result = cert_signature::verify_user_id_binding_signature_by_selector(
        signature,
        target_public_cert,
        selector,
        &[signer_public_cert.to_vec()],
    )
    .expect("certification verification should succeed");
    assert_eq!(
        result.status,
        cert_signature::CertificateSignatureStatus::Valid
    );
    assert_eq!(result.certification_kind, Some(kind));
    assert_eq!(
        result.signer_primary_fingerprint,
        Some(signer_fingerprint.to_ascii_lowercase())
    );
    assert_eq!(result.signing_key_fingerprint, None);
}

fn duplicate_public_user_id(material: &CandidateMaterial) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(&material.public_cert).expect("public cert should parse");
    let policy = StandardPolicy::new();
    let template: openpgp::packet::signature::SignatureBuilder = cert
        .with_policy(&policy, None)
        .expect("cert should validate")
        .primary_userid()
        .expect("primary User ID should exist")
        .binding_signature()
        .clone()
        .into();
    let user_id: openpgp::packet::UserID =
        "Duplicated Certification User <duplicate-cert@example.test>".into();
    let mut keypair = material
        .keypair
        .lock()
        .expect("test keypair lock should succeed");
    let binding = user_id
        .bind(
            &mut *keypair,
            &cert,
            template
                .set_primary_userid(false)
                .expect("binding template should update")
                .set_signature_creation_time(std::time::SystemTime::now())
                .expect("binding creation time should update"),
        )
        .expect("duplicate User ID binding should build");
    let (duplicated, _) = cert
        .insert_packets(vec![Packet::from(user_id), binding.into()])
        .expect("duplicate User ID should insert");
    let mut public = Vec::new();
    duplicated
        .serialize(&mut public)
        .expect("duplicated public cert should serialize");
    public
}

fn unresolved_revoked_public_cert(material: &CandidateMaterial) -> Vec<u8> {
    let cert = openpgp::Cert::from_bytes(&material.public_cert).expect("public cert should parse");
    let other = build_candidate(CandidateVersion::V4).expect("other candidate should build");
    let mut other_keypair = other
        .keypair
        .lock()
        .expect("test keypair lock should succeed");
    let revocation = openpgp::cert::CertRevocationBuilder::new()
        .set_reason_for_revocation(openpgp::types::ReasonForRevocation::KeyRetired, b"")
        .expect("revocation reason should configure")
        .build(&mut *other_keypair, &cert, Some(HashAlgorithm::SHA256))
        .expect("unresolved revocation should build");
    let (revoked, _) = cert
        .insert_packets(vec![Packet::from(revocation)])
        .expect("unresolved revocation should insert");
    let mut public = Vec::new();
    revoked
        .serialize(&mut public)
        .expect("unresolved-revoked public cert should serialize");
    public
}

fn signing_only_primary_public_cert() -> (Vec<u8>, String) {
    let (cert, _) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::P256)
        .set_primary_key_flags(openpgp::types::KeyFlags::empty().set_signing())
        .add_userid("Signing Only Certification <signing-only-cert@example.test>")
        .add_transport_encryption_subkey()
        .generate()
        .expect("signing-only primary P-256 cert should generate");
    let fingerprint = cert.primary_key().key().fingerprint().to_hex();
    let mut public_cert = Vec::new();
    cert.serialize(&mut public_cert)
        .expect("public cert should serialize");
    (public_cert, fingerprint)
}

#[test]
fn test_external_signer_runtime_user_id_certifications_verify_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        for kind in [
            cert_signature::CertificationKind::Generic,
            cert_signature::CertificationKind::Persona,
            cert_signature::CertificationKind::Casual,
            cert_signature::CertificationKind::Positive,
        ] {
            let material = build_candidate(version).expect("candidate should build");
            let target = generated_target(version);
            let selector = first_user_id_selector(&target.public_key_data);
            let signature =
                cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
                    &material.public_cert,
                    &signing_key_fingerprint(&material),
                    material.runtime_provider(),
                    &target.public_key_data,
                    &selector,
                    kind,
                )
                .expect("external User ID certification should generate");

            assert_valid_public_candidate(version, &material.public_cert);
            assert_signature_hash(&signature, HashAlgorithm::SHA256);
            assert_certification_verifies(
                &signature,
                &material.public_cert,
                &signing_key_fingerprint(&material),
                &target.public_key_data,
                &selector,
                kind,
            );
        }
    }
}

#[test]
fn test_software_user_id_certification_keeps_default_hash() {
    for profile in [keys::KeyProfile::Universal, keys::KeyProfile::Advanced] {
        let signer = keys::generate_key_with_profile(
            "Software Certification Hash".to_string(),
            Some("software-certification-hash@example.test".to_string()),
            None,
            profile,
        )
        .expect("software signer should generate");
        let target = keys::generate_key_with_profile(
            "Software Certification Target".to_string(),
            Some("software-certification-target@example.test".to_string()),
            None,
            profile,
        )
        .expect("software target should generate");
        let selector = first_user_id_selector(&target.public_key_data);

        let signature = cert_signature::generate_user_id_certification_by_selector(
            &signer.cert_data,
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        )
        .expect("software certification should generate");

        assert_signature_hash(&signature, HashAlgorithm::SHA512);
    }
}

#[test]
fn test_external_signer_runtime_user_id_certification_accepts_duplicate_occurrence_selector() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let duplicated_public = duplicate_public_user_id(&material);
    let selectors = keys::discover_certificate_selectors(&duplicated_public)
        .expect("selectors should discover");
    let selector = selectors
        .user_ids
        .iter()
        .find(|user_id| user_id.occurrence_index == 1)
        .expect("duplicate occurrence should exist");
    let selector = keys::UserIdSelectorInput {
        user_id_data: selector.user_id_data.clone(),
        occurrence_index: selector.occurrence_index,
    };

    let signature =
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            material.runtime_provider(),
            &duplicated_public,
            &selector,
            cert_signature::CertificationKind::Persona,
        )
        .expect("duplicate occurrence selector should generate certification");

    assert_certification_verifies(
        &signature,
        &material.public_cert,
        &signing_key_fingerprint(&material),
        &duplicated_public,
        &selector,
        cert_signature::CertificationKind::Persona,
    );
}

#[test]
fn test_external_signer_runtime_user_id_certification_primary_only_before_callback() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);

    assert_callback_not_triggered(
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &material.public_cert,
            &subkey_fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        ),
    );
}

#[test]
fn test_external_signer_runtime_user_id_certification_requires_certification_capable_primary_before_callback(
) {
    let (public_cert, primary_fingerprint) = signing_only_primary_public_cert();
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);

    assert_callback_not_triggered(
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &public_cert,
            &primary_fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        ),
    );
}

#[test]
fn test_external_signer_runtime_user_id_certification_rejects_secret_non_p256_and_wrong_role_inputs(
) {
    let secret = keys::generate_key_with_profile(
        "Secret Certification".to_string(),
        Some("secret-certification@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("software key should generate");
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);

    assert_callback_not_triggered(
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &secret.cert_data,
            &secret.fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        ),
    );

    assert_callback_not_triggered(
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &secret.public_key_data,
            &secret.fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        ),
    );

    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let wrong_role_fingerprint = first_subkey_fingerprint(&material.public_cert);
    assert_callback_not_triggered(
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &material.public_cert,
            &wrong_role_fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        ),
    );
}

#[test]
fn test_external_signer_runtime_user_id_certification_rejects_revoked_or_unresolved_before_callback(
) {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);
    let revoked_public = insert_key_revocation(&material.public_cert, &material.revocation_cert);
    let unresolved_revoked_public = unresolved_revoked_public_cert(&material);

    for public_cert in [revoked_public, unresolved_revoked_public] {
        assert_callback_not_triggered(
            cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
                &public_cert,
                &signing_key_fingerprint(&material),
                Arc::new(UnexpectedRuntimeSigningProvider),
                &target.public_key_data,
                &selector,
                cert_signature::CertificationKind::Positive,
            ),
        );
    }
}

#[test]
fn test_external_signer_runtime_user_id_certification_allows_expired_but_not_revoked_signer() {
    let material =
        build_candidate_with_expiry(CandidateVersion::V4, Some(1)).expect("candidate should build");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);

    let signature =
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            material.runtime_provider(),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        )
        .expect("expired but not revoked signer should still certify");

    assert_certification_verifies(
        &signature,
        &material.public_cert,
        &signing_key_fingerprint(&material),
        &target.public_key_data,
        &selector,
        cert_signature::CertificationKind::Positive,
    );
}

#[test]
fn test_external_signer_runtime_user_id_certification_preserves_callback_failures() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);

    let cancelled =
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            Arc::new(CancelledRuntimeSigningProvider),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        );
    assert!(matches!(cancelled, Err(PgpError::OperationCancelled)));

    let failed =
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            Arc::new(FailingRuntimeSigningProvider {
                category: ExternalP256SigningFailureCategory::PrivateHandleMissing,
            }),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        );
    match failed {
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
fn test_external_signer_runtime_user_id_certification_rejects_invalid_responses() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);

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
        let result =
            cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
                &material.public_cert,
                &signing_key_fingerprint(&material),
                provider,
                &target.public_key_data,
                &selector,
                cert_signature::CertificationKind::Positive,
            );
        assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
    }
}

#[test]
fn test_external_signer_runtime_user_id_certification_rejects_wrong_public_key_signature() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other should build");
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);

    let result =
        cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            other.runtime_provider(),
            &target.public_key_data,
            &selector,
            cert_signature::CertificationKind::Positive,
        );

    assert!(matches!(result, Err(PgpError::SigningFailed { .. })));
}

#[test]
fn test_external_signer_runtime_user_id_certification_selector_failures_do_not_callback() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let target = generated_target(CandidateVersion::V4);
    let selector = first_user_id_selector(&target.public_key_data);
    let mismatched_user_id = keys::UserIdSelectorInput {
        user_id_data: [selector.user_id_data.clone(), b"-mismatch".to_vec()].concat(),
        occurrence_index: selector.occurrence_index,
    };
    let out_of_range = keys::UserIdSelectorInput {
        user_id_data: selector.user_id_data,
        occurrence_index: selector.occurrence_index + 99,
    };

    for invalid_selector in [mismatched_user_id, out_of_range] {
        assert_callback_not_triggered(
            cert_signature::generate_user_id_certification_by_selector_with_external_p256_signer(
                &material.public_cert,
                &signing_key_fingerprint(&material),
                Arc::new(UnexpectedRuntimeSigningProvider),
                &target.public_key_data,
                &invalid_selector,
                cert_signature::CertificationKind::Positive,
            ),
        );
    }
}
