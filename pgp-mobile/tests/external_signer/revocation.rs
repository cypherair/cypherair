use super::*;

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

fn insert_signature(public_cert: &[u8], signature: &[u8]) -> openpgp::Cert {
    let cert = openpgp::Cert::from_bytes(public_cert).expect("public cert should parse");
    let packet = Packet::from_bytes(signature).expect("signature packet should parse");
    cert.insert_packets(vec![packet])
        .expect("signature should insert")
        .0
}

fn assert_subkey_revoked(public_cert: &[u8], revocation: &[u8]) {
    let revoked_cert = insert_signature(public_cert, revocation);
    let policy = StandardPolicy::new();
    let subkey = revoked_cert
        .keys()
        .subkeys()
        .next()
        .expect("subkey should still exist");
    assert!(
        matches!(
            subkey.revocation_status(&policy, None),
            openpgp::types::RevocationStatus::Revoked(_)
        ),
        "selected subkey should be revoked after inserting revocation signature"
    );
}

fn assert_user_id_revoked(public_cert: &[u8], revocation: &[u8]) {
    let revoked_cert = insert_signature(public_cert, revocation);
    let policy = StandardPolicy::new();
    let user_id = revoked_cert
        .userids()
        .next()
        .expect("User ID should still exist");
    assert!(
        matches!(
            user_id.revocation_status(&policy, None),
            openpgp::types::RevocationStatus::Revoked(_)
        ),
        "selected User ID should be revoked after inserting revocation signature"
    );
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
        "Duplicated Secure Enclave User <duplicate@example.test>".into();
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
        .add_userid("Signing Only Primary <signing-only-primary@example.test>")
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
fn test_external_signer_runtime_selective_revocations_revoke_targets_for_v4_and_v6() {
    for version in CandidateVersion::all() {
        let material = build_candidate(version).expect("candidate should build");
        let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);
        let user_id_selector = first_user_id_selector(&material.public_cert);

        let subkey_revocation = keys::generate_subkey_revocation_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            material.runtime_provider(),
            &subkey_fingerprint,
        )
        .expect("external subkey revocation should generate");
        assert_valid_public_candidate(version, &material.public_cert);
        assert_subkey_revoked(&material.public_cert, &subkey_revocation);

        let user_id_revocation =
            keys::generate_user_id_revocation_by_selector_with_external_p256_signer(
                &material.public_cert,
                &signing_key_fingerprint(&material),
                material.runtime_provider(),
                &user_id_selector,
            )
            .expect("external User ID revocation should generate");
        assert_user_id_revoked(&material.public_cert, &user_id_revocation);
    }
}

#[test]
fn test_external_signer_runtime_selective_revocations_use_sha256_hash() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);
    let user_id_selector = first_user_id_selector(&material.public_cert);

    let subkey_revocation = keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        material.runtime_provider(),
        &subkey_fingerprint,
    )
    .expect("external subkey revocation should generate");
    let user_id_revocation =
        keys::generate_user_id_revocation_by_selector_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            material.runtime_provider(),
            &user_id_selector,
        )
        .expect("external User ID revocation should generate");

    assert_signature_hash(&subkey_revocation, HashAlgorithm::SHA256);
    assert_signature_hash(&user_id_revocation, HashAlgorithm::SHA256);
}

#[test]
fn test_software_selective_revocations_keep_default_hash() {
    let generated = keys::generate_key_with_profile(
        "Software Selective Revocation Hash".to_string(),
        Some("software-selective-revocation-hash@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("software key should generate");
    let subkey_fingerprint = first_subkey_fingerprint(&generated.public_key_data);
    let user_id_selector = first_user_id_selector(&generated.public_key_data);

    let subkey_revocation =
        keys::generate_subkey_revocation(&generated.cert_data, &subkey_fingerprint)
            .expect("software subkey revocation should generate");
    let user_id_revocation =
        keys::generate_user_id_revocation_by_selector(&generated.cert_data, &user_id_selector)
            .expect("software User ID revocation should generate");

    assert_signature_hash(&subkey_revocation, HashAlgorithm::SHA512);
    assert_signature_hash(&user_id_revocation, HashAlgorithm::SHA512);
}

#[test]
fn test_external_signer_runtime_user_id_revocation_accepts_duplicate_occurrence_selector() {
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

    let revocation = keys::generate_user_id_revocation_by_selector_with_external_p256_signer(
        &duplicated_public,
        &signing_key_fingerprint(&material),
        material.runtime_provider(),
        &selector,
    )
    .expect("duplicate occurrence selector should generate revocation");

    assert!(!revocation.is_empty());
}

#[test]
fn test_external_signer_runtime_selective_revocation_primary_only_before_callback() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);
    let user_id_selector = first_user_id_selector(&material.public_cert);

    assert_callback_not_triggered(keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &subkey_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        &subkey_fingerprint,
    ));
    assert_callback_not_triggered(
        keys::generate_user_id_revocation_by_selector_with_external_p256_signer(
            &material.public_cert,
            &subkey_fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
            &user_id_selector,
        ),
    );
}

#[test]
fn test_external_signer_runtime_selective_revocation_requires_certification_capable_primary_before_callback(
) {
    let (public_cert, primary_fingerprint) = signing_only_primary_public_cert();
    let subkey_fingerprint = first_subkey_fingerprint(&public_cert);
    let user_id_selector = first_user_id_selector(&public_cert);

    assert_callback_not_triggered(keys::generate_subkey_revocation_with_external_p256_signer(
        &public_cert,
        &primary_fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        &subkey_fingerprint,
    ));
    assert_callback_not_triggered(
        keys::generate_user_id_revocation_by_selector_with_external_p256_signer(
            &public_cert,
            &primary_fingerprint,
            Arc::new(UnexpectedRuntimeSigningProvider),
            &user_id_selector,
        ),
    );
}

#[test]
fn test_external_signer_runtime_selective_revocation_rejects_secret_input_before_callback() {
    let generated = keys::generate_key_with_profile(
        "Secret Selective Revocation".to_string(),
        Some("secret-selective-revocation@example.test".to_string()),
        None,
        keys::KeyProfile::Universal,
    )
    .expect("software key should generate");

    assert_callback_not_triggered(keys::generate_subkey_revocation_with_external_p256_signer(
        &generated.cert_data,
        &generated.fingerprint,
        Arc::new(UnexpectedRuntimeSigningProvider),
        &first_subkey_fingerprint(&generated.public_key_data),
    ));
}

#[test]
fn test_external_signer_runtime_selective_revocation_rejects_revoked_or_unresolved_before_callback()
{
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);
    let revoked_public = insert_key_revocation(&material.public_cert, &material.revocation_cert);
    let unresolved_revoked_public = unresolved_revoked_public_cert(&material);

    assert_callback_not_triggered(keys::generate_subkey_revocation_with_external_p256_signer(
        &revoked_public,
        &signing_key_fingerprint(&material),
        Arc::new(UnexpectedRuntimeSigningProvider),
        &subkey_fingerprint,
    ));
    assert_callback_not_triggered(keys::generate_subkey_revocation_with_external_p256_signer(
        &unresolved_revoked_public,
        &signing_key_fingerprint(&material),
        Arc::new(UnexpectedRuntimeSigningProvider),
        &subkey_fingerprint,
    ));
}

#[test]
fn test_external_signer_runtime_selective_revocation_allows_expired_public_cert() {
    let material =
        build_candidate_with_expiry(CandidateVersion::V4, Some(1)).expect("candidate should build");
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);
    sleep_past(first_transport_subkey_expiry(&material.public_cert));
    assert_primary_expired_now(&material.public_cert);

    let revocation = keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        material.runtime_provider(),
        &subkey_fingerprint,
    )
    .expect("expired but unrevoked cert should allow selective revocation");

    assert_subkey_revoked(&material.public_cert, &revocation);
}

#[test]
fn test_external_signer_runtime_selective_revocation_cancellation_and_categories_are_preserved() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);
    let user_id_selector = first_user_id_selector(&material.public_cert);

    let cancelled = keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(CancelledRuntimeSigningProvider),
        &subkey_fingerprint,
    );
    assert!(matches!(cancelled, Err(PgpError::OperationCancelled)));

    let failed = keys::generate_user_id_revocation_by_selector_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(FailingRuntimeSigningProvider {
            category: ExternalP256SigningFailureCategory::PrivateHandleMissing,
        }),
        &user_id_selector,
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
fn test_external_signer_runtime_selective_revocation_rejects_invalid_responses() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);

    let malformed = keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![1u8; P256_SCALAR_LENGTH - 1],
            s: vec![1u8; P256_SCALAR_LENGTH],
        }),
        &subkey_fingerprint,
    );
    assert!(matches!(malformed, Err(PgpError::RevocationError { .. })));

    let zero = keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(MalformedRuntimeSigningProvider {
            r: vec![0u8; P256_SCALAR_LENGTH],
            s: vec![1u8; P256_SCALAR_LENGTH],
        }),
        &subkey_fingerprint,
    );
    assert!(matches!(zero, Err(PgpError::RevocationError { .. })));
}

#[test]
fn test_external_signer_runtime_selective_revocation_rejects_wrong_digest_and_public_key() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let other = build_candidate(CandidateVersion::V4).expect("other candidate should build");
    let subkey_fingerprint = first_subkey_fingerprint(&material.public_cert);

    let wrong_digest = keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(WrongDigestRuntimeSigningProvider {
            keypair: material.keypair.clone(),
        }),
        &subkey_fingerprint,
    );
    assert!(matches!(
        wrong_digest,
        Err(PgpError::RevocationError { .. })
    ));

    let wrong_key = keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        other.runtime_provider(),
        &subkey_fingerprint,
    );
    assert!(matches!(wrong_key, Err(PgpError::RevocationError { .. })));
}

#[test]
fn test_external_signer_runtime_selective_revocation_selector_failures_do_not_callback() {
    let material = build_candidate(CandidateVersion::V4).expect("candidate should build");
    let user_id_selector = first_user_id_selector(&material.public_cert);
    let mismatched_user_id = keys::UserIdSelectorInput {
        user_id_data: [user_id_selector.user_id_data.clone(), b"-mismatch".to_vec()].concat(),
        occurrence_index: user_id_selector.occurrence_index,
    };

    assert_callback_not_triggered(keys::generate_subkey_revocation_with_external_p256_signer(
        &material.public_cert,
        &signing_key_fingerprint(&material),
        Arc::new(UnexpectedRuntimeSigningProvider),
        "0000000000000000000000000000000000000000",
    ));
    assert_callback_not_triggered(
        keys::generate_user_id_revocation_by_selector_with_external_p256_signer(
            &material.public_cert,
            &signing_key_fingerprint(&material),
            Arc::new(UnexpectedRuntimeSigningProvider),
            &mismatched_user_id,
        ),
    );
}
