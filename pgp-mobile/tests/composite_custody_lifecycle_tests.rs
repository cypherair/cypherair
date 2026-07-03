//! Device-Bound Post-Quantum split-custody lifecycle tests (RFC 9980 —
//! issue #567 Phase 3). Covers production certificate generation around
//! software PQ component keys, certificate shape and policy validity,
//! inspection, revocation, expiry modification, certification, and the
//! fail-closed generation/signing negatives.

mod common;

use std::sync::Arc;

use common::composite::{
    CancellingMlDsa65SigningProvider, SoftwareCompositeMaterial, MLDSA65_PUBLIC_KEY_LENGTH,
    MLKEM768_PUBLIC_KEY_LENGTH,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::{PublicKeyAlgorithm, RevocationStatus, SymmetricAlgorithm};
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile, SecureEnclaveCompositePublicCertificateInput};
use pgp_mobile::PgpEngine;
use sequoia_openpgp as openpgp;

fn engine() -> PgpEngine {
    PgpEngine::new()
}

#[test]
fn generates_policy_valid_v6_composite_certificate() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");

    let info = keys::parse_key_info(&material.public_key_data).expect("key info parses");
    assert_eq!(info.key_version, 6);
    assert_eq!(info.profile, KeyProfile::PostQuantum);
    assert!(info.has_encryption_subkey);
    assert!(!info.is_revoked);
    assert!(!info.is_expired);

    let cert = openpgp::Cert::from_bytes(&material.public_key_data).expect("cert parses");
    assert!(!cert.is_tsk());
    assert_eq!(
        cert.primary_key().key().pk_algo(),
        PublicKeyAlgorithm::MLDSA65_Ed25519
    );
    let subkey_algos: Vec<_> = cert
        .keys()
        .subkeys()
        .map(|subkey| subkey.key().pk_algo())
        .collect();
    assert_eq!(subkey_algos, vec![PublicKeyAlgorithm::MLKEM768_X25519]);

    let policy = StandardPolicy::new();
    let valid_cert = cert
        .with_policy(&policy, None)
        .expect("certificate is policy-valid");
    let primary_signature = valid_cert.primary_userid().expect("primary user id");
    let features = primary_signature
        .binding_signature()
        .features()
        .expect("features are set");
    assert!(features.supports_seipdv2());
    assert!(!features.supports_seipdv1());
    let preferred_symmetric = primary_signature
        .binding_signature()
        .preferred_symmetric_algorithms()
        .expect("symmetric preferences are set");
    assert_eq!(
        preferred_symmetric.first(),
        Some(&SymmetricAlgorithm::AES256)
    );

    let signing_capable: Vec<_> = valid_cert
        .keys()
        .alive()
        .revoked(false)
        .for_signing()
        .map(|ka| ka.key().fingerprint().to_hex().to_lowercase())
        .collect();
    assert_eq!(
        signing_capable,
        vec![material.signing_key_fingerprint.clone()]
    );
    let encryption_capable: Vec<_> = valid_cert
        .keys()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(|ka| ka.key().fingerprint().to_hex().to_lowercase())
        .collect();
    assert_eq!(
        encryption_capable,
        vec![material.key_agreement_subkey_fingerprint.clone()]
    );
}

#[test]
fn inspection_returns_component_public_keys() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let inspection = engine()
        .inspect_secure_enclave_composite_bindings(material.public_key_data.clone())
        .expect("inspection succeeds");

    assert_eq!(inspection.fingerprint, material.fingerprint);
    assert_eq!(inspection.key_version, 6);
    assert_eq!(
        inspection.signing_key_fingerprint,
        material.signing_key_fingerprint
    );
    assert_eq!(
        inspection.key_agreement_subkey_fingerprint,
        material.key_agreement_subkey_fingerprint
    );
    assert_eq!(
        inspection.mldsa65_signing_public_key,
        material.mldsa65_signing_public_key
    );
    assert_eq!(
        inspection.mlkem768_key_agreement_public_key,
        material.mlkem768_key_agreement_public_key
    );
    assert_eq!(inspection.eddsa_signing_public_key.len(), 32);
    assert_eq!(inspection.ecdh_key_agreement_public_key.len(), 32);
    assert_eq!(material.classical_eddsa_secret.len(), 32);
    assert_eq!(material.classical_ecdh_secret.len(), 32);
}

#[test]
fn pre_generated_revocation_certificate_verifies() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let reason = keys::parse_revocation_cert(&material.revocation_cert, &material.public_key_data)
        .expect("revocation certificate verifies against its certificate");
    assert!(!reason.is_empty());
}

#[test]
fn generation_rejects_invalid_component_public_keys() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let provider = material.signing_provider();

    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        // Wrong ML-DSA public length.
        (
            vec![1u8; 100],
            material.mlkem768_key_agreement_public_key.clone(),
        ),
        // All-zero ML-DSA public.
        (
            vec![0u8; MLDSA65_PUBLIC_KEY_LENGTH],
            material.mlkem768_key_agreement_public_key.clone(),
        ),
        // Wrong ML-KEM public length.
        (material.mldsa65_signing_public_key.clone(), vec![1u8; 100]),
        // Non-canonical ML-KEM coefficients (0xFFF >= q).
        (
            material.mldsa65_signing_public_key.clone(),
            vec![0xFFu8; MLKEM768_PUBLIC_KEY_LENGTH],
        ),
    ];
    for (mldsa_public, mlkem_public) in cases {
        let result = keys::generate_secure_enclave_composite_public_certificate(
            SecureEnclaveCompositePublicCertificateInput {
                name: "Invalid Component".to_string(),
                email: None,
                expiry_seconds: None,
                mldsa65_signing_public_key: mldsa_public,
                mlkem768_key_agreement_public_key: mlkem_public,
            },
            Arc::clone(&provider),
        );
        assert!(matches!(result, Err(PgpError::InvalidKeyData { .. })));
    }

    let empty_name = keys::generate_secure_enclave_composite_public_certificate(
        SecureEnclaveCompositePublicCertificateInput {
            name: "   ".to_string(),
            email: None,
            expiry_seconds: None,
            mldsa65_signing_public_key: material.mldsa65_signing_public_key.clone(),
            mlkem768_key_agreement_public_key: material.mlkem768_key_agreement_public_key.clone(),
        },
        provider,
    );
    assert!(matches!(empty_name, Err(PgpError::InvalidKeyData { .. })));
}

#[test]
fn generation_fails_closed_when_provider_key_does_not_match_public() {
    let material_a = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let material_b = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");

    // Provider B signs with a different ML-DSA key than the supplied public:
    // the self-verify inside the composite signer must fail the first binding.
    let result = keys::generate_secure_enclave_composite_public_certificate(
        SecureEnclaveCompositePublicCertificateInput {
            name: "Mismatched Provider".to_string(),
            email: None,
            expiry_seconds: None,
            mldsa65_signing_public_key: material_a.mldsa65_signing_public_key.clone(),
            mlkem768_key_agreement_public_key: material_a.mlkem768_key_agreement_public_key.clone(),
        },
        material_b.signing_provider(),
    );
    match result {
        Err(PgpError::KeyGenerationFailed { reason }) => {
            assert!(reason.contains("unverified"), "reason: {reason}")
        }
        Err(other) => panic!("expected KeyGenerationFailed, got {other:?}"),
        Ok(_) => panic!("expected KeyGenerationFailed, got a generated certificate"),
    }
}

#[test]
fn generation_propagates_cancellation() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let result = keys::generate_secure_enclave_composite_public_certificate(
        SecureEnclaveCompositePublicCertificateInput {
            name: "Cancelled".to_string(),
            email: None,
            expiry_seconds: None,
            mldsa65_signing_public_key: material.mldsa65_signing_public_key.clone(),
            mlkem768_key_agreement_public_key: material.mlkem768_key_agreement_public_key.clone(),
        },
        Arc::new(CancellingMlDsa65SigningProvider),
    );
    assert!(matches!(result, Err(PgpError::OperationCancelled)));
}

#[test]
fn cleartext_signing_round_trips_and_rejects_wrong_classical_component() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");

    let signed = engine()
        .sign_cleartext_with_external_composite_signer(
            b"device-bound post-quantum cleartext".to_vec(),
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
        )
        .expect("cleartext signing succeeds");
    let result = engine()
        .verify_cleartext_detailed(signed, vec![material.public_key_data.clone()])
        .expect("verification succeeds");
    assert_eq!(
        result.summary_state,
        pgp_mobile::signature_details::SignatureVerificationState::Verified
    );

    let wrong_secret = engine().sign_cleartext_with_external_composite_signer(
        b"device-bound post-quantum cleartext".to_vec(),
        material.public_key_data.clone(),
        material.signing_key_fingerprint.clone(),
        vec![7u8; 32],
        material.signing_provider(),
    );
    match wrong_secret {
        Err(PgpError::SigningFailed { reason }) => {
            assert!(reason.contains("does not match"), "reason: {reason}")
        }
        other => panic!("expected SigningFailed, got {other:?}"),
    }
}

#[test]
fn expiry_modification_updates_public_certificate() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let before = keys::parse_key_info(&material.public_key_data).expect("key info parses");

    let updated = engine()
        .modify_expiry_with_external_composite_signer(
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            Some(90 * 24 * 60 * 60),
        )
        .expect("expiry modification succeeds");

    assert_ne!(updated.key_info.expiry_timestamp, before.expiry_timestamp);
    assert!(updated.key_info.expiry_timestamp.is_some());
    let cert = openpgp::Cert::from_bytes(&updated.public_key_data).expect("updated cert parses");
    assert!(!cert.is_tsk());
}

#[test]
fn subkey_and_user_id_revocations_apply_to_certificate() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let policy = StandardPolicy::new();

    let subkey_revocation = engine()
        .generate_subkey_revocation_with_external_composite_signer(
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            material.key_agreement_subkey_fingerprint.clone(),
        )
        .expect("subkey revocation generates");
    let packet = openpgp::Packet::from_bytes(&subkey_revocation).expect("signature parses");
    let openpgp::Packet::Signature(signature) = packet else {
        panic!("expected a signature packet");
    };
    let cert = openpgp::Cert::from_bytes(&material.public_key_data).expect("cert parses");
    let (cert, _) = cert
        .insert_packets(vec![openpgp::Packet::from(signature)])
        .expect("revocation merges");
    let subkey = cert.keys().subkeys().next().expect("subkey present");
    assert!(matches!(
        subkey.revocation_status(&policy, None),
        RevocationStatus::Revoked(_)
    ));

    let selectors = keys::discover_certificate_selectors(&material.public_key_data)
        .expect("selectors discover");
    let user_id = selectors.user_ids.first().expect("user id present");
    let user_id_revocation = engine()
        .generate_user_id_revocation_by_selector_with_external_composite_signer(
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            pgp_mobile::keys::UserIdSelectorInput {
                user_id_data: user_id.user_id_data.clone(),
                occurrence_index: user_id.occurrence_index,
            },
        )
        .expect("user id revocation generates");
    let packet = openpgp::Packet::from_bytes(&user_id_revocation).expect("signature parses");
    let openpgp::Packet::Signature(signature) = packet else {
        panic!("expected a signature packet");
    };
    let cert = openpgp::Cert::from_bytes(&material.public_key_data).expect("cert parses");
    let (cert, _) = cert
        .insert_packets(vec![openpgp::Packet::from(signature)])
        .expect("revocation merges");
    let revoked_user_id = cert.userids().next().expect("user id present");
    assert!(matches!(
        revoked_user_id.revocation_status(&policy, None),
        RevocationStatus::Revoked(_)
    ));
}

#[test]
fn certifies_another_certificate_user_id() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let target = keys::generate_key_with_profile(
        "Certified Contact".to_string(),
        Some("contact@example.test".to_string()),
        None,
        KeyProfile::Universal,
    )
    .expect("target key generates");

    let selectors =
        keys::discover_certificate_selectors(&target.public_key_data).expect("selectors discover");
    let user_id = selectors.user_ids.first().expect("user id present");

    let certification = engine()
        .generate_user_id_certification_by_selector_with_external_composite_signer(
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            target.public_key_data.clone(),
            pgp_mobile::keys::UserIdSelectorInput {
                user_id_data: user_id.user_id_data.clone(),
                occurrence_index: user_id.occurrence_index,
            },
            pgp_mobile::cert_signature::CertificationKind::Generic,
        )
        .expect("certification generates");

    let packet = openpgp::Packet::from_bytes(&certification).expect("signature parses");
    let openpgp::Packet::Signature(signature) = packet else {
        panic!("expected a signature packet");
    };
    let signer_cert =
        openpgp::Cert::from_bytes(&material.public_key_data).expect("signer cert parses");
    let target_cert = openpgp::Cert::from_bytes(&target.public_key_data).expect("target parses");
    let target_user_id = target_cert.userids().next().expect("target user id");
    signature
        .verify_userid_binding(
            signer_cert.primary_key().key(),
            target_cert.primary_key().key(),
            target_user_id.userid(),
        )
        .expect("certification verifies against the composite signer");
}
