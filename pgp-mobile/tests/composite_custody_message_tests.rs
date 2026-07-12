//! Device-Bound Post-Quantum split-custody message tests (RFC 9980 —
//! issue #567 Phase 3). The foreign-sender round-trip is the correctness
//! proof for the vendored KEM combiner: stock Sequoia encapsulates through
//! its native composite path, and our split-custody decryptor (in-Rust
//! X25519 + external ML-KEM decapsulation + vendored combiner + AES-256
//! unwrap) must recover the identical session key.

mod common;

use std::io::Write;
use std::sync::Arc;

use common::composite::{
    CancellingMlKem768DecapsulationProvider, SoftwareCompositeMaterial,
    WrongShareMlKem768DecapsulationProvider,
};
use common::format::{detect_pkesk_algorithms, detect_seipd_v2_cipher};

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient};
use openpgp::types::{AEADAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{
    self, ExternalCompositeKeyAgreementError, ExternalCompositeKeyAgreementFailureCategory,
    ExternalMlKem768DecapsulationProvider, ExternalMlKem768DecapsulationRequest, KeyProfile,
    MlKem768KeyShare,
};
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::{decrypt, PgpEngine};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

const PLAINTEXT: &[u8] = b"split-custody composite message";

fn engine() -> PgpEngine {
    PgpEngine::new()
}

/// Encrypt the way another Sequoia-based RFC 9980 implementation (e.g. `sq`)
/// would: stock streaming Encryptor over the certificate's policy-valid
/// transport-encryption keys, native composite encapsulation included.
fn foreign_stock_encrypt(recipient_cert_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(recipient_cert_data).expect("recipient cert parses");
    let valid_cert = cert.with_policy(&policy, None).expect("policy-valid cert");
    let recipients = valid_cert
        .keys()
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .expect("encryptor builds");
    let mut literal = LiteralWriter::new(message).build().expect("literal builds");
    literal.write_all(plaintext).expect("write plaintext");
    literal.finalize().expect("finalize");
    sink
}

/// Encrypt with hidden (wildcard) recipient key IDs, preserving the given
/// recipient order, so PKESK-skip semantics can be exercised end to end.
fn encrypt_hidden_recipients(recipient_cert_data: &[&[u8]], plaintext: &[u8]) -> Vec<u8> {
    let policy = StandardPolicy::new();
    let certs: Vec<openpgp::Cert> = recipient_cert_data
        .iter()
        .map(|bytes| openpgp::Cert::from_bytes(bytes).expect("recipient cert parses"))
        .collect();

    let mut recipients: Vec<Recipient> = Vec::new();
    for cert in &certs {
        for ka in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            let recipient: Recipient = ka.into();
            let hidden = recipient
                .set_key_handle(None)
                .expect("hide recipient keyid");
            recipients.push(hidden);
        }
    }

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .expect("encryptor builds");
    let mut literal = LiteralWriter::new(message).build().expect("literal builds");
    literal.write_all(plaintext).expect("write plaintext");
    literal.finalize().expect("finalize");
    sink
}

#[test]
fn wildcard_non_composite_pkesk_is_skipped_and_composite_pkesk_decrypts() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let legacy = keys::generate_key_with_profile(
        "Hidden Universal Peer".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("profile A generates");

    // Hidden (wildcard) recipients; the non-composite X25519 PKESK is emitted
    // before the composite PKESK. A wildcard recipient speculatively matches
    // our key, so the foreign packet reaches prepare_request and is rejected as
    // a non-match: it must be skipped, not treated as a definitive failure.
    let ciphertext = encrypt_hidden_recipients(
        &[
            legacy.public_key_data.as_slice(),
            material.public_key_data.as_slice(),
        ],
        PLAINTEXT,
    );

    let result = engine()
        .decrypt_detailed_with_external_composite_key_agreement(
            ciphertext,
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.classical_ecdh_secret.clone(),
            material.decapsulation_provider(),
            vec![],
        )
        .expect("non-composite wildcard PKESK must be skipped and ours decrypted");
    assert_eq!(result.plaintext, PLAINTEXT);
}

#[test]
fn wildcard_other_composite_recipient_pkesk_is_skipped_via_unwrap_failure() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let other = SoftwareCompositeMaterial::generate(None).expect("other generation succeeds");

    // Hidden (wildcard) recipients; a different composite recipient's PKESK is
    // emitted first. Decapsulating it with our key yields an implicit-rejection
    // share, so the session-key unwrap fails without recording a definitive
    // error, and decryption must continue to our own PKESK.
    let ciphertext = encrypt_hidden_recipients(
        &[
            other.public_key_data.as_slice(),
            material.public_key_data.as_slice(),
        ],
        PLAINTEXT,
    );

    let result = engine()
        .decrypt_detailed_with_external_composite_key_agreement(
            ciphertext,
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.classical_ecdh_secret.clone(),
            material.decapsulation_provider(),
            vec![],
        )
        .expect("the other recipient's wildcard PKESK must be skipped and ours decrypted");
    assert_eq!(result.plaintext, PLAINTEXT);
}

#[test]
fn foreign_sequoia_message_decrypts_through_split_custody_path() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let ciphertext = foreign_stock_encrypt(&material.public_key_data, PLAINTEXT);

    // PQ-only recipient: SEIPDv2 with the AES-256 floor, PKESK algorithm 35.
    assert_eq!(
        detect_pkesk_algorithms(&ciphertext),
        vec![PublicKeyAlgorithm::MLKEM768_X25519]
    );
    assert_eq!(
        detect_seipd_v2_cipher(&ciphertext),
        Some((SymmetricAlgorithm::AES256, AEADAlgorithm::OCB))
    );
    assert_eq!(
        decrypt::message_quantum_safety(&ciphertext).expect("quantum safety derives"),
        decrypt::MessageQuantumSafety::FullyPostQuantum
    );

    let result = engine()
        .decrypt_detailed_with_external_composite_key_agreement(
            ciphertext,
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.classical_ecdh_secret.clone(),
            material.decapsulation_provider(),
            vec![],
        )
        .expect("split-custody decrypt succeeds");
    assert_eq!(result.plaintext, PLAINTEXT);
    assert_eq!(result.summary_state, SignatureVerificationState::NotSigned);
}

#[test]
fn engine_encrypts_and_signs_to_foreign_pq_recipient() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let (foreign_tsk, foreign_public_armored) = common::pq::generate_foreign_pq();

    let ciphertext = engine()
        .encrypt_with_external_composite_signer(
            PLAINTEXT.to_vec(),
            vec![foreign_public_armored.clone()],
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            None,
        )
        .expect("engine encrypt succeeds");

    // The foreign side decrypts with stock software keys and verifies our
    // composite signature against the split-custody public certificate.
    let secret_keys = vec![Zeroizing::new(foreign_tsk)];
    let result = decrypt::decrypt_detailed(
        &ciphertext,
        &secret_keys,
        &[material.public_key_data.clone()],
    )
    .expect("foreign decrypt succeeds");
    assert_eq!(result.plaintext, PLAINTEXT);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

#[test]
fn mixed_v4_recipient_set_keeps_both_recipients_decryptable() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let legacy = keys::generate_key_with_profile(
        "Universal Peer".to_string(),
        None,
        None,
        KeyProfile::Universal,
    )
    .expect("profile A generates");

    let ciphertext = engine()
        .encrypt(
            PLAINTEXT.to_vec(),
            vec![
                material.public_key_data.clone(),
                legacy.public_key_data.clone(),
            ],
            None,
            None,
        )
        .expect("mixed encrypt succeeds");

    // Mixed with a v4 recipient: SEIPDv1 (no v2 container), one composite PKESK.
    assert_eq!(detect_seipd_v2_cipher(&ciphertext), None);
    let algorithms = detect_pkesk_algorithms(&ciphertext);
    assert_eq!(algorithms.len(), 2);
    assert!(algorithms.contains(&PublicKeyAlgorithm::MLKEM768_X25519));
    assert_eq!(
        decrypt::message_quantum_safety(&ciphertext).expect("quantum safety derives"),
        decrypt::MessageQuantumSafety::Mixed
    );

    let split_custody = engine()
        .decrypt_detailed_with_external_composite_key_agreement(
            ciphertext.clone(),
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.classical_ecdh_secret.clone(),
            material.decapsulation_provider(),
            vec![],
        )
        .expect("split-custody decrypt succeeds");
    assert_eq!(split_custody.plaintext, PLAINTEXT);

    let secret_keys = vec![Zeroizing::new(legacy.cert_data)];
    let software = decrypt::decrypt_detailed(&ciphertext, &secret_keys, &[])
        .expect("profile A decrypt succeeds");
    assert_eq!(software.plaintext, PLAINTEXT);
}

#[test]
fn decrypt_fails_closed_on_wrong_key_share() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let ciphertext = foreign_stock_encrypt(&material.public_key_data, PLAINTEXT);

    let result = engine().decrypt_detailed_with_external_composite_key_agreement(
        ciphertext,
        material.public_key_data.clone(),
        material.key_agreement_subkey_fingerprint.clone(),
        material.classical_ecdh_secret.clone(),
        Arc::new(WrongShareMlKem768DecapsulationProvider),
        vec![],
    );
    // A wrong-but-well-formed key share must fail AES key unwrap and abort
    // with an error — never partial plaintext, never a cancellation.
    let error = result.err().expect("wrong key share must fail");
    assert!(!matches!(error, PgpError::OperationCancelled));
}

#[test]
fn decrypt_propagates_cancellation_and_failure_categories() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let ciphertext = foreign_stock_encrypt(&material.public_key_data, PLAINTEXT);

    let cancelled = engine().decrypt_detailed_with_external_composite_key_agreement(
        ciphertext.clone(),
        material.public_key_data.clone(),
        material.key_agreement_subkey_fingerprint.clone(),
        material.classical_ecdh_secret.clone(),
        Arc::new(CancellingMlKem768DecapsulationProvider),
        vec![],
    );
    assert!(matches!(cancelled, Err(PgpError::OperationCancelled)));

    struct FailingProvider;
    impl ExternalMlKem768DecapsulationProvider for FailingProvider {
        fn decapsulate_mlkem768(
            &self,
            _request: ExternalMlKem768DecapsulationRequest,
        ) -> Result<MlKem768KeyShare, ExternalCompositeKeyAgreementError> {
            Err(ExternalCompositeKeyAgreementError::Failed {
                category: ExternalCompositeKeyAgreementFailureCategory::LocalAuthenticationFailed,
            })
        }
    }
    let failed = engine().decrypt_detailed_with_external_composite_key_agreement(
        ciphertext.clone(),
        material.public_key_data.clone(),
        material.key_agreement_subkey_fingerprint.clone(),
        material.classical_ecdh_secret.clone(),
        Arc::new(FailingProvider),
        vec![],
    );
    assert!(matches!(
        failed,
        Err(PgpError::ExternalCompositeKeyAgreementFailed {
            category: ExternalCompositeKeyAgreementFailureCategory::LocalAuthenticationFailed,
        })
    ));

    let wrong_classical = engine().decrypt_detailed_with_external_composite_key_agreement(
        ciphertext,
        material.public_key_data.clone(),
        material.key_agreement_subkey_fingerprint.clone(),
        vec![7u8; 32],
        material.decapsulation_provider(),
        vec![],
    );
    assert!(wrong_classical.is_err());
}

#[test]
fn password_message_twins_round_trip_with_verified_signature() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");

    let ciphertext = engine()
        .encrypt_with_password_and_external_composite_signer(
            PLAINTEXT.to_vec(),
            "correct horse battery staple".to_string(),
            pgp_mobile::password::PasswordMessageFormat::Seipdv2,
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
        )
        .expect("password encrypt succeeds");

    let result = engine()
        .decrypt_with_password(
            ciphertext,
            "correct horse battery staple".to_string(),
            vec![material.public_key_data.clone()],
        )
        .expect("password decrypt succeeds");
    assert_eq!(result.plaintext.as_deref(), Some(PLAINTEXT));
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

#[test]
fn file_streaming_twins_round_trip_with_verified_signature() {
    let material = SoftwareCompositeMaterial::generate(None).expect("generation succeeds");
    let workdir = tempfile::tempdir().expect("tempdir");
    let input_path = workdir.path().join("plain.txt");
    let encrypted_path = workdir.path().join("cipher.asc");
    let decrypted_path = workdir.path().join("roundtrip.txt");
    std::fs::write(&input_path, PLAINTEXT).expect("write input");

    engine()
        .encrypt_file_with_external_composite_signer(
            input_path.to_string_lossy().into_owned(),
            encrypted_path.to_string_lossy().into_owned(),
            vec![material.public_key_data.clone()],
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            None,
            None,
        )
        .expect("file encrypt succeeds");

    let result = engine()
        .decrypt_file_detailed_with_external_composite_key_agreement(
            encrypted_path.to_string_lossy().into_owned(),
            decrypted_path.to_string_lossy().into_owned(),
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.classical_ecdh_secret.clone(),
            material.decapsulation_provider(),
            vec![material.public_key_data.clone()],
            None,
        )
        .expect("file decrypt succeeds");
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    assert_eq!(
        std::fs::read(&decrypted_path).expect("read decrypted"),
        PLAINTEXT
    );

    let signature = engine()
        .sign_detached_file_with_external_composite_signer(
            input_path.to_string_lossy().into_owned(),
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            None,
        )
        .expect("detached sign succeeds");
    let verify = engine()
        .verify_detached_file_detailed(
            input_path.to_string_lossy().into_owned(),
            signature,
            vec![material.public_key_data.clone()],
            None,
        )
        .expect("detached verify succeeds");
    assert_eq!(verify.summary_state, SignatureVerificationState::Verified);
}
