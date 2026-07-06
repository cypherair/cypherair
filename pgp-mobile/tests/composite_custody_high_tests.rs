//! Device-Bound Post-Quantum · High split-custody tests (RFC 9980 — issue #591
//! Phase 3). Mirrors the 65/768 composite coverage for the ML-DSA-87 + Ed448 /
//! ML-KEM-1024 + X448 tier. The foreign-sender round-trip is the correctness
//! proof for the vendored ML-KEM-1024 + X448 KEM combiner: stock Sequoia
//! encapsulates through its native composite path, and our split-custody
//! decryptor (in-Rust X448 + external ML-KEM-1024 decapsulation + vendored
//! combiner + AES-256 unwrap) must recover the identical session key.

mod common;

use std::io::Write;

use common::composite::SoftwareCompositeHighMaterial;
use common::format::{detect_pkesk_algorithms, detect_seipd_v2_cipher};

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::{AEADAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::signature_details::SignatureVerificationState;
use pgp_mobile::{decrypt, PgpEngine};
use sequoia_openpgp as openpgp;

const PLAINTEXT: &[u8] = b"split-custody composite high message";

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

#[test]
fn generates_policy_valid_v6_composite_high_certificate() {
    let material = SoftwareCompositeHighMaterial::generate(None).expect("generation succeeds");

    let info = keys::parse_key_info(&material.public_key_data).expect("key info parses");
    assert_eq!(info.key_version, 6);
    assert_eq!(info.profile, KeyProfile::PostQuantumHigh);
    assert!(info.has_encryption_subkey);
    assert!(!info.is_revoked);
    assert!(!info.is_expired);

    let cert = openpgp::Cert::from_bytes(&material.public_key_data).expect("cert parses");
    assert!(!cert.is_tsk());
    assert_eq!(
        cert.primary_key().key().pk_algo(),
        PublicKeyAlgorithm::MLDSA87_Ed448
    );
    let subkey_algos: Vec<_> = cert
        .keys()
        .subkeys()
        .map(|subkey| subkey.key().pk_algo())
        .collect();
    assert_eq!(subkey_algos, vec![PublicKeyAlgorithm::MLKEM1024_X448]);

    let policy = StandardPolicy::new();
    let valid_cert = cert
        .with_policy(&policy, None)
        .expect("certificate is policy-valid");
    let primary_userid = valid_cert.primary_userid().expect("primary user id");
    let features = primary_userid
        .binding_signature()
        .features()
        .expect("features are set");
    assert!(features.supports_seipdv2());
    assert!(!features.supports_seipdv1());
}

#[test]
fn inspection_returns_high_component_public_keys() {
    let material = SoftwareCompositeHighMaterial::generate(None).expect("generation succeeds");
    let inspection = engine()
        .inspect_secure_enclave_composite_high_bindings(material.public_key_data.clone())
        .expect("inspection succeeds");

    assert_eq!(inspection.fingerprint, material.fingerprint);
    assert_eq!(inspection.key_version, 6);
    assert_eq!(
        inspection.signing_key_fingerprint,
        material.signing_key_fingerprint
    );
    assert_eq!(
        inspection.mldsa87_signing_public_key,
        material.mldsa87_signing_public_key
    );
    assert_eq!(
        inspection.mlkem1024_key_agreement_public_key,
        material.mlkem1024_key_agreement_public_key
    );
    // Ed448 public keys are 57 bytes, X448 public keys 56 bytes.
    assert_eq!(inspection.eddsa_signing_public_key.len(), 57);
    assert_eq!(inspection.ecdh_key_agreement_public_key.len(), 56);
    assert_eq!(material.classical_eddsa_secret.len(), 57);
    assert_eq!(material.classical_ecdh_secret.len(), 56);
}

#[test]
fn cleartext_signing_round_trips_and_rejects_wrong_classical_component() {
    let material = SoftwareCompositeHighMaterial::generate(None).expect("generation succeeds");

    let signed = engine()
        .sign_cleartext_with_external_composite_high_signer(
            b"device-bound post-quantum high cleartext".to_vec(),
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
        )
        .expect("cleartext signing succeeds");
    let result = engine()
        .verify_cleartext_detailed(signed, vec![material.public_key_data.clone()])
        .expect("verification succeeds");
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);

    // A wrong-length-but-plausible Ed448 secret must fail closed at signer
    // construction (certificate binding mismatch), never emit a signature.
    let wrong_secret = engine().sign_cleartext_with_external_composite_high_signer(
        b"device-bound post-quantum high cleartext".to_vec(),
        material.public_key_data.clone(),
        material.signing_key_fingerprint.clone(),
        vec![7u8; 57],
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
fn foreign_sequoia_message_decrypts_through_split_custody_path() {
    let material = SoftwareCompositeHighMaterial::generate(None).expect("generation succeeds");
    let ciphertext = foreign_stock_encrypt(&material.public_key_data, PLAINTEXT);

    // PQ-only recipient: SEIPDv2 with the AES-256 floor, PKESK algorithm 36.
    assert_eq!(
        detect_pkesk_algorithms(&ciphertext),
        vec![PublicKeyAlgorithm::MLKEM1024_X448]
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
        .decrypt_detailed_with_external_composite_high_key_agreement(
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
fn engine_encrypts_signs_and_decrypts_through_split_custody() {
    let material = SoftwareCompositeHighMaterial::generate(None).expect("generation succeeds");

    // Encrypt to and sign with the same · High identity, exercising both the
    // external ML-DSA-87 signer and the external ML-KEM-1024 decapsulator.
    let ciphertext = engine()
        .encrypt_with_external_composite_high_signer(
            PLAINTEXT.to_vec(),
            vec![material.public_key_data.clone()],
            material.public_key_data.clone(),
            material.signing_key_fingerprint.clone(),
            material.classical_eddsa_secret.clone(),
            material.signing_provider(),
            None,
        )
        .expect("engine encrypt succeeds");

    let result = engine()
        .decrypt_detailed_with_external_composite_high_key_agreement(
            ciphertext,
            material.public_key_data.clone(),
            material.key_agreement_subkey_fingerprint.clone(),
            material.classical_ecdh_secret.clone(),
            material.decapsulation_provider(),
            vec![material.public_key_data.clone()],
        )
        .expect("split-custody decrypt succeeds");
    assert_eq!(result.plaintext, PLAINTEXT);
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}
