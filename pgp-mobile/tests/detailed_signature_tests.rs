use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use openpgp::types::SignatureType;
use pgp_mobile::decrypt::{self, SignatureStatus};
use pgp_mobile::encrypt;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, GeneratedKey, KeyProfile};
use pgp_mobile::signature_details::{DetailedSignatureStatus, SignatureVerificationState};
use pgp_mobile::{streaming, verify};
use sequoia_openpgp as openpgp;
use tempfile::NamedTempFile;

fn generate_key(name: &str, profile: KeyProfile, expiry_seconds: Option<u64>) -> GeneratedKey {
    keys::generate_key_with_profile(name.to_string(), None, expiry_seconds, profile)
        .expect("key generation should succeed")
}

fn extract_signing_keypair(cert_data: &[u8]) -> openpgp::crypto::KeyPair {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(cert_data).expect("signer cert should parse");
    cert.keys()
        .with_policy(&policy, None)
        .supported()
        .secret()
        .for_signing()
        .next()
        .expect("signing key should exist")
        .key()
        .clone()
        .into_keypair()
        .expect("keypair extraction should succeed")
}

fn sign_cleartext_multi(text: &[u8], signer_certs: &[&[u8]]) -> Vec<u8> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let first = extract_signing_keypair(signer_certs[0]);
    let mut signer = Signer::with_template(
        message,
        first,
        openpgp::packet::signature::SignatureBuilder::new(SignatureType::Text),
    )
    .expect("cleartext signer should initialize");
    for cert in signer_certs.iter().skip(1) {
        signer = signer
            .add_signer(extract_signing_keypair(cert))
            .expect("additional signer should be added");
    }
    let mut signer = signer
        .cleartext()
        .build()
        .expect("cleartext signer should build");
    signer
        .write_all(text)
        .expect("cleartext signer should accept plaintext");
    signer.finalize().expect("cleartext signer should finalize");
    sink
}

fn sign_detached_multi(data: &[u8], signer_certs: &[&[u8]]) -> Vec<u8> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Signature)
        .build()
        .expect("armorer should build");
    let first = extract_signing_keypair(signer_certs[0]);
    let mut signer = Signer::new(message, first).expect("detached signer should initialize");
    for cert in signer_certs.iter().skip(1) {
        signer = signer
            .add_signer(extract_signing_keypair(cert))
            .expect("additional signer should be added");
    }
    let mut signer = signer
        .detached()
        .build()
        .expect("detached signer should build");
    signer
        .write_all(data)
        .expect("detached signer should accept data");
    signer.finalize().expect("detached signer should finalize");
    sink
}

fn encrypt_multi_signed(
    plaintext: &[u8],
    recipient_cert_data: &[u8],
    signer_certs: &[&[u8]],
) -> Vec<u8> {
    let policy = StandardPolicy::new();
    let recipient_cert =
        openpgp::Cert::from_bytes(recipient_cert_data).expect("recipient cert should parse");
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let recipients = recipient_cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .for_transport_encryption();
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .expect("encryptor should build");
    let first = extract_signing_keypair(signer_certs[0]);
    let mut signer = Signer::new(message, first).expect("message signer should initialize");
    for cert in signer_certs.iter().skip(1) {
        signer = signer
            .add_signer(extract_signing_keypair(cert))
            .expect("additional signer should be added");
    }
    let message = signer.build().expect("message signer should build");
    let mut literal = LiteralWriter::new(message)
        .build()
        .expect("literal writer should build");
    literal
        .write_all(plaintext)
        .expect("literal writer should accept plaintext");
    literal.finalize().expect("literal writer should finalize");
    sink
}

#[test]
fn test_verify_cleartext_detailed_multi_signature_all_valid() {
    let signer_a = generate_key("Signer A", KeyProfile::Universal, None);
    let signer_b = generate_key("Signer B", KeyProfile::Universal, None);
    let signed = sign_cleartext_multi(
        b"cleartext detailed",
        &[&signer_a.cert_data, &signer_b.cert_data],
    );

    let detailed = verify::verify_cleartext_detailed(
        &signed,
        &[
            signer_a.public_key_data.clone(),
            signer_b.public_key_data.clone(),
        ],
    )
    .expect("detailed verification should succeed");
    let legacy = verify::verify_cleartext(
        &signed,
        &[
            signer_a.public_key_data.clone(),
            signer_b.public_key_data.clone(),
        ],
    )
    .expect("legacy verification should succeed");

    assert_eq!(detailed.legacy_status, legacy.status);
    assert_eq!(detailed.summary_state, SignatureVerificationState::Verified);
    assert_eq!(detailed.summary_entry_index, Some(0));
    assert_eq!(
        detailed.legacy_signer_fingerprint,
        legacy.signer_fingerprint
    );
    assert_eq!(
        detailed.content.as_deref(),
        Some(&b"cleartext detailed"[..])
    );
    assert_eq!(detailed.signatures.len(), 2);
    assert!(detailed
        .signatures
        .iter()
        .all(|entry| entry.status == DetailedSignatureStatus::Valid));
    assert!(detailed
        .signatures
        .iter()
        .all(|entry| entry.state == SignatureVerificationState::Verified));
    let observed_fingerprints: Vec<String> = detailed
        .signatures
        .iter()
        .map(|entry| {
            entry
                .signer_primary_fingerprint
                .clone()
                .expect("valid entry should have fp")
        })
        .collect();
    assert!(observed_fingerprints.contains(&signer_a.fingerprint));
    assert!(observed_fingerprints.contains(&signer_b.fingerprint));
    assert_eq!(
        detailed.signatures[0].signer_primary_fingerprint,
        detailed.legacy_signer_fingerprint
    );
}

#[test]
fn test_verify_cleartext_detailed_expired_signer_matches_legacy_and_preserves_entries() {
    let signer = generate_key("Expiring Signer", KeyProfile::Universal, Some(1));
    let signed = sign_cleartext_multi(b"expired cleartext", &[&signer.cert_data]);
    std::thread::sleep(Duration::from_secs(2));

    let detailed = verify::verify_cleartext_detailed(&signed, &[signer.public_key_data.clone()])
        .expect("expired detailed verification should still grade");
    let legacy = verify::verify_cleartext(&signed, &[signer.public_key_data])
        .expect("expired legacy verification should still grade");

    assert_eq!(detailed.legacy_status, SignatureStatus::Expired);
    assert_eq!(detailed.summary_state, SignatureVerificationState::Expired);
    assert_eq!(
        detailed.legacy_signer_fingerprint,
        legacy.signer_fingerprint
    );
    assert!(!detailed.signatures.is_empty());
    assert!(detailed
        .signatures
        .iter()
        .all(|entry| entry.status == DetailedSignatureStatus::Expired));
}

#[test]
fn test_verify_detached_detailed_repeated_signer_preserves_repeated_entries() {
    let signer = generate_key("Repeated Signer", KeyProfile::Universal, None);
    let data = b"repeated signer detached";
    let signature = sign_detached_multi(data, &[&signer.cert_data, &signer.cert_data]);

    let detailed = verify::verify_detached_detailed(data, &signature, &[signer.public_key_data])
        .expect("detailed detached verification should succeed");

    assert_eq!(detailed.legacy_status, SignatureStatus::Valid);
    assert_eq!(detailed.summary_state, SignatureVerificationState::Verified);
    assert_eq!(detailed.signatures.len(), 2);
    assert_eq!(
        detailed.signatures[0].status,
        DetailedSignatureStatus::Valid
    );
    assert_eq!(
        detailed.signatures[1].status,
        DetailedSignatureStatus::Valid
    );
    assert_eq!(
        detailed.signatures[0].signer_primary_fingerprint,
        Some(signer.fingerprint.clone())
    );
    assert_eq!(
        detailed.signatures[1].signer_primary_fingerprint,
        Some(signer.fingerprint)
    );
}

#[test]
fn test_verify_detached_detailed_known_plus_unknown_preserves_unknown_nil_fingerprint() {
    let signer_a = generate_key("Signer A", KeyProfile::Universal, None);
    let signer_b = generate_key("Signer B", KeyProfile::Universal, None);
    let data = b"known plus unknown";
    let signature = sign_detached_multi(data, &[&signer_a.cert_data, &signer_b.cert_data]);

    let detailed = verify::verify_detached_detailed(data, &signature, &[signer_a.public_key_data])
        .expect("detailed detached verification should succeed");

    assert_eq!(detailed.legacy_status, SignatureStatus::Valid);
    assert_eq!(detailed.summary_state, SignatureVerificationState::Verified);
    assert_eq!(detailed.signatures.len(), 2);
    assert!(detailed
        .signatures
        .iter()
        .any(|entry| entry.status == DetailedSignatureStatus::Valid
            && entry.signer_primary_fingerprint == Some(signer_a.fingerprint.clone())));
    assert!(detailed.signatures.iter().any(|entry| entry.status
        == DetailedSignatureStatus::UnknownSigner
        && entry.signer_primary_fingerprint.is_none()
        && entry.state == SignatureVerificationState::SignerCertificateUnavailable));
}

#[test]
fn test_verify_detached_detailed_tampered_data_matches_legacy_bad() {
    let signer = generate_key("Signer", KeyProfile::Universal, None);
    let data = b"detached tamper";
    let signature = sign_detached_multi(data, &[&signer.cert_data]);

    let mut tampered = data.to_vec();
    tampered[0] ^= 0x01;

    let detailed =
        verify::verify_detached_detailed(&tampered, &signature, &[signer.public_key_data.clone()])
            .expect("tampered detailed verification should grade");
    let legacy = verify::verify_detached(&tampered, &signature, &[signer.public_key_data])
        .expect("tampered legacy verification should grade");

    assert_eq!(detailed.legacy_status, SignatureStatus::Bad);
    assert_eq!(detailed.summary_state, SignatureVerificationState::Invalid);
    assert_eq!(detailed.legacy_status, legacy.status);
    assert_eq!(
        detailed.legacy_signer_fingerprint,
        legacy.signer_fingerprint
    );
}

#[test]
fn test_verify_detached_file_detailed_matches_in_memory_and_legacy_fields() {
    let signer_a = generate_key("Signer A", KeyProfile::Universal, None);
    let signer_b = generate_key("Signer B", KeyProfile::Universal, None);
    let data = b"detached file detailed";
    let signature = sign_detached_multi(data, &[&signer_a.cert_data, &signer_b.cert_data]);
    let input = NamedTempFile::new().expect("temp input should be created");
    std::fs::write(input.path(), data).expect("input file should be written");

    let file_detailed = streaming::verify_detached_file_detailed(
        input.path().to_str().unwrap(),
        &signature,
        &[signer_a.public_key_data.clone()],
        None,
    )
    .expect("file detailed verification should succeed");
    let in_memory_detailed =
        verify::verify_detached_detailed(data, &signature, &[signer_a.public_key_data.clone()])
            .expect("in-memory detailed verification should succeed");
    let legacy = streaming::verify_detached_file(
        input.path().to_str().unwrap(),
        &signature,
        &[signer_a.public_key_data],
        None,
    )
    .expect("legacy file verification should succeed");

    assert_eq!(
        file_detailed.legacy_status,
        in_memory_detailed.legacy_status
    );
    assert_eq!(
        file_detailed.summary_state,
        in_memory_detailed.summary_state
    );
    assert_eq!(
        file_detailed.summary_entry_index,
        in_memory_detailed.summary_entry_index
    );
    assert_eq!(
        file_detailed.legacy_signer_fingerprint,
        in_memory_detailed.legacy_signer_fingerprint
    );
    assert_eq!(file_detailed.signatures, in_memory_detailed.signatures);
    assert_eq!(file_detailed.legacy_status, legacy.status);
    assert_eq!(
        file_detailed.legacy_signer_fingerprint,
        legacy.signer_fingerprint
    );
    assert_eq!(file_detailed.signatures.len(), 2);
    assert!(file_detailed.signatures.iter().any(|entry| {
        entry.status == DetailedSignatureStatus::UnknownSigner
            && entry.signer_primary_fingerprint.is_none()
            && entry.state == SignatureVerificationState::SignerCertificateUnavailable
    }));
}

#[test]
fn test_verify_detached_file_detailed_tampered_data_matches_in_memory_bad() {
    let signer = generate_key("Signer", KeyProfile::Universal, None);
    let data = b"tampered detached file";
    let signature = sign_detached_multi(data, &[&signer.cert_data]);
    let input = NamedTempFile::new().expect("temp input should be created");
    let mut tampered = data.to_vec();
    tampered[0] ^= 0x01;
    std::fs::write(input.path(), &tampered).expect("tampered file should be written");

    let file_detailed = streaming::verify_detached_file_detailed(
        input.path().to_str().unwrap(),
        &signature,
        &[signer.public_key_data.clone()],
        None,
    )
    .expect("file detailed verification should grade");
    let in_memory_detailed =
        verify::verify_detached_detailed(&tampered, &signature, &[signer.public_key_data.clone()])
            .expect("in-memory detailed verification should grade");
    let legacy = streaming::verify_detached_file(
        input.path().to_str().unwrap(),
        &signature,
        &[signer.public_key_data],
        None,
    )
    .expect("legacy file verification should grade");

    assert_eq!(file_detailed.legacy_status, SignatureStatus::Bad);
    assert_eq!(
        file_detailed.summary_state,
        SignatureVerificationState::Invalid
    );
    assert_eq!(
        file_detailed.legacy_status,
        in_memory_detailed.legacy_status
    );
    assert_eq!(
        file_detailed.legacy_signer_fingerprint,
        in_memory_detailed.legacy_signer_fingerprint
    );
    assert_eq!(file_detailed.signatures, in_memory_detailed.signatures);
    assert_eq!(file_detailed.legacy_status, legacy.status);
    assert_eq!(
        file_detailed.legacy_signer_fingerprint,
        legacy.signer_fingerprint
    );
}

#[test]
fn test_decrypt_detailed_multi_signature_matches_legacy_and_preserves_entries() {
    let signer_a = generate_key("Signer A", KeyProfile::Universal, None);
    let signer_b = generate_key("Signer B", KeyProfile::Universal, None);
    let recipient = generate_key("Recipient", KeyProfile::Universal, None);
    let plaintext = b"decrypt detailed multi-sig";
    let ciphertext = encrypt_multi_signed(
        plaintext,
        &recipient.public_key_data,
        &[&signer_a.cert_data, &signer_b.cert_data],
    );

    let detailed = decrypt::decrypt_detailed(
        &ciphertext,
        &[recipient.cert_data.clone()],
        &[
            signer_a.public_key_data.clone(),
            signer_b.public_key_data.clone(),
        ],
    )
    .expect("detailed decrypt should succeed");
    let legacy = decrypt::decrypt(
        &ciphertext,
        &[recipient.cert_data],
        &[signer_a.public_key_data, signer_b.public_key_data],
    )
    .expect("legacy decrypt should succeed");

    assert_eq!(detailed.legacy_status, legacy.signature_status.unwrap());
    assert_eq!(detailed.summary_state, SignatureVerificationState::Verified);
    assert_eq!(
        detailed.legacy_signer_fingerprint,
        legacy.signer_fingerprint
    );
    assert_eq!(detailed.plaintext, plaintext);
    assert_eq!(detailed.signatures.len(), 2);
    assert_eq!(
        detailed.signatures[0].status,
        DetailedSignatureStatus::Valid
    );
    assert_eq!(
        detailed.signatures[1].status,
        DetailedSignatureStatus::Valid
    );
}

#[test]
fn test_decrypt_detailed_unsigned_returns_empty_signatures_and_not_signed() {
    let recipient = generate_key("Recipient", KeyProfile::Universal, None);
    let ciphertext = encrypt::encrypt_binary(
        b"unsigned decrypt detailed",
        &[recipient.public_key_data.clone()],
        None,
        None,
    )
    .expect("unsigned encryption should succeed");

    let detailed = decrypt::decrypt_detailed(&ciphertext, &[recipient.cert_data], &[])
        .expect("unsigned detailed decrypt should succeed");

    assert_eq!(detailed.legacy_status, SignatureStatus::NotSigned);
    assert_eq!(
        detailed.summary_state,
        SignatureVerificationState::NotSigned
    );
    assert_eq!(detailed.summary_entry_index, None);
    assert!(detailed.signatures.is_empty());
}

#[test]
fn test_decrypt_file_detailed_unsigned_returns_empty_signatures_and_not_signed() {
    let recipient = generate_key("Recipient", KeyProfile::Universal, None);
    let input = NamedTempFile::new().expect("temp input should be created");
    let output = NamedTempFile::new().expect("temp output should be created");
    std::fs::write(input.path(), b"unsigned file detailed").expect("plaintext should be written");
    std::fs::remove_file(output.path()).expect("output placeholder should be removed");

    streaming::encrypt_file(
        input.path().to_str().unwrap(),
        output.path().to_str().unwrap(),
        &[recipient.public_key_data.clone()],
        None,
        None,
        None,
    )
    .expect("file encryption should succeed");

    let decrypted_output = NamedTempFile::new().expect("temp decrypted output should be created");
    std::fs::remove_file(decrypted_output.path()).expect("decrypted placeholder should be removed");

    let detailed = streaming::decrypt_file_detailed(
        output.path().to_str().unwrap(),
        decrypted_output.path().to_str().unwrap(),
        &[recipient.cert_data],
        &[],
        None,
    )
    .expect("file detailed decrypt should succeed");

    assert_eq!(detailed.legacy_status, SignatureStatus::NotSigned);
    assert_eq!(
        detailed.summary_state,
        SignatureVerificationState::NotSigned
    );
    assert_eq!(detailed.summary_entry_index, None);
    assert!(detailed.signatures.is_empty());
}

struct CancelImmediately;

impl streaming::ProgressReporter for CancelImmediately {
    fn on_progress(&self, _bytes_processed: u64, _total_bytes: u64) -> bool {
        false
    }
}

#[test]
fn test_verify_detached_file_detailed_cancel_returns_operation_cancelled() {
    let signer = generate_key("Signer", KeyProfile::Universal, None);
    let input = NamedTempFile::new().expect("temp input should be created");
    std::fs::write(input.path(), vec![0x42; 256 * 1024]).expect("input file should be written");
    let signature = sign_detached_multi(
        &std::fs::read(input.path()).expect("input file should be readable"),
        &[&signer.cert_data],
    );

    let result = streaming::verify_detached_file_detailed(
        input.path().to_str().unwrap(),
        &signature,
        &[signer.public_key_data],
        Some(Arc::new(CancelImmediately)),
    );

    match result {
        Err(PgpError::OperationCancelled) => {}
        other => panic!("expected OperationCancelled, got {other:?}"),
    }
}
