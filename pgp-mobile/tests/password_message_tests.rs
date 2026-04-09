//! Password / SKESK message tests.

mod common;

use std::io::Write;

use common::detect_message_format;
use openpgp::crypto::{Password, S2K};
use openpgp::packet::{SEIP, SKESK};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::{AEADAlgorithm, HashAlgorithm, SymmetricAlgorithm};
use pgp_mobile::decrypt::SignatureStatus;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::password::{self, PasswordDecryptStatus, PasswordMessageFormat};
use sequoia_openpgp as openpgp;

fn gen_key(name: &str, profile: KeyProfile) -> keys::GeneratedKey {
    keys::generate_key_with_profile(name.to_string(), None, None, profile)
        .expect("key generation should succeed")
}

fn dearmor_message(data: &[u8]) -> Vec<u8> {
    pgp_mobile::armor::decode_armor(data)
        .expect("message should dearmor cleanly")
        .0
}

fn top_level_packets(ciphertext: &[u8]) -> Vec<openpgp::Packet> {
    openpgp::PacketPile::from_bytes(ciphertext)
        .expect("ciphertext should parse")
        .into_children()
        .collect()
}

fn assert_default_s2k(s2k: &S2K) {
    match s2k {
        S2K::Iterated {
            hash,
            hash_bytes,
            ..
        } => {
            assert_eq!(*hash, HashAlgorithm::SHA256);
            assert_eq!(*hash_bytes, 0x3e00000);
        }
        other => panic!("expected iterated+salted S2K::default(), got {other:?}"),
    }
}

fn encrypt_mixed_message(
    plaintext: &[u8],
    password: &Password,
    recipient_cert: &[u8],
) -> Vec<u8> {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(recipient_cert).expect("recipient cert should parse");
    let recipients = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .for_transport_encryption();

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::with_passwords(message, std::iter::once(password.clone()))
        .add_recipients(recipients)
        .symmetric_algo(SymmetricAlgorithm::AES256)
        .build()
        .expect("mixed encryptor should build");
    let mut literal = LiteralWriter::new(message)
        .build()
        .expect("literal writer should build");
    literal.write_all(plaintext).expect("write should succeed");
    literal.finalize().expect("finalize should succeed");

    sink
}

fn mutate_skesk4_symmetric_algo(ciphertext: &[u8], algo: SymmetricAlgorithm) -> Vec<u8> {
    let mut pile = openpgp::PacketPile::from_bytes(ciphertext).expect("ciphertext should parse");
    match pile.path_ref_mut(&[0]) {
        Some(openpgp::Packet::SKESK(SKESK::V4(skesk))) => {
            skesk.set_symmetric_algo(algo);
        }
        other => panic!("expected first packet to be SKESK4, got {other:?}"),
    }

    let mut serialized = Vec::new();
    pile.serialize(&mut serialized)
        .expect("mutated pile should serialize");
    serialized
}

fn mutate_seip2_aead_algo(ciphertext: &[u8], algo: AEADAlgorithm) -> Vec<u8> {
    let mut pile = openpgp::PacketPile::from_bytes(ciphertext).expect("ciphertext should parse");
    match pile.path_ref_mut(&[1]) {
        Some(openpgp::Packet::SEIP(SEIP::V2(seip))) => {
            seip.set_aead(algo);
        }
        other => panic!("expected second packet to be SEIP2, got {other:?}"),
    }

    let mut serialized = Vec::new();
    pile.serialize(&mut serialized)
        .expect("mutated pile should serialize");
    serialized
}

fn find_auth_failure_tamper(ciphertext: &[u8], password: &Password) -> Vec<u8> {
    let len = ciphertext.len();
    for pos in (0..len).rev() {
        let mut tampered = ciphertext.to_vec();
        tampered[pos] ^= 0x01;

        let result = password::decrypt(&tampered, password, &[]);
        if matches!(
            result,
            Err(PgpError::AeadAuthenticationFailed) | Err(PgpError::IntegrityCheckFailed)
        ) {
            return tampered;
        }
    }

    panic!("could not locate a deterministic auth/integrity tamper position");
}

#[test]
fn test_password_encrypt_decrypt_armored_seipdv1_round_trip_unsigned() {
    let password: Password = "correct horse battery staple".into();
    let plaintext = b"Password message using SEIPDv1.";

    let ciphertext = password::encrypt(plaintext, &password, PasswordMessageFormat::Seipdv1, None)
        .expect("password encryption should succeed");
    let binary = dearmor_message(&ciphertext);
    let (has_v1, has_v2) = detect_message_format(&binary);
    assert!(has_v1);
    assert!(!has_v2);

    let result = password::decrypt(&ciphertext, &password, &[])
        .expect("password decryption should succeed");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
    assert_eq!(result.signature_status, Some(SignatureStatus::NotSigned));
}

#[test]
fn test_password_encrypt_decrypt_armored_seipdv2_round_trip_signed() {
    let password: Password = "advanced password".into();
    let signer = gen_key("Password Signer B", KeyProfile::Advanced);
    let plaintext = b"Password message using SEIPDv2 and a v6 signature.";

    let ciphertext = password::encrypt(
        plaintext,
        &password,
        PasswordMessageFormat::Seipdv2,
        Some(&signer.cert_data),
    )
    .expect("password encryption should succeed");
    let binary = dearmor_message(&ciphertext);
    let (has_v1, has_v2) = detect_message_format(&binary);
    assert!(!has_v1);
    assert!(has_v2);

    let result = password::decrypt(&ciphertext, &password, &[signer.public_key_data.clone()])
        .expect("password decryption should succeed");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
    assert_eq!(result.signer_fingerprint, Some(signer.fingerprint));
}

#[test]
fn test_password_encrypt_decrypt_binary_seipdv1_round_trip_signed() {
    let password: Password = "binary-seipdv1".into();
    let signer = gen_key("Password Signer A", KeyProfile::Universal);
    let plaintext = b"Binary password message using SEIPDv1.";

    let ciphertext = password::encrypt_binary(
        plaintext,
        &password,
        PasswordMessageFormat::Seipdv1,
        Some(&signer.cert_data),
    )
    .expect("password encryption should succeed");

    let result = password::decrypt(&ciphertext, &password, &[signer.public_key_data.clone()])
        .expect("password decryption should succeed");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
    assert_eq!(result.signature_status, Some(SignatureStatus::Valid));
    assert_eq!(result.signer_fingerprint, Some(signer.fingerprint));
}

#[test]
fn test_password_encrypt_decrypt_binary_seipdv2_round_trip_unsigned() {
    let password: Password = "binary-seipdv2".into();
    let plaintext = b"Binary password message using SEIPDv2.";

    let ciphertext =
        password::encrypt_binary(plaintext, &password, PasswordMessageFormat::Seipdv2, None)
            .expect("password encryption should succeed");

    let result = password::decrypt(&ciphertext, &password, &[])
        .expect("password decryption should succeed");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
    assert_eq!(result.signature_status, Some(SignatureStatus::NotSigned));
}

#[test]
fn test_password_encrypt_seipdv1_uses_aes256_and_default_s2k() {
    let password: Password = "seipdv1-packet-inspect".into();
    let ciphertext = password::encrypt_binary(
        b"inspect me",
        &password,
        PasswordMessageFormat::Seipdv1,
        None,
    )
    .expect("password encryption should succeed");

    let packets = top_level_packets(&ciphertext);
    match &packets[0] {
        openpgp::Packet::SKESK(SKESK::V4(skesk)) => {
            assert_eq!(skesk.symmetric_algo(), SymmetricAlgorithm::AES256);
            assert_default_s2k(skesk.s2k());
        }
        other => panic!("expected SKESK4 packet, got {other:?}"),
    }
    match &packets[1] {
        openpgp::Packet::SEIP(SEIP::V1(_)) => {}
        other => panic!("expected SEIPDv1 packet, got {other:?}"),
    }
}

#[test]
fn test_password_encrypt_seipdv2_uses_ocb_aes256_and_default_s2k() {
    let password: Password = "seipdv2-packet-inspect".into();
    let ciphertext = password::encrypt_binary(
        b"inspect me",
        &password,
        PasswordMessageFormat::Seipdv2,
        None,
    )
    .expect("password encryption should succeed");

    let packets = top_level_packets(&ciphertext);
    match &packets[0] {
        openpgp::Packet::SKESK(SKESK::V6(skesk)) => {
            assert_eq!(skesk.symmetric_algo(), SymmetricAlgorithm::AES256);
            assert_eq!(skesk.aead_algo(), AEADAlgorithm::OCB);
            assert_default_s2k(skesk.s2k());
        }
        other => panic!("expected SKESK6 packet, got {other:?}"),
    }
    match &packets[1] {
        openpgp::Packet::SEIP(SEIP::V2(seip)) => {
            assert_eq!(seip.symmetric_algo(), SymmetricAlgorithm::AES256);
            assert_eq!(seip.aead(), AEADAlgorithm::OCB);
        }
        other => panic!("expected SEIPDv2 packet, got {other:?}"),
    }
}

#[test]
fn test_password_decrypt_no_skesk_returns_status() {
    let recipient = gen_key("Recipient", KeyProfile::Universal);
    let ciphertext = pgp_mobile::encrypt::encrypt_binary(
        b"recipient-only message",
        &[recipient.public_key_data.clone()],
        None,
        None,
    )
    .expect("recipient encryption should succeed");

    let result = password::decrypt(&ciphertext, &Password::from("password"), &[])
        .expect("password decrypt should return status");
    assert_eq!(result.status, PasswordDecryptStatus::NoSkesk);
    assert_eq!(result.plaintext, None);
}

#[test]
fn test_password_decrypt_password_rejected_is_deterministic_for_skesk6() {
    let ciphertext = password::encrypt_binary(
        b"reject me",
        &Password::from("correct-password"),
        PasswordMessageFormat::Seipdv2,
        None,
    )
    .expect("password encryption should succeed");

    let result = password::decrypt(&ciphertext, &Password::from("wrong-password"), &[])
        .expect("wrong password should return family-local status for SKESK6");
    assert_eq!(result.status, PasswordDecryptStatus::PasswordRejected);
    assert_eq!(result.plaintext, None);
}

#[test]
fn test_password_decrypt_mixed_pkesk_skesk_message_succeeds() {
    let password: Password = "mixed-message-password".into();
    let recipient = gen_key("Mixed Recipient", KeyProfile::Universal);
    let plaintext = b"mixed password + recipient message";

    let ciphertext = encrypt_mixed_message(plaintext, &password, &recipient.public_key_data);
    let result = password::decrypt(&ciphertext, &password, &[])
        .expect("password path should decrypt mixed message");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
}

#[test]
fn test_password_decrypt_tampered_seipdv1_tail_returns_integrity_error() {
    let password: Password = "tamper-v1".into();
    let ciphertext = password::encrypt_binary(
        b"tamper target v1",
        &password,
        PasswordMessageFormat::Seipdv1,
        None,
    )
    .expect("password encryption should succeed");

    let tampered = find_auth_failure_tamper(&ciphertext, &password);
    let result = password::decrypt(&tampered, &password, &[]);
    assert!(matches!(result, Err(PgpError::IntegrityCheckFailed)));
}

#[test]
fn test_password_decrypt_tampered_seipdv2_tail_returns_auth_or_integrity_error() {
    let password: Password = "tamper-v2".into();
    let ciphertext = password::encrypt_binary(
        b"tamper target v2",
        &password,
        PasswordMessageFormat::Seipdv2,
        None,
    )
    .expect("password encryption should succeed");

    let tampered = find_auth_failure_tamper(&ciphertext, &password);
    let result = password::decrypt(&tampered, &password, &[]);
    assert!(matches!(
        result,
        Err(PgpError::AeadAuthenticationFailed) | Err(PgpError::IntegrityCheckFailed)
    ));
}

#[test]
fn test_password_decrypt_malformed_input_returns_corrupt_data() {
    let result = password::decrypt(b"not a valid OpenPGP message", &Password::from("pw"), &[]);
    assert!(matches!(result, Err(PgpError::CorruptData { .. })));
}

#[test]
fn test_password_decrypt_seipdv1_unsupported_algorithm_returns_error() {
    let ciphertext = password::encrypt_binary(
        b"unsupported-v1",
        &Password::from("pw"),
        PasswordMessageFormat::Seipdv1,
        None,
    )
    .expect("password encryption should succeed");

    let mutated = mutate_skesk4_symmetric_algo(&ciphertext, SymmetricAlgorithm::Private(100));
    let result = password::decrypt(&mutated, &Password::from("pw"), &[]);
    assert!(matches!(result, Err(PgpError::UnsupportedAlgorithm { .. })));
}

#[test]
fn test_password_decrypt_seipdv2_unsupported_algorithm_returns_error() {
    let ciphertext = password::encrypt_binary(
        b"unsupported-v2",
        &Password::from("pw"),
        PasswordMessageFormat::Seipdv2,
        None,
    )
    .expect("password encryption should succeed");

    let mutated = mutate_seip2_aead_algo(&ciphertext, AEADAlgorithm::Private(100));
    let result = password::decrypt(&mutated, &Password::from("pw"), &[]);
    assert!(matches!(result, Err(PgpError::UnsupportedAlgorithm { .. })));
}
