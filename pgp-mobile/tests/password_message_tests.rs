//! Password / SKESK message tests.

mod common;

use std::io::Write;

use common::detect_message_format;
use openpgp::crypto::symmetric::BlockCipherMode;
use openpgp::crypto::symmetric::{Encryptor as SymmetricEncryptor, PaddingMode};
use openpgp::crypto::{Password, SessionKey, S2K};
use openpgp::packet::skesk::{SKESK4, SKESK6};
use openpgp::packet::{SEIP, SKESK};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::serialize::Serialize;
use openpgp::types::{AEADAlgorithm, HashAlgorithm, SymmetricAlgorithm};
use openssl::kdf::{hkdf, HkdfMode};
use openssl::md::Md;
use pgp_mobile::decrypt::SignatureStatus;
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeyProfile};
use pgp_mobile::password::{self, PasswordDecryptStatus, PasswordMessageFormat};
use pgp_mobile::signature_details::SignatureVerificationState;
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

fn serialize_packet_pile(pile: &openpgp::PacketPile) -> Vec<u8> {
    let mut serialized = Vec::new();
    pile.serialize(&mut serialized)
        .expect("mutated pile should serialize");
    serialized
}

fn assert_default_s2k(s2k: &S2K) {
    match s2k {
        S2K::Iterated {
            hash, hash_bytes, ..
        } => {
            assert_eq!(*hash, HashAlgorithm::SHA256);
            assert_eq!(*hash_bytes, 0x3e00000);
        }
        other => panic!("expected iterated+salted S2K::default(), got {other:?}"),
    }
}

fn encrypt_mixed_message(plaintext: &[u8], password: &Password, recipient_cert: &[u8]) -> Vec<u8> {
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

fn encrypt_message_with_passwords(
    plaintext: &[u8],
    passwords: &[Password],
    format: PasswordMessageFormat,
) -> Vec<u8> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let encryptor = Encryptor::with_passwords(message, passwords.iter().cloned())
        .symmetric_algo(SymmetricAlgorithm::AES256);
    let encryptor = match format {
        PasswordMessageFormat::Seipdv1 => encryptor,
        PasswordMessageFormat::Seipdv2 => encryptor.aead_algo(AEADAlgorithm::OCB),
    };
    let message = encryptor.build().expect("password encryptor should build");
    let mut literal = LiteralWriter::new(message)
        .build()
        .expect("literal writer should build");
    literal.write_all(plaintext).expect("write should succeed");
    literal.finalize().expect("finalize should succeed");

    sink
}

fn mutate_nth_skesk4_symmetric_algo(
    ciphertext: &[u8],
    skesk_index: usize,
    algo: SymmetricAlgorithm,
) -> Vec<u8> {
    let mut pile = openpgp::PacketPile::from_bytes(ciphertext).expect("ciphertext should parse");
    match pile.path_ref_mut(&[skesk_index]) {
        Some(openpgp::Packet::SKESK(SKESK::V4(skesk))) => {
            skesk.set_symmetric_algo(algo);
        }
        other => panic!("expected SKESK4 packet at index {skesk_index}, got {other:?}"),
    }

    serialize_packet_pile(&pile)
}

fn mutate_skesk4_symmetric_algo(ciphertext: &[u8], algo: SymmetricAlgorithm) -> Vec<u8> {
    mutate_nth_skesk4_symmetric_algo(ciphertext, 0, algo)
}

fn mutate_seip2_aead_algo(ciphertext: &[u8], algo: AEADAlgorithm) -> Vec<u8> {
    let mut pile = openpgp::PacketPile::from_bytes(ciphertext).expect("ciphertext should parse");
    match pile.path_ref_mut(&[1]) {
        Some(openpgp::Packet::SEIP(SEIP::V2(seip))) => {
            seip.set_aead(algo);
        }
        other => panic!("expected second packet to be SEIP2, got {other:?}"),
    }

    serialize_packet_pile(&pile)
}

fn rewrite_skesk4_esk_with_payload_algo(
    skesk: &mut SKESK4,
    password: &Password,
    payload_algo: SymmetricAlgorithm,
) {
    let (_, session_key) = skesk
        .decrypt(password)
        .expect("SKESK4 should decrypt with the known password");
    let esk_algo = skesk.symmetric_algo();
    let key = skesk
        .s2k()
        .derive_key(password, esk_algo.key_size().expect("supported esk algo"))
        .expect("S2K should derive key");

    let mut prefixed_session_key: SessionKey = vec![0; 1 + session_key.len()].into();
    prefixed_session_key[0] = payload_algo.into();
    prefixed_session_key[1..].copy_from_slice(&session_key);

    let mut esk = Vec::new();
    let mut encryptor = SymmetricEncryptor::new(
        esk_algo,
        BlockCipherMode::CFB,
        PaddingMode::None,
        &key,
        None,
        &mut esk,
    )
    .expect("CFB encryptor should build");
    encryptor
        .write_all(&prefixed_session_key)
        .expect("ESK write should succeed");
    encryptor.finalize().expect("ESK finalize should succeed");

    skesk.set_esk(Some(esk.into_boxed_slice()));
}

fn mutate_nth_skesk4_inner_payload_algo(
    ciphertext: &[u8],
    skesk_index: usize,
    password: &Password,
    payload_algo: SymmetricAlgorithm,
) -> Vec<u8> {
    let mut pile = openpgp::PacketPile::from_bytes(ciphertext).expect("ciphertext should parse");
    match pile.path_ref_mut(&[skesk_index]) {
        Some(openpgp::Packet::SKESK(SKESK::V4(skesk))) => {
            rewrite_skesk4_esk_with_payload_algo(skesk, password, payload_algo);
        }
        other => panic!("expected SKESK4 packet at index {skesk_index}, got {other:?}"),
    }

    serialize_packet_pile(&pile)
}

fn rewrite_skesk6_with_session_key(
    skesk: &mut SKESK6,
    payload_algo: SymmetricAlgorithm,
    password: &Password,
    session_key: &SessionKey,
) {
    assert_eq!(
        payload_algo.key_size().expect("supported payload algo"),
        session_key.len()
    );

    let esk_algo = skesk.symmetric_algo();
    let esk_aead = skesk.aead_algo();
    let s2k = skesk.s2k().clone();
    let ad = [0xc3, 6, esk_algo.into(), esk_aead.into()];
    let key = s2k
        .derive_key(password, esk_algo.key_size().expect("supported esk algo"))
        .expect("S2K should derive key");

    let mut kek: SessionKey = vec![0; esk_algo.key_size().expect("supported esk algo")].into();
    hkdf(
        Md::sha256(),
        key.as_ref(),
        None,
        Some(&ad),
        HkdfMode::ExtractAndExpand,
        None,
        kek.as_mut(),
    )
    .expect("HKDF should derive KEK");

    let iv = vec![0x5a; esk_aead.nonce_size().expect("supported AEAD algo")].into_boxed_slice();
    let mut context = esk_aead
        .context(esk_algo, &kek, &ad, &iv)
        .expect("AEAD context should build")
        .for_encryption()
        .expect("AEAD encryptor should build");
    let mut esk = vec![0u8; session_key.len() + esk_aead.digest_size().expect("digest size")];
    context
        .encrypt_seal(&mut esk, session_key)
        .expect("ESK sealing should succeed");

    *skesk = SKESK6::new(esk_algo, esk_aead, s2k, iv, esk.into_boxed_slice())
        .expect("mutated SKESK6 should build");
}

fn mutate_nth_skesk6_with_wrong_session_key(
    ciphertext: &[u8],
    skesk_index: usize,
    password: &Password,
) -> Vec<u8> {
    let payload_algo = match top_level_packets(ciphertext).last() {
        Some(openpgp::Packet::SEIP(SEIP::V2(seip))) => seip.symmetric_algo(),
        other => panic!("expected trailing SEIP2 packet, got {other:?}"),
    };

    let mut pile = openpgp::PacketPile::from_bytes(ciphertext).expect("ciphertext should parse");
    match pile.path_ref_mut(&[skesk_index]) {
        Some(openpgp::Packet::SKESK(SKESK::V6(skesk))) => {
            let session_key = skesk
                .decrypt(password)
                .expect("SKESK6 should decrypt with the known password");
            let mut wrong_session_key = session_key.clone();
            wrong_session_key[0] ^= 0x01;
            rewrite_skesk6_with_session_key(skesk, payload_algo, password, &wrong_session_key);
        }
        other => panic!("expected SKESK6 packet at index {skesk_index}, got {other:?}"),
    }

    serialize_packet_pile(&pile)
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

    let result =
        password::decrypt(&ciphertext, &password, &[]).expect("password decryption should succeed");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
    assert_eq!(result.signature_status, Some(SignatureStatus::NotSigned));
    assert_eq!(result.summary_state, SignatureVerificationState::NotSigned);
    assert!(result.signatures.is_empty());
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
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
    assert_eq!(result.summary_entry_index, Some(0));
    assert_eq!(result.signatures.len(), 1);
    assert_eq!(
        result.signatures[0].state,
        SignatureVerificationState::Verified
    );
}

#[test]
fn test_password_decrypt_signed_without_verification_cert_preserves_signer_evidence() {
    let password: Password = "password missing verification cert".into();
    let signer = gen_key("Password Missing Signer", KeyProfile::Universal);
    let plaintext = b"Password signed message without verification cert.";

    let ciphertext = password::encrypt_binary(
        plaintext,
        &password,
        PasswordMessageFormat::Seipdv1,
        Some(&signer.cert_data),
    )
    .expect("password encryption should succeed");

    let result =
        password::decrypt(&ciphertext, &password, &[]).expect("password decryption should succeed");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
    assert_eq!(
        result.signature_status,
        Some(SignatureStatus::UnknownSigner)
    );
    assert_eq!(
        result.summary_state,
        SignatureVerificationState::SignerCertificateUnavailable
    );
    assert_eq!(result.summary_entry_index, Some(0));
    assert_eq!(result.signatures.len(), 1);
    assert_eq!(
        result.signatures[0].state,
        SignatureVerificationState::SignerCertificateUnavailable
    );
    assert!(
        !result.signatures[0]
            .signer_evidence
            .issuer_fingerprints
            .is_empty()
            || !result.signatures[0]
                .signer_evidence
                .issuer_key_ids
                .is_empty()
    );
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
    assert_eq!(result.summary_state, SignatureVerificationState::Verified);
}

#[test]
fn test_password_encrypt_decrypt_binary_seipdv2_round_trip_unsigned() {
    let password: Password = "binary-seipdv2".into();
    let plaintext = b"Binary password message using SEIPDv2.";

    let ciphertext =
        password::encrypt_binary(plaintext, &password, PasswordMessageFormat::Seipdv2, None)
            .expect("password encryption should succeed");

    let result =
        password::decrypt(&ciphertext, &password, &[]).expect("password decryption should succeed");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
    assert_eq!(result.signature_status, Some(SignatureStatus::NotSigned));
    assert_eq!(result.summary_state, SignatureVerificationState::NotSigned);
    assert!(result.signatures.is_empty());
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
fn test_password_decrypt_multi_password_message_accepts_second_password() {
    let plaintext = b"multi password message";
    let passwords = vec![
        Password::from("first-password"),
        Password::from("second-password"),
    ];
    let ciphertext =
        encrypt_message_with_passwords(plaintext, &passwords, PasswordMessageFormat::Seipdv1);

    let packets = top_level_packets(&ciphertext);
    assert!(matches!(&packets[0], openpgp::Packet::SKESK(SKESK::V4(_))));
    assert!(matches!(&packets[1], openpgp::Packet::SKESK(SKESK::V4(_))));

    let result = password::decrypt(&ciphertext, &passwords[1], &[])
        .expect("second password should decrypt multi-password message");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
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
fn test_password_decrypt_multi_skesk4_inner_unsupported_algo_can_fall_through_to_later_candidate() {
    let shared_password = Password::from("shared-skesk4-password");
    let plaintext = b"skesk4 fallthrough message";
    let ciphertext = encrypt_message_with_passwords(
        plaintext,
        &[shared_password.clone(), shared_password.clone()],
        PasswordMessageFormat::Seipdv1,
    );
    let mutated = mutate_nth_skesk4_inner_payload_algo(
        &ciphertext,
        0,
        &shared_password,
        SymmetricAlgorithm::Private(100),
    );

    let result = password::decrypt(&mutated, &shared_password, &[])
        .expect("later SKESK4 candidate should still decrypt");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
}

#[test]
fn test_password_decrypt_multi_skesk6_auth_failure_can_fall_through_to_later_candidate() {
    let shared_password = Password::from("shared-skesk6-password");
    let plaintext = b"skesk6 fallthrough message";
    let ciphertext = encrypt_message_with_passwords(
        plaintext,
        &[shared_password.clone(), shared_password.clone()],
        PasswordMessageFormat::Seipdv2,
    );
    let mutated = mutate_nth_skesk6_with_wrong_session_key(&ciphertext, 0, &shared_password);

    let result = password::decrypt(&mutated, &shared_password, &[])
        .expect("later SKESK6 candidate should still decrypt");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
}

#[test]
fn test_password_decrypt_multi_skesk_outer_unsupported_algo_can_fall_through_to_later_candidate() {
    let shared_password = Password::from("shared-outer-unsupported-password");
    let plaintext = b"outer unsupported fallthrough";
    let ciphertext = encrypt_message_with_passwords(
        plaintext,
        &[shared_password.clone(), shared_password.clone()],
        PasswordMessageFormat::Seipdv1,
    );
    let mutated =
        mutate_nth_skesk4_symmetric_algo(&ciphertext, 0, SymmetricAlgorithm::Private(100));

    let result = password::decrypt(&mutated, &shared_password, &[])
        .expect("later SKESK candidate should still decrypt");
    assert_eq!(result.status, PasswordDecryptStatus::Decrypted);
    assert_eq!(result.plaintext.as_deref(), Some(&plaintext[..]));
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
fn test_password_decrypt_single_skesk4_inner_unsupported_algo_returns_error() {
    let password = Password::from("single-skesk4-password");
    let ciphertext = encrypt_message_with_passwords(
        b"single skesk4 inner unsupported",
        &[password.clone()],
        PasswordMessageFormat::Seipdv1,
    );
    let mutated = mutate_nth_skesk4_inner_payload_algo(
        &ciphertext,
        0,
        &password,
        SymmetricAlgorithm::Private(100),
    );

    let result = password::decrypt(&mutated, &password, &[]);
    assert!(matches!(result, Err(PgpError::UnsupportedAlgorithm { .. })));
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
