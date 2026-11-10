//! Rules E1, E2 and E7: what a failed decryption returns, and that expiry and
//! revocation do not stop a decryption.

mod common;

use std::time::SystemTime;

use common::keys::{self, PLAINTEXT};
use common::messages;
use cypher_engine::{EngineError, KeyShape, PrivateKey, decrypt, encrypt};

fn flip(message: &[u8], position: usize) -> Vec<u8> {
    let mut tampered = message.to_vec();
    tampered[position] ^= 0x01;
    tampered
}

/// E1. A message larger than Sequoia's setup buffer, tampered at its end, in
/// both containers: Sequoia alone would have released the plaintext before
/// the end; the engine returns only the error.
#[test]
fn e1_no_plaintext_when_authentication_fails() {
    let large = vec![0x42u8; 1024 * 1024];
    for shape in [KeyShape::V4Curve25519, KeyShape::V6Curve25519] {
        let alice = keys::new_key(shape, "Alice");
        let message = encrypt(large.clone(), vec![alice.certificate.clone()], None).unwrap();
        let binary = messages::binary(&message.message);
        let tampered = flip(&binary, binary.len() - 8);
        assert_eq!(
            decrypt(tampered, keys::handle(&alice), vec![]).unwrap_err(),
            EngineError::Tampered,
            "{shape:?}"
        );
    }
}

/// E2. A tampered container is `Tampered`, in both containers, in the first
/// block and in a later one.
#[test]
fn e2_tampered_container_is_tampered() {
    for shape in [KeyShape::V4Curve25519, KeyShape::V6Curve25519] {
        let alice = keys::new_key(shape, "Alice");
        let text = vec![0x42u8; 64 * 1024];
        let message = encrypt(text, vec![alice.certificate.clone()], None).unwrap();
        let binary = messages::binary(&message.message);
        let container = messages::container_offset(&binary);
        let first_block = container + 48;
        let later_block = container + (binary.len() - container) * 3 / 4;
        for position in [first_block, later_block] {
            assert_eq!(
                decrypt(flip(&binary, position), keys::handle(&alice), vec![]).unwrap_err(),
                EngineError::Tampered,
                "{shape:?} at {position}"
            );
        }
    }
}

/// E2. A recipient packet that names the key and does not unwrap is
/// `Tampered`.
#[test]
fn e2_named_recipient_packet_that_does_not_unwrap_is_tampered() {
    for shape in [
        KeyShape::V4Curve25519,
        KeyShape::V6Curve25519,
        KeyShape::V6MlDsa65,
    ] {
        let alice = keys::new_key(shape, "Alice");
        let message = encrypt(PLAINTEXT.to_vec(), vec![alice.certificate.clone()], None).unwrap();
        let binary = messages::binary(&message.message);
        // The last bytes of the only session-key packet: the wrapped key.
        let wrapped_key = messages::container_offset(&binary) - 4;
        assert_eq!(
            decrypt(flip(&binary, wrapped_key), keys::handle(&alice), vec![]).unwrap_err(),
            EngineError::Tampered,
            "{shape:?}"
        );
    }
}

/// E2. A message for someone else is `NoMatchingKey`, whether its recipient
/// packet names that key or hides it. A hidden packet for the key decrypts.
#[test]
fn e2_message_for_someone_else_is_no_matching_key() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let bob = keys::new_key(KeyShape::V6Curve25519, "Bob");
    let to_bob = encrypt(PLAINTEXT.to_vec(), vec![bob.certificate.clone()], None).unwrap();
    assert_eq!(
        decrypt(to_bob.message, keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::NoMatchingKey
    );

    let literal = messages::literal(PLAINTEXT);
    let bob_cert = sequoia_cert(&bob);
    let hidden_to_bob = messages::encrypted_raw(&[&bob_cert], &literal, SystemTime::now(), true);
    assert_eq!(
        decrypt(hidden_to_bob.clone(), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::NoMatchingKey
    );
    let decrypted = decrypt(hidden_to_bob, keys::handle(&bob), vec![]).unwrap();
    assert_eq!(decrypted.plaintext, PLAINTEXT);
}

/// E2. Input that does not parse is `Malformed`; OpenPGP that is not an
/// encrypted message is `WrongKind`.
#[test]
fn e2_input_that_is_not_an_encrypted_message() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    assert_eq!(
        decrypt(b"not a message".to_vec(), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::Malformed
    );
    assert_eq!(
        decrypt(Vec::new(), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::Malformed
    );
    assert_eq!(
        decrypt(alice.certificate.clone(), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::WrongKind
    );
}

/// E7. A revoked key and an expired key still decrypt.
#[test]
fn e7_expired_or_revoked_key_still_decrypts() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let message = encrypt(PLAINTEXT.to_vec(), vec![alice.certificate.clone()], None).unwrap();
    let revoked =
        PrivateKey::portable(keys::revoked(&alice), alice.secret.clone().unwrap()).unwrap();
    assert_eq!(
        decrypt(message.message, revoked, vec![]).unwrap().plaintext,
        PLAINTEXT
    );

    let expired = keys::expired_cert("Erin");
    let (created, _) = keys::expired_window();
    let while_valid = created + std::time::Duration::from_secs(60 * 60);
    let message = messages::encrypted_raw(
        &[&expired],
        &messages::literal(PLAINTEXT),
        while_valid,
        false,
    );
    let decrypted = decrypt(message, keys::handle_of(&expired), vec![]).unwrap();
    assert_eq!(decrypted.plaintext, PLAINTEXT);
}

fn sequoia_cert(key: &cypher_engine::NewKey) -> sequoia_openpgp::Cert {
    use sequoia_openpgp::parse::Parse;
    sequoia_openpgp::Cert::from_bytes(&key.certificate).unwrap()
}
