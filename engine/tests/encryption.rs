//! Rules E4, E5, E6 and E8: the outgoing format, the quantum-safe flag,
//! unusable recipients, and keys that may not sign.

mod common;

use common::keys::{self, PLAINTEXT};
use common::messages;
use cypher_engine::{EngineError, KeyShape, OutgoingFormat, decrypt, encrypt, outgoing_format};
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::types::{AEADAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;

fn tsk_cert(key: &cypher_engine::NewKey) -> Cert {
    Cert::from_bytes(&keys::tsk(key)).unwrap()
}

/// E4. Never compressed, always AES-256, and SEIPDv2 only if every recipient
/// supports it; `outgoing_format` says exactly what `encrypt` writes.
#[test]
fn e4_outgoing_message_format() {
    let legacy = keys::new_key(KeyShape::V4Curve25519, "Lea");
    let modern = keys::new_key(KeyShape::V6Curve25519, "Mo");
    let signer = keys::handle(&modern);

    let cases = [
        (
            vec![&modern],
            OutgoingFormat {
                modern: true,
                held_back_by: vec![],
            },
        ),
        (
            vec![&legacy],
            OutgoingFormat {
                modern: false,
                held_back_by: vec![0],
            },
        ),
        (
            vec![&modern, &legacy],
            OutgoingFormat {
                modern: false,
                held_back_by: vec![1],
            },
        ),
    ];
    for (recipients, expected) in cases {
        let certificates: Vec<Vec<u8>> = recipients
            .iter()
            .map(|key| key.certificate.clone())
            .collect();
        assert_eq!(outgoing_format(certificates.clone()).unwrap(), expected);

        let message = encrypt(PLAINTEXT, certificates, Some(signer.clone())).unwrap();
        let layers = messages::layers(
            &messages::binary(&message.message),
            &tsk_cert(recipients[0]),
        );
        assert_eq!(
            layers,
            messages::Layers {
                compressed: false,
                cipher: SymmetricAlgorithm::AES256,
                aead: expected.modern.then_some(AEADAlgorithm::OCB),
            },
            "{expected:?}"
        );
    }
}

/// E5. The flag is read from the message: only a message whose every
/// session-key packet is post-quantum is quantum-safe, on both sides.
#[test]
fn e5_quantum_safe_flag_comes_from_the_message() {
    let pq = keys::new_key(KeyShape::V6MlDsa65, "Quinn");
    let pq_high = keys::new_key(KeyShape::V6MlDsa87, "Quill");
    let classical = keys::new_key(KeyShape::V6Curve25519, "Cleo");

    let cases = [
        (vec![&pq], true),
        (vec![&pq_high, &pq], true),
        (vec![&pq, &classical], false),
        (vec![&classical], false),
    ];
    for (recipients, quantum_safe) in cases {
        let certificates = recipients
            .iter()
            .map(|key| key.certificate.clone())
            .collect();
        let message = encrypt(PLAINTEXT, certificates, None).unwrap();
        assert_eq!(message.quantum_safe, quantum_safe);
        let decrypted = decrypt(message.message, keys::handle(recipients[0]), vec![]).unwrap();
        assert_eq!(decrypted.quantum_safe, quantum_safe);
    }
}

/// E5. A message cut off is an error: before its container it is
/// `Malformed`, inside its container `Tampered`.
#[test]
fn e5_cut_off_message_is_an_error() {
    let pq = keys::new_key(KeyShape::V6MlDsa65, "Quinn");
    let message = encrypt(&vec![0x42; 16 * 1024], vec![pq.certificate.clone()], None).unwrap();
    let binary = messages::binary(&message.message);
    let container = messages::container_offset(&binary);

    let before_container = binary[..container].to_vec();
    assert_eq!(
        decrypt(before_container, keys::handle(&pq), vec![]).unwrap_err(),
        EngineError::Malformed
    );
    let inside_container = binary[..binary.len() - 64].to_vec();
    assert_eq!(
        decrypt(inside_container, keys::handle(&pq), vec![]).unwrap_err(),
        EngineError::Tampered
    );
}

/// E6. An expired or revoked recipient is refused with its position, by both
/// `encrypt` and `outgoing_format`.
#[test]
fn e6_expired_or_revoked_recipient_is_refused_by_position() {
    let valid = keys::new_key(KeyShape::V6Curve25519, "Val");
    let revoked = keys::revoked(&keys::new_key(KeyShape::V6Curve25519, "Rev"));
    let (expired, _) = keys::split(&keys::expired_cert("Erin"));

    for (recipients, position) in [
        (vec![valid.certificate.clone(), expired], 1),
        (vec![revoked, valid.certificate.clone()], 0),
    ] {
        let expected = EngineError::RecipientUnusable { position };
        assert_eq!(outgoing_format(recipients.clone()).unwrap_err(), expected);
        assert_eq!(encrypt(PLAINTEXT, recipients, None).unwrap_err(), expected);
    }
}

/// E8. An expired or revoked key does not sign.
#[test]
fn e8_expired_or_revoked_key_does_not_sign() {
    let bob = keys::new_key(KeyShape::V6Curve25519, "Bob");
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let revoked_alice = cypher_engine::PrivateKey::portable(
        keys::revoked(&alice),
        alice.secret.as_deref().unwrap(),
    )
    .unwrap();
    let expired = keys::handle_of(&keys::expired_cert("Erin"));

    assert_eq!(
        encrypt(
            PLAINTEXT,
            vec![bob.certificate.clone()],
            Some(revoked_alice)
        )
        .unwrap_err(),
        EngineError::KeyRevoked
    );
    assert_eq!(
        encrypt(PLAINTEXT, vec![bob.certificate.clone()], Some(expired)).unwrap_err(),
        EngineError::KeyExpired
    );
}

/// E5. A password packet beside a post-quantum packet for the key makes the
/// message not quantum-safe. A session-key packet of a version the engine does
/// not read is refused as `Unsupported`, so it cannot pass as quantum-safe; a
/// damaged one of a version it reads stays `Malformed`.
#[test]
fn e5_other_session_key_packets_make_the_flag_false() {
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
    use std::io::Write;

    let pq = keys::new_key(KeyShape::V6MlDsa65, "Quinn");
    let cert = Cert::from_bytes(&pq.certificate).unwrap();
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).unwrap();
    let mut with_password = Vec::new();
    let message = Encryptor::with_passwords(Message::new(&mut with_password), Some("password"))
        .add_recipients(valid.keys().for_transport_encryption())
        .build()
        .unwrap();
    let mut literal = LiteralWriter::new(message).build().unwrap();
    literal.write_all(PLAINTEXT).unwrap();
    literal.finalize().unwrap();
    let decrypted = decrypt(with_password, keys::handle(&pq), vec![]).unwrap();
    assert_eq!(
        (decrypted.plaintext.as_slice(), decrypted.quantum_safe),
        (PLAINTEXT, false)
    );

    let message = encrypt(PLAINTEXT, vec![pq.certificate.clone()], None).unwrap();
    let mut with_unknown_version = vec![0xC0 | 1, 40, 99];
    with_unknown_version.resize(2 + 40, 0);
    with_unknown_version.extend_from_slice(&messages::binary(&message.message));
    assert_eq!(
        decrypt(with_unknown_version, keys::handle(&pq), vec![]).unwrap_err(),
        EngineError::Unsupported
    );

    // Version 3 naming EdDSA, which cannot encrypt: Sequoia returns it unparsed.
    let mut damaged = vec![0xC0 | 1, 40, 3];
    damaged.extend_from_slice(&[0; 8]);
    damaged.push(22);
    damaged.resize(2 + 40, 0);
    damaged.extend_from_slice(&messages::binary(&message.message));
    assert_eq!(
        decrypt(damaged, keys::handle(&pq), vec![]).unwrap_err(),
        EngineError::Malformed
    );
}
