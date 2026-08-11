//! Proof that our consumption bounds hold on the walks that read received,
//! unauthenticated input — the walks that run when someone opens a message
//! sent to them.
//!
//! The messages built here are hostile fixtures, constructed so the guard can
//! be shown to fire: each terminates without a literal packet, which leaves the
//! output-side ceilings nothing to count, so anything that refuses them has to
//! do it on the consumption side and has to do it before the expansion rather
//! than after. They expand for real — the nested fixture carries an 8 MiB
//! padding packet under eight compression layers in a few hundred bytes of
//! input — so an engine that failed to bound itself would inflate them before
//! returning, or not return at all, and this suite would notice either way.

mod common;

use std::io::Write as _;

use openpgp::packet::{Padding, PKESK};
use openpgp::parse::Parse as _;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Compressor, Encryptor, LiteralWriter, Message, Recipient};
use openpgp::serialize::Marshal as _;
use openpgp::types::CompressionAlgorithm;
use sequoia_openpgp as openpgp;

use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, GeneratedKey, KeySuite};
use pgp_mobile::{decrypt, encrypt, password, streaming, verify};

/// A key generation cheap enough to run once per test.
fn test_key() -> GeneratedKey {
    keys::generate_key_with_suite(
        "Consumption".to_string(),
        None,
        None,
        KeySuite::Ed25519LegacyCurve25519Legacy,
    )
    .expect("key generation should succeed")
}

fn ciphertext_for(key: &GeneratedKey) -> Vec<u8> {
    encrypt::encrypt_binary(b"bounded", &[key.public_key_data.clone()], None, None)
        .expect("encryption should succeed")
}

/// The message's first PKESK packet, to reuse as a session-key packet in the
/// crafted inputs below.
fn session_key_packet(ciphertext: &[u8]) -> PKESK {
    openpgp::PacketPile::from_bytes(ciphertext)
        .expect("ciphertext should parse")
        .descendants()
        .find_map(|packet| match packet {
            openpgp::Packet::PKESK(pkesk) => Some(pkesk.clone()),
            _ => None,
        })
        .expect("ciphertext should carry a PKESK packet")
}

/// Wrap `write_payload`'s packets in `layers` nested compressed data packets,
/// with no literal packet anywhere.
fn compressed_layers<F>(layers: usize, write_payload: F) -> Vec<u8>
where
    F: FnOnce(&mut Message<'_>),
{
    let mut sink = Vec::new();
    {
        let mut message = Message::new(&mut sink);
        for _ in 0..layers {
            message = Compressor::new(message)
                .algo(CompressionAlgorithm::Zip)
                .build()
                .expect("compressor should build");
        }
        write_payload(&mut message);
        message.finalize().expect("message should finalize");
    }
    sink
}

/// Eight compression layers over a session-key packet and 8 MiB of padding:
/// nesting far past what any producer emits, and expanding tens of
/// thousandfold if a walk lets it. Built here so the tests below can show our
/// depth bound refusing it.
fn nested_layers_bomb(pkesk: &PKESK) -> Vec<u8> {
    compressed_layers(8, |message| {
        openpgp::Packet::from(pkesk.clone())
            .serialize(message)
            .expect("PKESK should serialize");
        openpgp::Packet::from(Padding::from(vec![0u8; 8 * 1024 * 1024]))
            .serialize(message)
            .expect("padding should serialize");
    })
}

/// One compression layer over a hundred thousand session-key packets, so the
/// packet bound can be shown to stop the walk that would otherwise collect
/// every one of them.
fn packet_flood_bomb(pkesk: &PKESK) -> Vec<u8> {
    compressed_layers(1, |message| {
        let packet = openpgp::Packet::from(pkesk.clone());
        for _ in 0..100_000 {
            packet.serialize(message).expect("PKESK should serialize");
        }
    })
}

/// One compression layer over a session-key packet and 8 MB of padding, split
/// into packets Sequoia will parse rather than reject on size: few packets,
/// shallow nesting, and expansion regardless, so the byte bound is the one
/// left to catch it.
fn padding_flood_bomb(pkesk: &PKESK) -> Vec<u8> {
    compressed_layers(1, |message| {
        openpgp::Packet::from(pkesk.clone())
            .serialize(message)
            .expect("PKESK should serialize");
        for _ in 0..8 {
            openpgp::Packet::from(Padding::from(vec![0u8; 1_000_000]))
                .serialize(message)
                .expect("padding should serialize");
        }
    })
}

fn write_temp_file(name: &str, contents: &[u8]) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write temp file");
    let path = path.to_str().expect("utf-8 path").to_string();
    (dir, path)
}

#[test]
fn nested_compressed_layers_do_not_expand_in_phase_one() {
    let key = test_key();
    let pkesk = session_key_packet(&ciphertext_for(&key));
    let bomb = nested_layers_bomb(&pkesk);
    assert!(
        bomb.len() < 64 * 1024,
        "the crafted input must stay small enough to be a bomb: {} bytes",
        bomb.len()
    );

    // Each phase-1 route refuses without descending far enough to inflate: the
    // walk stops at the second compression layer, so it never reaches the
    // session-key packet or the padding beneath it.
    assert!(matches!(
        decrypt::parse_recipients(&bomb),
        Err(PgpError::CorruptData { .. })
    ));
    assert!(matches!(
        decrypt::match_recipients(&bomb, &[key.public_key_data.clone()]),
        Err(PgpError::CorruptData { .. })
    ));
    assert!(matches!(
        decrypt::message_quantum_safety(&bomb),
        Err(PgpError::CorruptData { .. })
    ));
    assert!(matches!(
        password::decrypt(&bomb, &openpgp::crypto::Password::from("secret"), &[]),
        Err(PgpError::CorruptData { .. })
    ));

    let (_dir, path) = write_temp_file("nested.gpg", &bomb);
    assert!(matches!(
        streaming::match_recipients_from_file(&path, &[key.public_key_data.clone()]),
        Err(PgpError::CorruptData { .. })
    ));
}

#[test]
fn nested_compressed_layers_are_refused_before_the_decryptor_is_built() {
    let key = test_key();
    let pkesk = session_key_packet(&ciphertext_for(&key));
    let bomb = nested_layers_bomb(&pkesk);

    // Sequoia's own walk to the literal packet descends through compression, so
    // the bound has to fire from inside it. Without one, the walk inflates the
    // whole nest before reporting a malformed message.
    assert!(matches!(
        decrypt::decrypt_detailed(&bomb, &[key.cert_data.clone()], &[]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
    assert!(matches!(
        verify::verify_cleartext_detailed(&bomb, &[key.public_key_data.clone()]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));

    let (_dir, input) = write_temp_file("nested.gpg", &bomb);
    let (_out_dir, output) = write_temp_file("out.bin", b"");
    assert!(matches!(
        streaming::decrypt_file_detailed(&input, &output, &[key.cert_data.clone()], &[], None),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
}

#[test]
fn a_flood_of_session_key_packets_is_refused() {
    let key = test_key();
    let pkesk = session_key_packet(&ciphertext_for(&key));
    let bomb = packet_flood_bomb(&pkesk);

    assert!(matches!(
        decrypt::parse_recipients(&bomb),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
    assert!(matches!(
        decrypt::decrypt_detailed(&bomb, &[key.cert_data.clone()], &[]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
}

#[test]
fn packets_that_outweigh_their_message_are_refused_before_they_are_read() {
    let key = test_key();
    let pkesk = session_key_packet(&ciphertext_for(&key));
    let bomb = padding_flood_bomb(&pkesk);

    assert!(matches!(
        decrypt::parse_recipients(&bomb),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
    assert!(matches!(
        decrypt::decrypt_detailed(&bomb, &[key.cert_data.clone()], &[]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
}

#[test]
fn a_compressed_message_still_decrypts() {
    // The bounds must leave the deepest shape a producer emits alone: an
    // encryption container over a compression container, putting the literal
    // data two containers down.
    let key = test_key();
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(&key.public_key_data).expect("cert should parse");
    let recipients: Vec<Recipient> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(Into::into)
        .collect();

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .expect("encryptor should build");
        let message = Compressor::new(message)
            .algo(CompressionAlgorithm::Zip)
            .build()
            .expect("compressor should build");
        let mut message = LiteralWriter::new(message).build().expect("literal writer");
        message
            .write_all(b"compressed inside the encryption container")
            .expect("write plaintext");
        message.finalize().expect("finalize");
    }

    let result = decrypt::decrypt_detailed(&sink, &[key.cert_data.clone()], &[])
        .expect("a compressed message must still decrypt");
    assert_eq!(
        result.plaintext,
        b"compressed inside the encryption container".to_vec()
    );
}

#[test]
fn an_encrypted_message_inside_a_compressed_one_still_resolves() {
    // RFC 9580's grammar allows a compressed message to hold an encrypted one,
    // so the phase-1 walk descends one layer. That allowance is the reason the
    // depth bound is one rather than zero, and this is what it buys.
    let key = test_key();
    let ciphertext = ciphertext_for(&key);
    let wrapped = compressed_layers(1, |message| {
        message
            .write_all(&ciphertext)
            .expect("write nested ciphertext");
    });

    let recipients = decrypt::parse_recipients(&wrapped).expect("recipients should be found");
    assert_eq!(recipients.len(), 1);
    let matched = decrypt::match_recipients(&wrapped, &[key.public_key_data.clone()])
        .expect("the local certificate should match");
    assert_eq!(matched.len(), 1);

    let result = decrypt::decrypt_detailed(&wrapped, &[key.cert_data.clone()], &[])
        .expect("a compressed encrypted message must still decrypt");
    assert_eq!(result.plaintext, b"bounded".to_vec());
}
