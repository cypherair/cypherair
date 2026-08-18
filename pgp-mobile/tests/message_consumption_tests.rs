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
use openpgp::serialize::stream::{
    Compressor, Encryptor, LiteralWriter, Message, Recipient, Signer,
};
use openpgp::serialize::Marshal as _;
use openpgp::types::CompressionAlgorithm;
use sequoia_openpgp as openpgp;

use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, GeneratedKey, KeySuite, KeyValidity};
use pgp_mobile::{decrypt, encrypt, password, streaming, verify};

/// A key generation cheap enough to run once per test.
fn test_key() -> GeneratedKey {
    keys::generate_key_with_suite(
        "Consumption".to_string(),
        None,
        KeyValidity::Never,
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

/// The transport-encryption recipients of a certificate.
fn recipients_of<'a>(cert: &'a openpgp::Cert, policy: &'a StandardPolicy) -> Vec<Recipient<'a>> {
    cert.keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(Into::into)
        .collect()
}

/// A message that is entirely well-formed until after its literal data: a
/// 512 KiB payload followed by three thousand padding packets.
///
/// This is the fixture for the *other* channel. Every bomb above breaches its
/// bound while Sequoia is still building the decryptor, so the refusal comes
/// back from `with_policy`. Here the walk reaches the literal packet, the
/// decryptor is built, and the bound fires later — from the `Read` impl, which
/// wraps what it is handed and used to make the refusal unrecognizable. A
/// payload larger than the plaintext buffer is what keeps the trailing packets
/// out of the setup walk, so the shape depends on the 64 KiB buffer as much as
/// on the packet count.
fn trailing_packet_flood(key: &GeneratedKey, encrypted: bool) -> Vec<u8> {
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(if encrypted {
        &key.public_key_data
    } else {
        &key.cert_data
    })
    .expect("cert should parse");

    let mut sink = Vec::new();
    {
        let mut message = Message::new(&mut sink);
        if encrypted {
            message = Encryptor::for_recipients(message, recipients_of(&cert, &policy))
                .build()
                .expect("encryptor should build");
        } else {
            let keypair = cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .secret()
                .for_signing()
                .next()
                .expect("a signing key")
                .key()
                .clone()
                .into_keypair()
                .expect("signing keypair");
            message = Signer::new(message, keypair)
                .expect("signer should build")
                .build()
                .expect("signer should build");
        }

        {
            let mut literal = LiteralWriter::new(message)
                .build()
                .expect("literal writer should build");
            literal
                .write_all(&vec![b'x'; 512 * 1024])
                .expect("write plaintext");
            message = literal
                .finalize_one()
                .expect("finalize literal")
                .expect("inner message");
        }

        // Inside the encryption container, where the payload is; after the
        // signature otherwise, since a signed message admits no trailing
        // packets within its own structure.
        let padding = openpgp::Packet::from(Padding::from(vec![0u8; 16]));
        if encrypted {
            for _ in 0..3000 {
                padding
                    .serialize(&mut message)
                    .expect("padding should serialize");
            }
            message.finalize().expect("finalize message");
        } else {
            message.finalize().expect("finalize message");
        }
    }

    if !encrypted {
        let padding = openpgp::Packet::from(Padding::from(vec![0u8; 16]));
        for _ in 0..3000 {
            padding
                .serialize(&mut sink)
                .expect("padding should serialize");
        }
    }
    sink
}

fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn temp_path(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path()
        .join(name)
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

fn write_temp_file(name: &str, contents: &[u8]) -> (tempfile::TempDir, String) {
    let dir = temp_dir();
    let path = temp_path(&dir, name);
    std::fs::write(&path, contents).expect("write temp file");
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

    // Each phase-1 route refuses at the second compression layer, without
    // descending far enough to inflate: it never reaches the session-key packet
    // or the padding beneath it. The refusal says so rather than reporting
    // nothing found, which would reach the reader as "the data appears damaged".
    assert!(matches!(
        decrypt::parse_recipients(&bomb),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
    assert!(matches!(
        decrypt::match_recipients(&bomb, &[key.public_key_data.clone()]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
    assert!(matches!(
        decrypt::message_quantum_safety(&bomb),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
    assert!(matches!(
        password::decrypt(&bomb, &openpgp::crypto::Password::from("secret"), &[]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));

    let (_dir, path) = write_temp_file("nested.gpg", &bomb);
    assert!(matches!(
        streaming::match_recipients_from_file(&path, &[key.public_key_data.clone()]),
        Err(PgpError::MessageLimitsExceeded { .. })
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
fn a_bound_that_fires_during_the_read_is_still_reported_as_a_bound() {
    // The refusal has to survive Sequoia's `Read` impl, which wraps what it is
    // handed. Landing here as `CorruptData` would tell the reader their message
    // is damaged and to ask the sender to resend — wrong on both counts.
    let key = test_key();
    let encrypted = trailing_packet_flood(&key, true);
    assert!(
        encrypted.len() > 64 * 1024,
        "the payload must exceed the plaintext buffer, or the trailing packets \
         are walked during setup instead: {} bytes",
        encrypted.len()
    );

    assert!(matches!(
        decrypt::decrypt_detailed(&encrypted, &[key.cert_data.clone()], &[]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));

    // The verify route reaches the same channel through a signed message; an
    // encrypted one is refused by the message grammar first, since a verifier
    // does not open the container.
    let signed = trailing_packet_flood(&key, false);
    assert!(matches!(
        verify::verify_cleartext_detailed(&signed, &[key.public_key_data.clone()]),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));

    let dir = temp_dir();
    let input = temp_path(&dir, "trailing.gpg");
    std::fs::write(&input, &encrypted).expect("write input");
    let output = temp_path(&dir, "out.bin");
    assert!(matches!(
        streaming::decrypt_file_detailed(&input, &output, &[key.cert_data.clone()], &[], None),
        Err(PgpError::MessageLimitsExceeded { .. })
    ));
    // The success-only output contract holds through the new error path: this
    // refusal arrives after the temp file has been written to, so the cleanup
    // is the thing being checked, not the absence of an attempt.
    assert!(!std::path::Path::new(&output).exists());
    assert!(
        std::fs::read_dir(dir.path())
            .expect("read temp dir")
            .filter_map(Result::ok)
            .all(|entry| entry.file_name() == std::ffi::OsStr::new("trailing.gpg")),
        "no partial plaintext may be left behind"
    );
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
fn the_two_walks_do_not_split_a_verdict_on_a_crowded_message() {
    // Phase 1 counts the session-key packets; the setup walk counts those plus
    // the framing around the payload. If their allowances were equal, a message
    // near the ceiling would pass phase 1 — showing its recipient a key — and
    // then be refused when they used it. A thousand recipients is already past
    // anything real, so this is the boundary that has to hold.
    let key = test_key();
    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(&key.public_key_data).expect("cert should parse");
    let crowd: Vec<Recipient> = (0..1024)
        .flat_map(|_| recipients_of(&cert, &policy))
        .collect();
    assert_eq!(
        crowd.len(),
        1024,
        "the test key must contribute exactly one encryption subkey per pass"
    );

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Encryptor::for_recipients(message, crowd)
            .build()
            .expect("encryptor should build");
        let mut message = LiteralWriter::new(message).build().expect("literal writer");
        message.write_all(b"crowded").expect("write plaintext");
        message.finalize().expect("finalize");
    }

    let recipients = decrypt::parse_recipients(&sink).expect("phase 1 must accept the message");
    assert_eq!(recipients.len(), 1024);
    let result = decrypt::decrypt_detailed(&sink, &[key.cert_data.clone()], &[])
        .expect("what phase 1 accepted, phase 2 must open");
    assert_eq!(result.plaintext, b"crowded".to_vec());
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
