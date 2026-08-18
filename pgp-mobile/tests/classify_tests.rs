//! Content classification of files that arrive named rather than chosen.
//!
//! The GnuPG fixtures are the point: they are what a real producer writes, so
//! they carry the shapes a name cannot describe — a revocation certificate
//! armored as a public key block, a signed message hidden inside a compressed
//! container, a cleartext-signed message whose trailing block reads as a bare
//! signature to anything that does not look first.

mod common;

use common::load_fixture;
use pgp_mobile::classify::{classify_openpgp_data, OpenPgpDataKind};
use pgp_mobile::error::PgpError;
use pgp_mobile::keys::{self, KeySuite};

#[test]
fn armored_and_binary_public_certificates_classify_as_certificates() {
    for fixture in ["gpg_pubkey.asc", "gpg_pubkey.gpg"] {
        assert_eq!(
            classify_openpgp_data(&load_fixture(fixture)).unwrap(),
            OpenPgpDataKind::PublicCertificate,
            "{fixture}"
        );
    }
}

#[test]
fn secret_key_classifies_apart_from_the_certificate_it_contains() {
    assert_eq!(
        classify_openpgp_data(&load_fixture("gpg_secretkey.asc")).unwrap(),
        OpenPgpDataKind::SecretKey
    );
}

#[test]
fn armored_and_binary_encrypted_messages_classify_as_ciphertext() {
    for fixture in [
        "gpg_encrypted_message.asc",
        "gpg_encrypted_message.gpg",
        "gpg_encrypted_compressed_deflate.asc",
        "gpg_encrypted_compressed_zlib.asc",
    ] {
        assert_eq!(
            classify_openpgp_data(&load_fixture(fixture)).unwrap(),
            OpenPgpDataKind::Ciphertext,
            "{fixture}"
        );
    }
}

/// The cleartext framework ends in a signature block. Reading the packets
/// without recognizing the framing first finds that block and calls the whole
/// file a detached signature, which sends the reader to look for an original
/// that is already in their hands.
#[test]
fn cleartext_signed_message_classifies_as_a_signed_message() {
    assert_eq!(
        classify_openpgp_data(&load_fixture("gpg_cleartext_signed.asc")).unwrap(),
        OpenPgpDataKind::SignedMessage
    );
}

/// A one-pass-signed message compresses by default, so the packet that decides
/// sits one container down.
#[test]
fn compressed_inline_signed_message_classifies_as_a_signed_message() {
    assert_eq!(
        classify_openpgp_data(&load_fixture("gpg_signed_compressed.asc")).unwrap(),
        OpenPgpDataKind::SignedMessage
    );
}

#[test]
fn armored_and_binary_detached_signatures_classify_as_detached() {
    for fixture in ["gpg_detached_sig.asc", "gpg_detached_sig.sig"] {
        assert_eq!(
            classify_openpgp_data(&load_fixture(fixture)).unwrap(),
            OpenPgpDataKind::DetachedSignature,
            "{fixture}"
        );
    }
}

/// GnuPG armors a revocation certificate as a `PUBLIC KEY BLOCK`, so the header
/// says certificate and the single packet inside says otherwise.
#[test]
fn revocation_certificate_classifies_apart_from_the_certificate_it_is_armored_as() {
    let key = keys::generate_key_with_suite(
        "Revocation Subject".to_string(),
        Some("revoked@example.com".to_string()),
        None,
        KeySuite::Ed25519X25519,
    )
    .expect("key generation should succeed");

    assert_eq!(
        classify_openpgp_data(&key.revocation_cert).unwrap(),
        OpenPgpDataKind::RevocationCertificate
    );
}

/// A nested compressed container is a decompression bomb, and a header walk is
/// where one is spent: at the depth the walk stops descending, Sequoia's
/// `recurse` skips the container instead — by inflating all of it. The fixture
/// below is a few hundred bytes and holds 64 MiB; the shape scales past any
/// memory the device has, on a file anybody can send. The walk must refuse it
/// outright, so that opening it costs an error message rather than the process.
#[test]
fn nested_compressed_containers_are_refused_without_inflating_them() {
    let bomb = nested_compression_bomb(64 * 1024 * 1024);
    assert!(
        bomb.len() < 64 * 1024,
        "the fixture should be tiny beside what it expands to, got {} bytes",
        bomb.len()
    );

    let started = std::time::Instant::now();
    let error = classify_openpgp_data(&bomb).expect_err("a nested container is refused");

    assert!(
        matches!(error, PgpError::MessageLimitsExceeded { .. }),
        "expected a consumption bound, got {error:?}"
    );
    // Inflating even the first layer would take orders of magnitude longer than
    // this; the assertion is what separates "refused" from "read it all and
    // then complained".
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "refusal should not have read the payload, took {:?}",
        started.elapsed()
    );
}

/// `Compressed( Compressed( Literal ) )` over `payload_bytes` of zeros.
fn nested_compression_bomb(payload_bytes: usize) -> Vec<u8> {
    use sequoia_openpgp::serialize::stream::{Compressor, LiteralWriter, Message};
    use sequoia_openpgp::types::CompressionAlgorithm;
    use std::io::Write as _;

    let mut bomb = Vec::new();
    let outer = Compressor::new(Message::new(&mut bomb))
        .algo(CompressionAlgorithm::Zip)
        .build()
        .expect("outer compressor");
    let inner = Compressor::new(outer)
        .algo(CompressionAlgorithm::Zip)
        .build()
        .expect("inner compressor");
    let mut literal = LiteralWriter::new(inner).build().expect("literal writer");

    let chunk = vec![0u8; 1024 * 1024];
    let mut written = 0;
    while written < payload_bytes {
        let take = chunk.len().min(payload_bytes - written);
        literal.write_all(&chunk[..take]).expect("write payload");
        written += take;
    }
    literal.finalize().expect("finalize");

    bomb
}

#[test]
fn non_openpgp_bytes_are_refused() {
    let error = classify_openpgp_data(b"just some text a user dropped on the app")
        .expect_err("plain text is not OpenPGP");
    assert!(matches!(error, PgpError::CorruptData { .. }));
}

/// Literal data is OpenPGP the parser reads happily and nothing the app has a
/// destination for, so it fails rather than landing somewhere by default.
#[test]
fn bare_literal_data_is_refused() {
    let literal = {
        use sequoia_openpgp::serialize::SerializeInto as _;
        let mut packet =
            sequoia_openpgp::packet::Literal::new(sequoia_openpgp::types::DataFormat::Binary);
        packet.set_body(b"payload".to_vec());
        sequoia_openpgp::Packet::from(packet)
            .to_vec()
            .expect("literal packet should serialize")
    };

    let error = classify_openpgp_data(&literal).expect_err("literal data has no destination");
    assert!(matches!(error, PgpError::CorruptData { .. }));
}
