//! Rule E3: hostile input is refused, each kind with one error. A bound that
//! fires after the unwrap is `LimitsExceeded` in the new container, and these
//! tests use it; in the old container it is `Tampered`, which one test pins. That a panic
//! below the boundary becomes `Internal` is pinned in `src/error.rs`, with a
//! deliberate panic.
//!
//! The expansion test that needs 256 MiB is ignored by default; run it with
//! `cargo test -- --ignored`.

mod common;

use std::time::SystemTime;

use common::keys::{self, PLAINTEXT};
use common::messages;
use cypher_engine::{
    ArmorKind, EngineError, KeyShape, PrivateKey, armor, decrypt, encrypt, inspect_certificate,
};
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use sequoia_openpgp as openpgp;

fn cert_of(key: &cypher_engine::NewKey) -> Cert {
    Cert::from_bytes(&key.certificate).unwrap()
}

fn to(key: &cypher_engine::NewKey, inner: &[u8]) -> Vec<u8> {
    messages::encrypted_raw(&[&cert_of(key)], inner, SystemTime::now(), false)
}

/// Too many session-key packets, before any key is tried.
#[test]
fn e3_too_many_packets_before_the_container() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let message = messages::binary(
        &encrypt(PLAINTEXT, vec![alice.certificate.clone()], None)
            .unwrap()
            .message,
    );
    let container = messages::container_offset(&message);
    let mut flooded = Vec::new();
    for _ in 0..1100 {
        flooded.extend_from_slice(&message[..container]);
    }
    flooded.extend_from_slice(&message[container..]);
    assert_eq!(
        decrypt(flooded, keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::LimitsExceeded
    );
}

/// Too many packets inside the container, after the key was unwrapped.
#[test]
fn e3_too_many_packets_after_the_key_was_unwrapped() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let mut inner = Vec::new();
    for _ in 0..2100 {
        inner.extend_from_slice(&[0xC0 | 21, 1, 0]);
    }
    inner.extend_from_slice(&messages::literal(PLAINTEXT));
    assert_eq!(
        decrypt(to(&alice, &inner), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::LimitsExceeded
    );
}

/// Too many packets while the plaintext is being read: the message is larger
/// than Sequoia's setup buffer, and the packets follow the literal data, so
/// the bound fires inside `Decryptor::read`, not while the decryptor is built.
#[test]
fn e3_too_many_packets_while_reading() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let mut inner = messages::literal(&vec![0x42; 128 * 1024]);
    for _ in 0..2100 {
        inner.extend_from_slice(&[0xC0 | 21, 1, 0]);
    }
    assert_eq!(
        decrypt(to(&alice, &inner), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::LimitsExceeded
    );
}

/// Too deep nesting, outside the container and inside it.
#[test]
fn e3_too_deep_nesting() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let message = messages::binary(
        &encrypt(PLAINTEXT, vec![alice.certificate.clone()], None)
            .unwrap()
            .message,
    );
    let outside = messages::compressed(&messages::compressed(&message));
    assert_eq!(
        decrypt(outside, keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::LimitsExceeded
    );

    let mut inner = messages::literal(PLAINTEXT);
    for _ in 0..4 {
        inner = messages::compressed(&inner);
    }
    assert_eq!(
        decrypt(to(&alice, &inner), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::LimitsExceeded
    );
}

/// Too much expansion inside the container: packets the walk skips, which a
/// few bytes of compressed input inflate past the walk's budget.
#[test]
fn e3_too_much_expansion() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let mut skipped = Vec::new();
    for _ in 0..3 {
        skipped.extend_from_slice(&messages::padding(512 * 1024));
    }
    skipped.extend_from_slice(&messages::literal(PLAINTEXT));
    let inner = messages::compressed(&skipped);
    assert!(inner.len() < 16 * 1024);
    assert_eq!(
        decrypt(to(&alice, &inner), keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::LimitsExceeded
    );
}

/// Too much expansion of the plaintext itself, past what decrypting into
/// memory may hold: `LimitsExceeded` in the new container, `Tampered` in the
/// old one, where that ceiling is decided by content not yet authenticated.
#[test]
#[ignore = "needs 256 MiB; run with --ignored"]
fn e3_too_much_plaintext() {
    let mut inner = Vec::new();
    {
        use openpgp::serialize::stream::{Compressor, LiteralWriter, Message};
        use std::io::Write;
        let compressor = Compressor::new(Message::new(&mut inner)).build().unwrap();
        let mut literal = LiteralWriter::new(compressor).build().unwrap();
        let zeros = vec![0u8; 1024 * 1024];
        for _ in 0..257 {
            literal.write_all(&zeros).unwrap();
        }
        literal.finalize().unwrap();
    }
    for (shape, expected) in [
        (KeyShape::V6Curve25519, EngineError::LimitsExceeded),
        (KeyShape::V4Curve25519, EngineError::Tampered),
    ] {
        let alice = keys::new_key(shape, "Alice");
        assert_eq!(
            decrypt(to(&alice, &inner), keys::handle(&alice), vec![]).unwrap_err(),
            expected,
            "{shape:?}"
        );
    }
}

/// In the old container a bound that fires after the unwrap is `Tampered`,
/// while the decryptor is built and while the plaintext is read: until its end
/// that container's content may have been changed, so nothing it decides is
/// reported.
#[test]
fn e3_bound_after_the_unwrap_in_the_old_container_is_tampered() {
    let alice = keys::new_key(KeyShape::V4Curve25519, "Alice");
    let padding = |count: usize| {
        let mut packets = Vec::new();
        for _ in 0..count {
            packets.extend_from_slice(&[0xC0 | 21, 1, 0]);
        }
        packets
    };
    let mut while_built = padding(2100);
    while_built.extend_from_slice(&messages::literal(PLAINTEXT));
    let mut while_read = messages::literal(&vec![0x42; 128 * 1024]);
    while_read.extend_from_slice(&padding(2100));
    for inner in [while_built, while_read] {
        let message = to(&alice, &inner);
        assert_eq!(messages::container_version(&message), 1);
        assert_eq!(
            decrypt(message, keys::handle(&alice), vec![]).unwrap_err(),
            EngineError::Tampered
        );
    }
}

/// A container without authentication (the old tag-9 packet) is
/// `Unsupported`, even behind a recipient packet for the key.
#[test]
fn e3_container_without_authentication_is_unsupported() {
    let alice = keys::new_key(KeyShape::V4Curve25519, "Alice");
    let message = messages::binary(
        &encrypt(PLAINTEXT, vec![alice.certificate.clone()], None)
            .unwrap()
            .message,
    );
    let container = messages::container_offset(&message);
    let mut unauthenticated = message[..container].to_vec();
    unauthenticated.extend_from_slice(&[0xC0 | 9, 64]);
    unauthenticated.extend_from_slice(&[0x5A; 64]);
    assert_eq!(
        decrypt(unauthenticated, keys::handle(&alice), vec![]).unwrap_err(),
        EngineError::Unsupported
    );
}

/// Key material beyond its bounds: too large, or too many packets.
#[test]
fn e3_key_material_beyond_its_bounds() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let secret = alice.secret.as_deref().unwrap();

    let mut too_large = alice.certificate.clone();
    too_large.resize(1024 * 1024 + 1, 0);
    let mut too_many_packets = alice.certificate.clone();
    let user_id = openpgp::Packet::from(openpgp::packet::UserID::from("Mallory"))
        .to_vec()
        .unwrap();
    for _ in 0..1024 {
        too_many_packets.extend_from_slice(&user_id);
    }

    for certificate in [too_large, too_many_packets] {
        assert_eq!(
            inspect_certificate(certificate.clone()).unwrap_err(),
            EngineError::LimitsExceeded
        );
        assert_eq!(
            PrivateKey::portable(certificate.clone(), secret).unwrap_err(),
            EngineError::LimitsExceeded
        );
        assert_eq!(
            armor(ArmorKind::Certificate, certificate).unwrap_err(),
            EngineError::LimitsExceeded
        );
    }

    let mut too_large_secret = secret.to_vec();
    too_large_secret.resize(1024 * 1024 + 1, 0);
    assert_eq!(
        PrivateKey::portable(alice.certificate.clone(), &too_large_secret).unwrap_err(),
        EngineError::LimitsExceeded
    );
    let mut too_large_revocation = alice.revocation.clone();
    too_large_revocation.resize(1024 * 1024 + 1, 0);
    assert_eq!(
        armor(ArmorKind::Revocation, too_large_revocation).unwrap_err(),
        EngineError::LimitsExceeded
    );
}
