//! Rule E9: each signature verdict has its own case, a bad signature is never
//! reported as something milder, and a verified signature wins the summary.

mod common;

use std::time::SystemTime;

use common::keys::{self, PLAINTEXT};
use common::messages;
use cypher_engine::{KeyShape, NewKey, Signature, Verdict, decrypt, encrypt};
use openpgp::Cert;
use openpgp::parse::Parse;
use sequoia_openpgp as openpgp;

fn tsk_cert(key: &NewKey) -> Cert {
    Cert::from_bytes(&keys::tsk(key)).unwrap()
}

fn public_cert(key: &NewKey) -> Cert {
    Cert::from_bytes(&key.certificate).unwrap()
}

fn signature(verdict: Verdict, signer: Option<u32>) -> Signature {
    Signature { verdict, signer }
}

struct Cast {
    alice: NewKey,
    bob: NewKey,
    carol: NewKey,
}

fn cast() -> Cast {
    Cast {
        alice: keys::new_key(KeyShape::V6Curve25519, "Alice"),
        bob: keys::new_key(KeyShape::V6Curve25519, "Bob"),
        carol: keys::new_key(KeyShape::V4Curve25519, "Carol"),
    }
}

/// A message to Bob whose container holds `inner`.
fn to_bob(cast: &Cast, inner: &[u8]) -> Vec<u8> {
    messages::encrypted_raw(&[&public_cert(&cast.bob)], inner, SystemTime::now(), false)
}

#[test]
fn e9_verified_unknown_signer_and_not_signed() {
    let cast = cast();
    let signed = encrypt(
        PLAINTEXT.to_vec(),
        vec![cast.bob.certificate.clone()],
        Some(keys::handle(&cast.alice)),
    )
    .unwrap()
    .message;
    let verifiers = vec![
        cast.carol.certificate.clone(),
        cast.alice.certificate.clone(),
    ];
    let decrypted = decrypt(signed.clone(), keys::handle(&cast.bob), verifiers).unwrap();
    assert_eq!(decrypted.plaintext, PLAINTEXT);
    assert_eq!(decrypted.signature, signature(Verdict::Verified, Some(1)));

    let decrypted = decrypt(signed, keys::handle(&cast.bob), vec![]).unwrap();
    assert_eq!(decrypted.signature, signature(Verdict::UnknownSigner, None));

    let unsigned = encrypt(PLAINTEXT.to_vec(), vec![cast.bob.certificate.clone()], None)
        .unwrap()
        .message;
    let decrypted = decrypt(
        unsigned,
        keys::handle(&cast.bob),
        vec![cast.alice.certificate.clone()],
    )
    .unwrap();
    assert_eq!(decrypted.signature, signature(Verdict::NotSigned, None));
}

#[test]
fn e9_invalid_signature_is_invalid() {
    let cast = cast();
    let alice = tsk_cert(&cast.alice);
    let signed = messages::signed(
        PLAINTEXT,
        vec![messages::signing_pair(&alice, SystemTime::now())],
    );
    let message = to_bob(&cast, &messages::corrupt_signature(&signed, &alice));
    let decrypted = decrypt(
        message,
        keys::handle(&cast.bob),
        vec![cast.alice.certificate.clone()],
    )
    .unwrap();
    assert_eq!(decrypted.signature, signature(Verdict::Invalid, Some(0)));
}

#[test]
fn e9_signer_revoked() {
    let cast = cast();
    let signed = encrypt(
        PLAINTEXT.to_vec(),
        vec![cast.bob.certificate.clone()],
        Some(keys::handle(&cast.alice)),
    )
    .unwrap()
    .message;
    let decrypted = decrypt(
        signed,
        keys::handle(&cast.bob),
        vec![keys::revoked(&cast.alice)],
    )
    .unwrap();
    assert_eq!(
        decrypted.signature,
        signature(Verdict::SignerRevoked, Some(0))
    );
}

/// A bad signature by a revoked key is `Invalid`, not the milder
/// `SignerRevoked`.
#[test]
fn e9_invalid_signature_by_revoked_key_is_invalid() {
    let cast = cast();
    let alice = tsk_cert(&cast.alice);
    let signed = messages::signed(
        PLAINTEXT,
        vec![messages::signing_pair(&alice, SystemTime::now())],
    );
    let message = to_bob(&cast, &messages::corrupt_signature(&signed, &alice));
    let decrypted = decrypt(
        message,
        keys::handle(&cast.bob),
        vec![keys::revoked(&cast.alice)],
    )
    .unwrap();
    assert_eq!(decrypted.signature, signature(Verdict::Invalid, Some(0)));
}

#[test]
fn e9_signer_expired() {
    let cast = cast();
    let erin = keys::expired_cert("Erin");
    let (created, _) = keys::expired_window();
    let pair = messages::signing_pair(&erin, created + std::time::Duration::from_secs(60));
    let message = to_bob(&cast, &messages::signed(PLAINTEXT, vec![pair]));
    let (erin_certificate, _) = keys::split(&erin);
    let decrypted = decrypt(message, keys::handle(&cast.bob), vec![erin_certificate]).unwrap();
    assert_eq!(
        decrypted.signature,
        signature(Verdict::SignerExpired, Some(0))
    );
}

/// One verified and one invalid signature are `Verified`, naming the verified
/// signer, whatever the order of the signatures and of the verifiers.
#[test]
fn e9_verified_signature_wins_over_invalid_one() {
    let cast = cast();
    let alice = tsk_cert(&cast.alice);
    let carol = tsk_cert(&cast.carol);
    let now = SystemTime::now();
    for pairs in [
        vec![
            messages::signing_pair(&alice, now),
            messages::signing_pair(&carol, now),
        ],
        vec![
            messages::signing_pair(&carol, now),
            messages::signing_pair(&alice, now),
        ],
    ] {
        let signed = messages::signed(PLAINTEXT, pairs);
        let message = to_bob(&cast, &messages::corrupt_signature(&signed, &carol));
        for (verifiers, alice_at) in [
            (
                vec![
                    cast.alice.certificate.clone(),
                    cast.carol.certificate.clone(),
                ],
                0,
            ),
            (
                vec![
                    cast.carol.certificate.clone(),
                    cast.alice.certificate.clone(),
                ],
                1,
            ),
        ] {
            let decrypted = decrypt(message.clone(), keys::handle(&cast.bob), verifiers).unwrap();
            assert_eq!(
                decrypted.signature,
                signature(Verdict::Verified, Some(alice_at))
            );
        }
    }
}
