//! Rules E15 and E16: every operation takes every custody through the same
//! function, and device custody fails closed.

mod common;

use std::sync::Arc;
use std::time::SystemTime;

use common::device::{self, Behaviour, SoftwareDevice};
use common::keys::{self, PLAINTEXT};
use common::messages;
use cypher_engine::{
    EngineError, Expiry, KeyShape, NewKey, PrivateKey, Signature, Verdict, decrypt,
    device_key_slots, encrypt, generate_device_key,
};
use openpgp::crypto::mpi;
use openpgp::packet::pkesk::{PKESK3, PKESK6};
use openpgp::packet::{PKESK, Packet};
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use openpgp::types::PublicKeyAlgorithm;
use sequoia_openpgp as openpgp;

const PORTABLE: [KeyShape; 5] = [
    KeyShape::V4Curve25519,
    KeyShape::V6Curve25519,
    KeyShape::V6Curve448,
    KeyShape::V6MlDsa65,
    KeyShape::V6MlDsa87,
];

const REFUSALS: [(Behaviour, EngineError); 3] = [
    (Behaviour::Cancel, EngineError::Cancelled),
    (
        Behaviour::NotAuthenticated,
        EngineError::DeviceNotAuthenticated,
    ),
    (Behaviour::Fail, EngineError::DeviceFailed),
];

fn cert(key: &NewKey) -> openpgp::Cert {
    openpgp::Cert::from_bytes(&key.certificate).unwrap()
}

/// E15. `encrypt` signs and `decrypt` opens through the same functions for
/// every custody and every family, and the signature verifies.
#[test]
fn e15_every_operation_takes_every_custody() {
    let mut handles: Vec<(String, NewKey, Arc<PrivateKey>)> = PORTABLE
        .iter()
        .map(|&shape| {
            let key = keys::new_key(shape, "Alice");
            let handle = keys::handle(&key);
            (format!("portable {shape:?}"), key, handle)
        })
        .collect();
    for shape in device::SHAPES {
        let (key, device) = device::device_key(shape, "Alice");
        let handle = device::device_handle(&key, &device);
        handles.push((format!("device-bound {shape:?}"), key, handle));
    }

    for (label, key, handle) in handles {
        let message = encrypt(
            PLAINTEXT,
            vec![key.certificate.clone()],
            Some(handle.clone()),
        )
        .unwrap();
        let decrypted = decrypt(message.message, handle, vec![key.certificate.clone()]).unwrap();
        assert_eq!(
            (decrypted.plaintext.as_slice(), decrypted.signature),
            (
                PLAINTEXT,
                Signature {
                    verdict: Verdict::Verified,
                    signer: Some(0)
                }
            ),
            "{label}"
        );
    }
}

/// E16. A device signature is verified before it is released: a device that
/// answers wrongly, or the device of another key, signs nothing, neither a
/// message nor a new certificate.
#[test]
fn e16_device_signature_is_verified_before_release() {
    for shape in device::SHAPES {
        let (key, device) = device::device_key(shape, "Alice");
        let handle = device::device_handle(&key, &device);
        for behaviour in [Behaviour::AnswerWrongly, Behaviour::AnswerShort] {
            device.behave(behaviour);
            assert_eq!(
                encrypt(
                    PLAINTEXT,
                    vec![key.certificate.clone()],
                    Some(handle.clone())
                )
                .unwrap_err(),
                EngineError::DeviceFailed,
                "{shape:?} {behaviour:?}"
            );

            let (signing, agreement) = device.public_keys();
            assert_eq!(
                generate_device_key(
                    shape,
                    keys::user("Bob"),
                    Expiry::Never,
                    keys::STAMP,
                    signing,
                    agreement,
                    device.clone(),
                )
                .unwrap_err(),
                EngineError::DeviceFailed,
                "{shape:?} {behaviour:?}"
            );
        }

        let other = SoftwareDevice::new(shape);
        let wrong = PrivateKey::device(
            key.certificate.clone(),
            key.secret.as_deref().unwrap_or_default(),
            other,
        )
        .unwrap();
        assert_eq!(
            encrypt(PLAINTEXT, vec![key.certificate.clone()], Some(wrong)).unwrap_err(),
            EngineError::DeviceFailed,
            "{shape:?} with another device"
        );
    }
}

/// E16. Classical halves that do not belong to the certificate fail before
/// the device is asked: those of another key, each half alone, halves of the
/// other family, none where there should be some, and some where there
/// should be none.
#[test]
fn e16_wrong_classical_half_fails_before_the_device_is_asked() {
    let (pq, pq_device) = device::device_key(KeyShape::V6MlDsa65, "Alice");
    let (other, _) = device::device_key(KeyShape::V6MlDsa65, "Bob");
    let (high, high_device) = device::device_key(KeyShape::V6MlDsa87, "Carol");
    let (p256, p256_device) = device::device_key(KeyShape::V6P256, "Dave");
    let (halves, other_halves) = (pq.secret.clone().unwrap(), other.secret.clone().unwrap());
    let mixed =
        |eddsa_from: &[u8], ecdh_from: &[u8]| [&eddsa_from[..32], &ecdh_from[32..]].concat();

    let cases: [(&NewKey, &Arc<SoftwareDevice>, Vec<u8>); 7] = [
        (&pq, &pq_device, other_halves.clone()),
        (&pq, &pq_device, mixed(&other_halves, &halves)),
        (&pq, &pq_device, mixed(&halves, &other_halves)),
        (&pq, &pq_device, high.secret.clone().unwrap()),
        (&pq, &pq_device, Vec::new()),
        (&high, &high_device, halves.clone()),
        (&p256, &p256_device, halves.clone()),
    ];
    for (index, (key, device, secret)) in cases.into_iter().enumerate() {
        let asked = || device.signs() + device.agreements();
        let before = asked();
        assert_eq!(
            PrivateKey::device(key.certificate.clone(), &secret, device.clone()).unwrap_err(),
            EngineError::KeyMismatch,
            "case {index}"
        );
        assert_eq!(asked(), before, "case {index}");
    }
}

/// A copy of a P-256 session-key packet whose ephemeral point is moved off
/// the curve, naming the recipient or hidden.
fn off_curve(packet: &[u8], named: bool) -> Vec<u8> {
    let Packet::PKESK(pkesk) = Packet::from_bytes(packet).unwrap() else {
        panic!("not a session-key packet")
    };
    let moved = |esk: &mpi::Ciphertext| {
        let mpi::Ciphertext::ECDH { e, key } = esk else {
            panic!("not ECDH")
        };
        let mut point = e.value().to_vec();
        *point.last_mut().unwrap() ^= 0x01;
        mpi::Ciphertext::ECDH {
            e: mpi::MPI::new(&point),
            key: key.clone(),
        }
    };
    let packet: Packet = match pkesk {
        PKESK::V3(pkesk) => PKESK3::new(
            pkesk.recipient().cloned().filter(|_| named),
            PublicKeyAlgorithm::ECDH,
            moved(pkesk.esk()),
        )
        .unwrap()
        .into(),
        PKESK::V6(pkesk) => PKESK6::new(
            pkesk.recipient().cloned().filter(|_| named),
            PublicKeyAlgorithm::ECDH,
            moved(pkesk.esk()),
        )
        .unwrap()
        .into(),
        _ => unreachable!(),
    };
    packet.to_vec().unwrap()
}

/// E16. The hidden-recipient rule, with a point off the curve: such a packet
/// is not for the key, and the device is never asked with it. A hidden one in
/// front of the real packet does not block the message; one that names the
/// key is `Tampered`.
#[test]
fn e16_point_off_the_curve_is_not_for_the_key() {
    for shape in [KeyShape::V4P256, KeyShape::V6P256] {
        let (key, device) = device::device_key(shape, "Alice");
        let handle = device::device_handle(&key, &device);
        let message = messages::binary(
            &encrypt(PLAINTEXT, vec![key.certificate.clone()], None)
                .unwrap()
                .message,
        );
        let packet_end = messages::session_key_packet_ends(&message)[0];

        let hidden_in_front = [off_curve(&message[..packet_end], false), message.clone()].concat();
        let decrypted = decrypt(hidden_in_front, handle.clone(), vec![]).unwrap();
        assert_eq!(decrypted.plaintext, PLAINTEXT, "{shape:?}");
        assert_eq!(device.agreements(), 1, "{shape:?}");

        let named_instead = [
            off_curve(&message[..packet_end], true),
            message[packet_end..].to_vec(),
        ]
        .concat();
        assert_eq!(
            decrypt(named_instead, handle, vec![]).unwrap_err(),
            EngineError::Tampered,
            "{shape:?}"
        );
        assert_eq!(device.agreements(), 1, "{shape:?}");
    }
}

/// E16. A cancel or a failure of the device stops the decryption and is
/// reported as itself, for a packet that names the key and for a hidden one:
/// the device is asked once, though a second packet for the key follows.
#[test]
fn e16_device_failure_stops_decryption() {
    for shape in device::SHAPES {
        let (key, device) = device::device_key(shape, "Alice");
        let handle = device::device_handle(&key, &device);
        let literal = messages::literal(PLAINTEXT);
        let now = SystemTime::now();
        let named =
            messages::encrypted_mixed(&[(&cert(&key), false), (&cert(&key), false)], &literal, now);
        let hidden =
            messages::encrypted_mixed(&[(&cert(&key), true), (&cert(&key), true)], &literal, now);
        for (behaviour, error) in REFUSALS {
            for (kind, message) in [("named", &named), ("hidden", &hidden)] {
                device.behave(behaviour);
                let before = device.agreements();
                assert_eq!(
                    decrypt(message.clone(), handle.clone(), vec![]).unwrap_err(),
                    error,
                    "{shape:?} {kind} {behaviour:?}"
                );
                assert_eq!(
                    device.agreements() - before,
                    1,
                    "{shape:?} {kind} {behaviour:?}"
                );
            }
        }
    }
}

/// E16. A failure of the device is not a failure of the message: in a nested
/// container, a cancel or failure while the inner packet is unwrapped is
/// reported as itself, also in the old container, though a session key was
/// already unwrapped.
#[test]
fn e16_device_failure_after_the_unwrap_is_reported_as_itself() {
    for shape in [KeyShape::V4P256, KeyShape::V6P256] {
        let (key, device) = device::device_key(shape, "Alice");
        let handle = device::device_handle(&key, &device);
        let now = SystemTime::now();
        let inner =
            messages::encrypted_raw(&[&cert(&key)], &messages::literal(PLAINTEXT), now, false);
        let nested = messages::encrypted_raw(&[&cert(&key)], &inner, now, false);
        for (behaviour, error) in REFUSALS {
            device.behave_after(1, behaviour);
            assert_eq!(
                decrypt(nested.clone(), handle.clone(), vec![]).unwrap_err(),
                error,
                "{shape:?} {behaviour:?}"
            );
        }
    }
}

/// E16. A cancel or a failure of the device stops the signing, of a message
/// and of a new certificate, and is reported as itself.
#[test]
fn e16_device_failure_stops_signing() {
    for shape in device::SHAPES {
        let (key, device) = device::device_key(shape, "Alice");
        let handle = device::device_handle(&key, &device);
        for (behaviour, error) in REFUSALS {
            device.behave(behaviour);
            assert_eq!(
                encrypt(
                    PLAINTEXT,
                    vec![key.certificate.clone()],
                    Some(handle.clone())
                )
                .unwrap_err(),
                error,
                "{shape:?} {behaviour:?}"
            );
            let (signing, agreement) = device.public_keys();
            assert_eq!(
                generate_device_key(
                    shape,
                    keys::user("Bob"),
                    Expiry::Never,
                    keys::STAMP,
                    signing,
                    agreement,
                    device.clone(),
                )
                .unwrap_err(),
                error,
                "{shape:?} {behaviour:?}"
            );
        }
    }
}

/// A shared secret of the right shape that is wrong unwraps nothing: a packet
/// that names the key is `Tampered`, a hidden one is someone else's. One of
/// the wrong shape is a failure of the device.
#[test]
fn wrong_shared_secret_unwraps_nothing() {
    for shape in device::SHAPES {
        let (key, device) = device::device_key(shape, "Alice");
        let handle = device::device_handle(&key, &device);
        let literal = messages::literal(PLAINTEXT);
        let now = SystemTime::now();
        let named = messages::encrypted_raw(&[&cert(&key)], &literal, now, false);
        let hidden = messages::encrypted_raw(&[&cert(&key)], &literal, now, true);

        device.behave(Behaviour::AnswerWrongly);
        assert_eq!(
            decrypt(named.clone(), handle.clone(), vec![]).unwrap_err(),
            EngineError::Tampered,
            "{shape:?}"
        );
        assert_eq!(
            decrypt(hidden, handle.clone(), vec![]).unwrap_err(),
            EngineError::NoMatchingKey,
            "{shape:?}"
        );
        device.behave(Behaviour::AnswerShort);
        assert_eq!(
            decrypt(named, handle, vec![]).unwrap_err(),
            EngineError::DeviceFailed,
            "{shape:?}"
        );
    }
}

/// `device_key_slots` gives the public keys the device stated, which the vault
/// compares with the keys it loads. A certificate of another layout has none.
#[test]
fn device_key_slots_are_the_devices_public_keys() {
    for shape in device::SHAPES {
        let (key, device) = device::device_key(shape, "Alice");
        let slots = device_key_slots(key.certificate).unwrap();
        assert_eq!(
            (slots.signing_public_key, slots.agreement_public_key),
            device.public_keys(),
            "{shape:?}"
        );
    }
    // A portable post-quantum key has the algorithms of a device-bound one,
    // but a signing subkey too.
    for shape in [KeyShape::V6Curve25519, KeyShape::V6MlDsa65] {
        let portable = keys::new_key(shape, "Bob");
        assert_eq!(
            device_key_slots(portable.certificate).unwrap_err(),
            EngineError::Unsupported,
            "{shape:?}"
        );
    }
    let portable = keys::new_key(KeyShape::V6Curve25519, "Bob");
    let (_, device) = device::device_key(KeyShape::V6P256, "Carol");
    assert_eq!(
        PrivateKey::device(portable.certificate, &[], device).unwrap_err(),
        EngineError::Unsupported
    );
}
