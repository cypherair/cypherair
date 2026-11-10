//! Rule E22: everything made with a key carries the stamp the caller gave,
//! the key expires at the stamp plus the period, a time beyond OpenPGP's range
//! is refused, and the prepared revocation still revokes after a later
//! self-signature. The expiry change is #1049's. That `gpg` and `sq` accept
//! the stamped keys is shown by the interoperability tests, whose keys all
//! carry the harness's stamp.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::device::{self, StandInSigner};
use common::keys;
use cypher_engine::{
    EngineError, Expiry, KeyShape, KeyStatus, NewKey, generate_device_key, generate_portable_key,
    inspect_certificate,
};
use openpgp::cert::prelude::*;
use openpgp::crypto::Signer;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use openpgp::types::SignatureType;
use openpgp::{Packet, PacketPile};
use sequoia_openpgp as openpgp;

/// Not a round number: nothing rounds it on the way.
const STAMP: u64 = keys::STAMP + 12_345;
const DAYS: u32 = 400;
const DAY: u64 = 24 * 60 * 60;

const PORTABLE: [KeyShape; 5] = [
    KeyShape::V4Curve25519,
    KeyShape::V6Curve25519,
    KeyShape::V6Curve448,
    KeyShape::V6MlDsa65,
    KeyShape::V6MlDsa87,
];

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Every time written into a piece of key material: each key packet's
/// creation time, each signature's, and each embedded back-signature's.
#[derive(Default)]
struct Times {
    keys: Vec<u64>,
    signatures: Vec<u64>,
    embedded: Vec<u64>,
}

impl Times {
    fn read(&mut self, bytes: &[u8]) {
        for packet in PacketPile::from_bytes(bytes).unwrap().into_children() {
            match packet {
                Packet::PublicKey(key) => self.keys.push(unix(key.creation_time())),
                Packet::PublicSubkey(key) => self.keys.push(unix(key.creation_time())),
                Packet::SecretKey(key) => self.keys.push(unix(key.creation_time())),
                Packet::SecretSubkey(key) => self.keys.push(unix(key.creation_time())),
                Packet::Signature(signature) => {
                    self.signatures
                        .push(unix(signature.signature_creation_time().unwrap()));
                    for embedded in signature.embedded_signatures() {
                        self.embedded
                            .push(unix(embedded.signature_creation_time().unwrap()));
                    }
                }
                _ => {}
            }
        }
    }
}

/// E22. For every shape in both custodies: every key packet, every signature
/// packet with its back-signature inside, and the prepared revocation carry
/// the stamp, and the key expires at the stamp plus the period.
#[test]
fn e22_everything_made_with_a_key_carries_the_stamp() {
    let expiry = Expiry::After { days: DAYS };
    let mut made: Vec<(String, NewKey)> = PORTABLE
        .iter()
        .map(|&shape| {
            let key = generate_portable_key(shape, keys::user("Alice"), expiry, STAMP).unwrap();
            (format!("portable {shape:?}"), key)
        })
        .collect();
    for shape in device::SHAPES {
        let device = device::SoftwareDevice::new(shape);
        let (signing, agreement) = device.public_keys();
        let key = generate_device_key(
            shape,
            keys::user("Alice"),
            expiry,
            STAMP,
            signing,
            agreement,
            device,
        )
        .unwrap();
        made.push((format!("device-bound {shape:?}"), key));
    }

    for (label, key) in made {
        let mut times = Times::default();
        times.read(&key.certificate);
        if let Some(secret) = &key.secret
            && label.starts_with("portable")
        {
            times.read(secret);
        }
        times.read(&key.revocation);

        // Two keys, each in the certificate and, for a portable key, in the
        // secret; the direct-key, User ID and subkey signatures and the
        // revocation; a back-signature where a subkey signs.
        let portable = label.starts_with("portable");
        assert!(times.keys.len() >= if portable { 4 } else { 2 }, "{label}");
        assert!(times.signatures.len() >= 4, "{label}");
        assert_eq!(!times.embedded.is_empty(), portable, "{label}");
        for time in times
            .keys
            .iter()
            .chain(&times.signatures)
            .chain(&times.embedded)
        {
            assert_eq!(*time, STAMP, "{label}");
        }

        let info = inspect_certificate(key.certificate).unwrap();
        assert_eq!(
            (info.created, info.newest_self_signature, info.expires),
            (STAMP, STAMP, Some(STAMP + u64::from(DAYS) * DAY)),
            "{label}"
        );
    }
}

/// E22. A stamp, or a stamp plus the period, beyond OpenPGP's 32-bit time is
/// `TimeOutOfRange`, before the device is asked; the last second is not.
/// A period of zero days, which OpenPGP would read as "never", is refused.
#[test]
fn e22_time_beyond_openpgp_is_refused() {
    let last = u64::from(u32::MAX);
    let refused = [
        (last + 1, Expiry::Never),
        (last - DAY + 1, Expiry::After { days: 1 }),
    ];
    let (_, device) = device::device_key(KeyShape::V6P256, "Alice");
    let (signing, agreement) = device.public_keys();
    let device_key = |stamp, expiry| {
        generate_device_key(
            KeyShape::V6P256,
            keys::user("Alice"),
            expiry,
            stamp,
            signing.clone(),
            agreement.clone(),
            device.clone(),
        )
    };
    let portable_key = |stamp, expiry| {
        generate_portable_key(KeyShape::V6Curve25519, keys::user("Alice"), expiry, stamp)
    };

    let asked = device.signs();
    for (stamp, expiry) in refused {
        assert_eq!(
            portable_key(stamp, expiry).unwrap_err(),
            EngineError::TimeOutOfRange,
            "{stamp} {expiry:?}"
        );
        assert_eq!(
            device_key(stamp, expiry).unwrap_err(),
            EngineError::TimeOutOfRange,
            "{stamp} {expiry:?}"
        );
    }
    assert_eq!(device.signs(), asked);

    assert!(portable_key(last - DAY, Expiry::After { days: 1 }).is_ok());
    assert!(device_key(last - DAY, Expiry::After { days: 1 }).is_ok());

    assert_eq!(
        portable_key(STAMP, Expiry::After { days: 0 }).unwrap_err(),
        EngineError::Internal
    );
    assert_eq!(
        device_key(STAMP, Expiry::After { days: 0 }).unwrap_err(),
        EngineError::Internal
    );
}

/// A later direct-key self-signature, as an expiry change makes one.
fn with_later_self_signature(cert: Cert, signer: &mut dyn Signer, later: SystemTime) -> Cert {
    let direct = cert
        .primary_key()
        .self_signatures()
        .find(|signature| signature.typ() == SignatureType::DirectKey)
        .unwrap()
        .clone();
    let later_direct = SignatureBuilder::from(direct)
        .set_signature_creation_time(later)
        .unwrap()
        .sign_direct_key(signer, cert.primary_key().key())
        .unwrap();
    cert.insert_packets(Some(later_direct)).unwrap().0
}

/// E22. The prepared revocation carries the key's creation time and states no
/// specific reason, so it revokes also after a later self-signature, which
/// becomes the newest self-signature.
#[test]
fn e22_prepared_revocation_still_revokes_after_a_later_self_signature() {
    let later = UNIX_EPOCH + Duration::from_secs(STAMP + 30 * DAY);
    let mut cases: Vec<(String, NewKey, Cert)> = Vec::new();
    for shape in [KeyShape::V4Curve25519, KeyShape::V6Curve25519] {
        let key = keys::new_key(shape, "Alice");
        let tsk = Cert::from_bytes(&keys::tsk(&key)).unwrap();
        let mut signer = tsk
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let cert = Cert::from_bytes(&key.certificate).unwrap();
        let cert = with_later_self_signature(cert, &mut signer, later);
        cases.push((format!("portable {shape:?}"), key, cert));
    }
    for shape in [KeyShape::V4P256, KeyShape::V6P256] {
        let (key, device) = device::device_key(shape, "Alice");
        let cert = Cert::from_bytes(&key.certificate).unwrap();
        let mut signer = StandInSigner::new(&cert, &device);
        let cert = with_later_self_signature(cert, &mut signer, later);
        cases.push((format!("device-bound {shape:?}"), key, cert));
    }

    for (label, key, cert) in cases {
        let info = inspect_certificate(cert.to_vec().unwrap()).unwrap();
        assert_eq!(
            (info.newest_self_signature, info.status),
            (unix(later), KeyStatus::Valid),
            "{label}"
        );
        let revocation = Packet::from_bytes(&key.revocation).unwrap();
        let revoked = cert.insert_packets(Some(revocation)).unwrap().0;
        assert_eq!(
            inspect_certificate(revoked.to_vec().unwrap())
                .unwrap()
                .status,
            KeyStatus::Revoked,
            "{label}"
        );
    }
}
