//! Rules E10, E11 and E12: a secret must belong to its certificate, a name
//! comes only from a validly bound User ID, and a shape is reported exactly.

mod common;

use common::{device, keys};
use cypher_engine::{
    Algorithm, AlgorithmKind, Curve, EngineError, Expiry, KeyShape, PrivateKey,
    generate_portable_key, inspect_certificate,
};
use openpgp::cert::CipherSuite;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use openpgp::{Cert, Packet, PacketPile, Profile};
use sequoia_openpgp as openpgp;

fn algorithm(kind: AlgorithmKind, curve: Curve, bits: u32) -> Algorithm {
    Algorithm { kind, curve, bits }
}

/// E10. A secret of another certificate is refused: as a whole, and when only
/// the primary key's or one subkey's secret is foreign.
#[test]
fn e10_secret_of_another_certificate_is_refused() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let bob = keys::new_key(KeyShape::V6Curve25519, "Bob");
    assert_eq!(
        PrivateKey::portable(alice.certificate.clone(), bob.secret.as_deref().unwrap())
            .unwrap_err(),
        EngineError::KeyMismatch
    );

    let packets = |key: &cypher_engine::NewKey| -> Vec<Packet> {
        PacketPile::from_bytes(key.secret.as_ref().unwrap())
            .unwrap()
            .into_children()
            .collect()
    };
    let (alice_secrets, bob_secrets) = (packets(&alice), packets(&bob));
    for foreign in [0, 2] {
        let mut mixed = Vec::new();
        for (index, packet) in alice_secrets.iter().enumerate() {
            let packet = if index == foreign {
                &bob_secrets[index]
            } else {
                packet
            };
            mixed.extend_from_slice(&packet.to_vec().unwrap());
        }
        assert_eq!(
            PrivateKey::portable(alice.certificate.clone(), &mixed).unwrap_err(),
            EngineError::KeyMismatch,
            "foreign secret at {foreign}"
        );
    }
}

/// E11. A User ID without a valid binding gives no name: neither one added
/// without a signature beside a valid one, nor one that carries another User
/// ID's signature.
#[test]
fn e11_name_only_from_a_validly_bound_user_id() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let cert = Cert::from_bytes(&alice.certificate).unwrap();

    let mallory = Packet::from(openpgp::packet::UserID::from(
        "Mallory <mallory@example.org>",
    ));
    let (with_unbound, _) = cert.clone().insert_packets(Some(mallory.clone())).unwrap();
    let info = inspect_certificate(with_unbound.to_vec().unwrap()).unwrap();
    assert_eq!(info.name.as_deref(), Some("Alice"));
    assert_eq!(info.email.as_deref(), Some("alice@example.org"));

    let swapped: Vec<Packet> = cert
        .into_packets()
        .map(|packet| match packet {
            Packet::UserID(_) => mallory.clone(),
            other => other,
        })
        .collect();
    let mut certificate = Vec::new();
    for packet in swapped {
        certificate.extend_from_slice(&packet.to_vec().unwrap());
    }
    let info = inspect_certificate(certificate).unwrap();
    assert_eq!((info.name, info.email), (None, None));
}

/// E12. Each shape the engine makes, in either custody, is reported as itself,
/// with its real algorithms, and its certificate holds no secret. A P-256 key
/// never shares a shape with a Curve25519 key. A key that matches none of ours
/// has no shape and still reports its algorithm and size; so does a key with
/// one more encryption key of another kind.
#[test]
fn e12_shape_is_reported_exactly() {
    use AlgorithmKind as A;
    let generated = [
        (
            KeyShape::V4Curve25519,
            4,
            algorithm(A::EdDsaLegacy, Curve::Ed25519, 0),
            algorithm(A::Ecdh, Curve::Curve25519, 0),
        ),
        (
            KeyShape::V6Curve25519,
            6,
            algorithm(A::Ed25519, Curve::None, 0),
            algorithm(A::X25519, Curve::None, 0),
        ),
        (
            KeyShape::V6Curve448,
            6,
            algorithm(A::Ed448, Curve::None, 0),
            algorithm(A::X448, Curve::None, 0),
        ),
        (
            KeyShape::V6MlDsa65,
            6,
            algorithm(A::MlDsa65Ed25519, Curve::None, 0),
            algorithm(A::MlKem768X25519, Curve::None, 0),
        ),
        (
            KeyShape::V6MlDsa87,
            6,
            algorithm(A::MlDsa87Ed448, Curve::None, 0),
            algorithm(A::MlKem1024X448, Curve::None, 0),
        ),
    ];
    for (shape, version, primary, encryption) in generated {
        let info = inspect_certificate(keys::new_key(shape, "Alice").certificate).unwrap();
        assert_eq!(
            (
                info.shape,
                info.version,
                info.primary,
                info.encryption,
                info.has_secret
            ),
            (Some(shape), version, primary, Some(encryption), false)
        );
    }

    let foreign = [
        (
            CipherSuite::P256,
            Profile::RFC4880,
            Some(KeyShape::V4P256),
            algorithm(A::Ecdsa, Curve::NistP256, 0),
            algorithm(A::Ecdh, Curve::NistP256, 0),
        ),
        (
            CipherSuite::P256,
            Profile::RFC9580,
            Some(KeyShape::V6P256),
            algorithm(A::Ecdsa, Curve::NistP256, 0),
            algorithm(A::Ecdh, Curve::NistP256, 0),
        ),
        (
            CipherSuite::P384,
            Profile::RFC4880,
            None,
            algorithm(A::Ecdsa, Curve::NistP384, 0),
            algorithm(A::Ecdh, Curve::NistP384, 0),
        ),
        (
            CipherSuite::RSA3k,
            Profile::RFC4880,
            None,
            algorithm(A::Rsa, Curve::None, 3072),
            algorithm(A::Rsa, Curve::None, 3072),
        ),
    ];
    for (suite, profile, shape, primary, encryption) in foreign {
        let (certificate, _) = keys::split(&keys::foreign_cert(suite, profile));
        let info = inspect_certificate(certificate).unwrap();
        assert_eq!(
            (info.shape, info.primary, info.encryption),
            (shape, primary, Some(encryption))
        );
    }

    for shape in [KeyShape::V4P256, KeyShape::V6P256] {
        assert_eq!(
            generate_portable_key(shape, keys::user("Alice"), Expiry::Never, keys::STAMP)
                .unwrap_err(),
            EngineError::Unsupported
        );
    }

    let device_bound = [
        (
            KeyShape::V4P256,
            4,
            algorithm(A::Ecdsa, Curve::NistP256, 0),
            algorithm(A::Ecdh, Curve::NistP256, 0),
        ),
        (
            KeyShape::V6P256,
            6,
            algorithm(A::Ecdsa, Curve::NistP256, 0),
            algorithm(A::Ecdh, Curve::NistP256, 0),
        ),
        (
            KeyShape::V6MlDsa65,
            6,
            algorithm(A::MlDsa65Ed25519, Curve::None, 0),
            algorithm(A::MlKem768X25519, Curve::None, 0),
        ),
        (
            KeyShape::V6MlDsa87,
            6,
            algorithm(A::MlDsa87Ed448, Curve::None, 0),
            algorithm(A::MlKem1024X448, Curve::None, 0),
        ),
    ];
    for (shape, version, primary, encryption) in device_bound {
        let (key, _) = device::device_key(shape, "Alice");
        let info = inspect_certificate(key.certificate).unwrap();
        assert_eq!(
            (
                info.shape,
                info.version,
                info.primary,
                info.encryption,
                info.has_secret
            ),
            (Some(shape), version, primary, Some(encryption), false)
        );
    }

    // A post-quantum key with one more, classical, encryption key is none of
    // ours, whichever of the two comes first.
    let mixed = |primary: CipherSuite, extra: CipherSuite| {
        let (cert, _) = openpgp::cert::CertBuilder::general_purpose(Some("Mixed"))
            .set_cipher_suite(primary)
            .set_profile(Profile::RFC9580)
            .unwrap()
            .add_subkey(
                openpgp::types::KeyFlags::empty().set_transport_encryption(),
                None,
                extra,
            )
            .generate()
            .unwrap();
        keys::split(&cert).0
    };
    for (primary, extra) in [
        (CipherSuite::MLDSA65_Ed25519, CipherSuite::Cv25519),
        (CipherSuite::Cv25519, CipherSuite::MLDSA65_Ed25519),
    ] {
        let info = inspect_certificate(mixed(primary, extra)).unwrap();
        assert_eq!(info.shape, None, "{primary:?} with {extra:?}");
    }
}

/// The name and email come back as given, also without an email and in
/// Chinese.
#[test]
fn generated_key_names_its_owner() {
    let cases = [
        ("Alice", Some("alice@example.org")),
        ("Alice", None),
        ("张三", Some("zhangsan@example.org")),
    ];
    for (name, email) in cases {
        let user = cypher_engine::UserId {
            name: name.to_owned(),
            email: email.map(str::to_owned),
        };
        let key = generate_portable_key(KeyShape::V6Curve25519, user, Expiry::Never, keys::STAMP)
            .unwrap();
        let info = inspect_certificate(key.certificate).unwrap();
        assert_eq!(
            (info.name.as_deref(), info.email.as_deref()),
            (Some(name), email)
        );
    }
}

/// A certificate that is shared is armored without the secret keys it may
/// carry.
#[test]
fn armored_certificate_holds_no_secret() {
    let alice = keys::new_key(KeyShape::V6Curve25519, "Alice");
    let with_secrets = keys::tsk(&alice);
    assert!(
        inspect_certificate(with_secrets.clone())
            .unwrap()
            .has_secret
    );
    let armored =
        cypher_engine::armor(cypher_engine::ArmorKind::Certificate, with_secrets).unwrap();
    let info = inspect_certificate(armored.into_bytes()).unwrap();
    assert_eq!(
        (info.has_secret, info.shape),
        (false, Some(KeyShape::V6Curve25519))
    );
}

/// Certifications of a User ID by other keys are dropped when a certificate is
/// read: a key with more of them than the packet bound can be added, its name
/// still comes from its own binding, and what the engine writes back carries
/// none of them.
#[test]
fn certifications_by_others_are_dropped() {
    use openpgp::packet::signature::SignatureBuilder;
    use openpgp::types::SignatureType;
    use std::time::{Duration, SystemTime};

    let alice =
        Cert::from_bytes(&keys::new_key(KeyShape::V6Curve25519, "Alice").certificate).unwrap();
    let bob = Cert::from_bytes(&keys::tsk(&keys::new_key(KeyShape::V6Curve25519, "Bob"))).unwrap();
    let mut certifier = bob
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let user_id = alice.userids().next().unwrap().userid().clone();
    let start = SystemTime::now() - Duration::from_secs(3600);
    let certifications: Vec<Packet> = (0..1100)
        .map(|second| {
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(start + Duration::from_secs(second))
                .unwrap()
                .sign_userid_binding(&mut certifier, alice.primary_key().key(), &user_id)
                .unwrap()
                .into()
        })
        .collect();
    let fingerprint = alice.fingerprint();
    let (certified, _) = alice.insert_packets(certifications).unwrap();
    let certificate = certified.to_vec().unwrap();
    assert!(
        PacketPile::from_bytes(&certificate)
            .unwrap()
            .children()
            .count()
            > 1024
    );

    let info = inspect_certificate(certificate.clone()).unwrap();
    assert_eq!(info.name.as_deref(), Some("Alice"));
    let written = cypher_engine::armor(cypher_engine::ArmorKind::Certificate, certificate).unwrap();
    let written = Cert::from_bytes(written.as_bytes()).unwrap();
    let kept: usize = written
        .userids()
        .map(|user_id| user_id.certifications().count())
        .sum();
    assert_eq!(kept, 0);
    assert_eq!(written.fingerprint(), fingerprint);
}
