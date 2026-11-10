//! Keys for tests: made by the engine, or built with Sequoia directly where the
//! engine cannot make them yet (expired and revoked keys, RSA and P-256).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use cypher_engine::{Expiry, KeyShape, NewKey, PrivateKey, UserId, generate_portable_key};
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::serialize::{Serialize, SerializeInto};
use openpgp::{Cert, Packet, Profile};
use sequoia_openpgp as openpgp;

pub const PLAINTEXT: &[u8] = b"Meet me at the old harbour at nine.";

pub fn user(name: &str) -> UserId {
    UserId {
        name: name.to_owned(),
        email: Some(format!("{}@example.org", name.to_lowercase())),
    }
}

/// A portable key made by the engine.
pub fn new_key(shape: KeyShape, name: &str) -> NewKey {
    generate_portable_key(shape, user(name), Expiry::Never).expect("generate a portable key")
}

/// The handle for a key made by the engine.
pub fn handle(key: &NewKey) -> Arc<PrivateKey> {
    PrivateKey::portable(
        key.certificate.clone(),
        key.secret.clone().expect("a portable secret"),
    )
    .expect("build the portable handle")
}

/// The handle for a certificate with secrets built by Sequoia.
pub fn handle_of(cert: &Cert) -> Arc<PrivateKey> {
    let (certificate, secret) = split(cert);
    PrivateKey::portable(certificate, secret).expect("build the portable handle")
}

/// A certificate with secrets, as the stored certificate and the portable
/// secret in the engine's format: the secret key packets, primary first.
pub fn split(cert: &Cert) -> (Vec<u8>, Vec<u8>) {
    let mut secret = Vec::new();
    for key in cert.keys().secret() {
        let packet = if key.primary() {
            Packet::SecretKey(key.key().clone().role_into_primary())
        } else {
            Packet::SecretSubkey(key.key().clone().role_into_subordinate())
        };
        packet.serialize(&mut secret).unwrap();
    }
    (cert.to_vec().unwrap(), secret)
}

/// The engine's certificate joined with its secret keys, as gpg and sq import it.
pub fn tsk(key: &NewKey) -> Vec<u8> {
    let cert = Cert::from_bytes(&key.certificate).unwrap();
    let secrets = openpgp::PacketPile::from_bytes(key.secret.as_ref().unwrap()).unwrap();
    let (cert, _) = cert.insert_packets(secrets.into_children()).unwrap();
    assert!(cert.is_tsk());
    cert.as_tsk().armored().to_vec().unwrap()
}

pub fn armored_certificate(certificate: &[u8]) -> Vec<u8> {
    Cert::from_bytes(certificate)
        .unwrap()
        .armored()
        .to_vec()
        .unwrap()
}

/// The certificate of an engine key with the key's own revocation applied.
pub fn revoked(key: &NewKey) -> Vec<u8> {
    let cert = Cert::from_bytes(&key.certificate).unwrap();
    let revocation = Packet::from_bytes(&key.revocation).unwrap();
    let (cert, _) = cert.insert_packets(Some(revocation)).unwrap();
    cert.to_vec().unwrap()
}

/// When `expired_cert` was created and when it expired: two days and one day ago.
pub fn expired_window() -> (SystemTime, SystemTime) {
    let day = Duration::from_secs(24 * 60 * 60);
    let created = SystemTime::now() - 2 * day;
    (created, created + day)
}

/// A v6 Curve25519 certificate with secrets that expired a day ago.
pub fn expired_cert(name: &str) -> Cert {
    let (created, _) = expired_window();
    CertBuilder::general_purpose(Some(format!(
        "{name} <{}@example.org>",
        name.to_lowercase()
    )))
    .set_cipher_suite(CipherSuite::Cv25519)
    .set_profile(Profile::RFC9580)
    .unwrap()
    .set_creation_time(created)
    .set_validity_period(Duration::from_secs(24 * 60 * 60))
    .generate()
    .unwrap()
    .0
}

/// A certificate with secrets in a cipher suite the engine does not make.
pub fn foreign_cert(suite: CipherSuite, profile: Profile) -> Cert {
    CertBuilder::general_purpose(Some("Foreign <foreign@example.org>"))
        .set_cipher_suite(suite)
        .set_profile(profile)
        .unwrap()
        .generate()
        .unwrap()
        .0
}
