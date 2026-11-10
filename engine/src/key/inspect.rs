//! What a certificate is: its real algorithms, its shape, its owner, its status.

use std::time::{SystemTime, UNIX_EPOCH};

use openpgp::cert::prelude::*;
use openpgp::crypto::mpi;
use openpgp::packet::key::{KeyParts, KeyRole};
use openpgp::types::{PublicKeyAlgorithm, RevocationStatus};
use sequoia_openpgp as openpgp;

use super::material;
use crate::error::contained;
use crate::message::recipients;
use crate::{
    Algorithm, AlgorithmKind, CertificateInfo, Curve, EngineError, KeyShape, KeyStatus, POLICY,
};

/// Describe a certificate, public or with secrets.
#[uniffi::export]
pub fn inspect_certificate(certificate: Vec<u8>) -> Result<CertificateInfo, EngineError> {
    contained(|| {
        let cert = material::certificate(&certificate)?;
        Ok(describe(&cert, SystemTime::now()))
    })
}

fn describe(cert: &Cert, now: SystemTime) -> CertificateInfo {
    let primary_key = cert.primary_key().key();
    let version = primary_key.version();
    let primary = algorithm(primary_key);
    let valid = cert.with_policy(&POLICY, now).ok();

    let status = match &valid {
        None => KeyStatus::Unusable,
        Some(valid) if matches!(valid.revocation_status(), RevocationStatus::Revoked(_)) => {
            KeyStatus::Revoked
        }
        Some(valid) if valid.alive().is_err() => KeyStatus::Expired,
        Some(_) => KeyStatus::Valid,
    };
    let encryption_keys: Vec<Algorithm> = valid
        .as_ref()
        .map(|valid| {
            encryption_keys(valid)
                .iter()
                .map(|key| algorithm(key.key()))
                .collect()
        })
        .unwrap_or_default();
    let encryption = encryption_keys.first().copied();
    let (name, email) = valid.as_ref().and_then(owner).unwrap_or((None, None));

    CertificateInfo {
        fingerprint: cert.fingerprint().to_hex().to_lowercase(),
        version,
        primary,
        encryption,
        shape: shape(version, primary, encryption),
        name,
        email,
        created: unix_seconds(primary_key.creation_time()),
        expires: valid
            .as_ref()
            .and_then(|valid| valid.primary_key().key_expiration_time())
            .map(unix_seconds),
        status,
        can_encrypt: valid.as_ref().is_some_and(recipients::accepts),
        quantum_safe: !encryption_keys.is_empty()
            && encryption_keys.iter().all(|encryption| {
                matches!(
                    encryption.kind,
                    AlgorithmKind::MlKem768X25519 | AlgorithmKind::MlKem1024X448
                )
            }),
        has_secret: cert.is_tsk(),
    }
}

/// The keys a message to this certificate is encrypted to: those `encrypt`
/// uses, else, for an expired or revoked certificate, those it would have used.
/// `encrypt` writes a recipient packet for each of them.
fn encryption_keys<'a>(
    valid: &'a ValidCert<'a>,
) -> Vec<ValidErasedKeyAmalgamation<'a, openpgp::packet::key::PublicParts>> {
    let usable: Vec<_> = recipients::encryption_keys(valid).collect();
    if usable.is_empty() {
        valid
            .keys()
            .supported()
            .for_transport_encryption()
            .collect()
    } else {
        usable
    }
}

/// The name and email of the primary User ID among those with a valid binding
/// that are not revoked.
fn owner(valid: &ValidCert) -> Option<(Option<String>, Option<String>)> {
    let not_revoked = |user_id: &ValidUserIDAmalgamation| {
        !matches!(user_id.revocation_status(), RevocationStatus::Revoked(_))
    };
    let user_id = valid
        .primary_userid()
        .ok()
        .filter(not_revoked)
        .or_else(|| valid.userids().find(not_revoked))?;
    let user_id = user_id.userid();
    match (user_id.name(), user_id.email()) {
        (Ok(name), Ok(email)) => Some((name.map(str::to_owned), email.map(str::to_owned))),
        // Not in name-and-address form: the whole User ID is the name.
        _ => Some((
            Some(String::from_utf8_lossy(user_id.value()).into_owned()),
            None,
        )),
    }
}

fn shape(version: u8, primary: Algorithm, encryption: Option<Algorithm>) -> Option<KeyShape> {
    use AlgorithmKind as A;
    let encryption = encryption?;
    let shape = match (
        version,
        primary.kind,
        primary.curve,
        encryption.kind,
        encryption.curve,
    ) {
        (4, A::EdDsaLegacy, Curve::Ed25519, A::Ecdh, Curve::Curve25519) => KeyShape::V4Curve25519,
        (4, A::Ecdsa, Curve::NistP256, A::Ecdh, Curve::NistP256) => KeyShape::V4P256,
        (6, A::Ed25519, _, A::X25519, _) => KeyShape::V6Curve25519,
        (6, A::Ecdsa, Curve::NistP256, A::Ecdh, Curve::NistP256) => KeyShape::V6P256,
        (6, A::Ed448, _, A::X448, _) => KeyShape::V6Curve448,
        (6, A::MlDsa65Ed25519, _, A::MlKem768X25519, _) => KeyShape::V6MlDsa65,
        (6, A::MlDsa87Ed448, _, A::MlKem1024X448, _) => KeyShape::V6MlDsa87,
        _ => return None,
    };
    Some(shape)
}

fn algorithm<P: KeyParts, R: KeyRole>(key: &openpgp::packet::Key<P, R>) -> Algorithm {
    use PublicKeyAlgorithm as P;
    #[allow(deprecated)]
    let kind = match key.pk_algo() {
        P::RSAEncryptSign | P::RSAEncrypt | P::RSASign => AlgorithmKind::Rsa,
        P::DSA => AlgorithmKind::Dsa,
        P::ElGamalEncrypt | P::ElGamalEncryptSign => AlgorithmKind::ElGamal,
        P::EdDSA => AlgorithmKind::EdDsaLegacy,
        P::ECDSA => AlgorithmKind::Ecdsa,
        P::ECDH => AlgorithmKind::Ecdh,
        P::Ed25519 => AlgorithmKind::Ed25519,
        P::X25519 => AlgorithmKind::X25519,
        P::Ed448 => AlgorithmKind::Ed448,
        P::X448 => AlgorithmKind::X448,
        P::MLDSA65_Ed25519 => AlgorithmKind::MlDsa65Ed25519,
        P::MLDSA87_Ed448 => AlgorithmKind::MlDsa87Ed448,
        P::MLKEM768_X25519 => AlgorithmKind::MlKem768X25519,
        P::MLKEM1024_X448 => AlgorithmKind::MlKem1024X448,
        _ => AlgorithmKind::Unknown,
    };
    let curve = match key.mpis() {
        mpi::PublicKey::EdDSA { curve, .. }
        | mpi::PublicKey::ECDSA { curve, .. }
        | mpi::PublicKey::ECDH { curve, .. } => curve_of(curve),
        _ => Curve::None,
    };
    let bits = match kind {
        AlgorithmKind::Rsa | AlgorithmKind::Dsa | AlgorithmKind::ElGamal => key
            .mpis()
            .bits()
            .and_then(|bits| u32::try_from(bits).ok())
            .unwrap_or(0),
        _ => 0,
    };
    Algorithm { kind, curve, bits }
}

fn curve_of(curve: &openpgp::types::Curve) -> Curve {
    use openpgp::types::Curve as C;
    match curve {
        C::Ed25519 => Curve::Ed25519,
        C::Cv25519 => Curve::Curve25519,
        C::NistP256 => Curve::NistP256,
        C::NistP384 => Curve::NistP384,
        C::NistP521 => Curve::NistP521,
        C::BrainpoolP256 => Curve::BrainpoolP256,
        C::BrainpoolP384 => Curve::BrainpoolP384,
        C::BrainpoolP512 => Curve::BrainpoolP512,
        _ => Curve::Unknown,
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
