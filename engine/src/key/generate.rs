//! Making a key, born with its revocation certificate.
//!
//! The caller gives the key's stamp, and the engine writes it into everything
//! it makes with the key: every key packet, every signature with its
//! back-signature, and the revocation. It reads no clock for these. An expiry
//! is a period counted from the stamp.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpgp::cert::{CertBuilder, CertRevocationBuilder, CipherSuite};
use openpgp::crypto::{Signer, mpi};
use openpgp::packet::key::{Key4, Key6, PrimaryRole, PublicParts, SubordinateRole};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::{Key, Signature, UserID};
use openpgp::serialize::SerializeInto as _;
use openpgp::types::{
    Curve, Features, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, ReasonForRevocation,
    SignatureType, SymmetricAlgorithm,
};
use openpgp::{Cert, Packet, Profile};
use sequoia_openpgp as openpgp;

use super::device::DeviceKey;
use super::material;
use crate::custody::{self, CompositeSigner, Halves, P256Signer, Tier};
use crate::error::{self, contained};
use crate::{EngineError, Expiry, KeyShape, NewKey, UserId};

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// Make a portable key in one of the three Curve shapes or the two
/// post-quantum shapes, at `stamp`. The P-256 shapes are device-bound only:
/// `Unsupported`.
///
/// A stamp, or a stamp plus the expiry, beyond OpenPGP's 32-bit time is
/// `TimeOutOfRange`; an expiry of zero days is `Internal`.
#[uniffi::export]
pub fn generate_portable_key(
    shape: KeyShape,
    user: UserId,
    expiry: Expiry,
    stamp: u64,
) -> Result<NewKey, EngineError> {
    contained(|| {
        let (suite, profile) = match shape {
            KeyShape::V4Curve25519 => (CipherSuite::Cv25519, Profile::RFC4880),
            KeyShape::V6Curve25519 => (CipherSuite::Cv25519, Profile::RFC9580),
            KeyShape::V6Curve448 => (CipherSuite::Cv448, Profile::RFC9580),
            KeyShape::V6MlDsa65 => (CipherSuite::MLDSA65_Ed25519, Profile::RFC9580),
            KeyShape::V6MlDsa87 => (CipherSuite::MLDSA87_Ed448, Profile::RFC9580),
            KeyShape::V4P256 | KeyShape::V6P256 => return Err(EngineError::Unsupported),
        };
        let (creation, validity) = times(stamp, expiry)?;

        // The builder writes the creation time into every key, signature,
        // back-signature and the revocation; it reads the clock only without
        // one. The revocation states no specific reason, so applying it is
        // final.
        let (cert, revocation) = CertBuilder::general_purpose(Some(user_id(&user)))
            .set_cipher_suite(suite)
            .set_profile(profile)
            .map_err(EngineError::internal)?
            .set_creation_time(creation)
            // Unconditional: `general_purpose` seeds a validity period of its own.
            .set_validity_period(validity)
            .set_features(features(shape))
            .map_err(EngineError::internal)?
            .generate()
            .map_err(EngineError::internal)?;

        let secret = material::write_secret_keys(&cert)?;
        Ok(NewKey {
            certificate: cert.to_vec().map_err(EngineError::internal)?,
            secret: Some(secret.to_vec()),
            revocation: Packet::from(revocation)
                .to_vec()
                .map_err(EngineError::internal)?,
        })
    })
}

/// Make a device-bound key in one of the two P-256 shapes or the two
/// post-quantum shapes, at `stamp`, around the public keys of the device's two
/// keys. The device signs every self-signature and the revocation, and each
/// signature is verified before it is used. The Curve shapes are portable
/// only: `Unsupported`.
///
/// For a post-quantum key the engine makes the classical halves; they are
/// `NewKey::secret`, which the vault seals. A P-256 key has none.
///
/// The public keys are what the Secure Enclave made: two distinct X9.63 points
/// on P-256, or a raw ML-DSA and ML-KEM key of the shape's sizes. Anything
/// else is `Internal`. Times are refused as by `generate_portable_key`. A
/// failure of the device is `Cancelled`, `DeviceNotAuthenticated` or
/// `DeviceFailed`.
#[uniffi::export]
pub fn generate_device_key(
    shape: KeyShape,
    user: UserId,
    expiry: Expiry,
    stamp: u64,
    signing_public_key: Vec<u8>,
    agreement_public_key: Vec<u8>,
    device: Arc<dyn DeviceKey>,
) -> Result<NewKey, EngineError> {
    contained(|| {
        let tier = match shape {
            KeyShape::V4P256 | KeyShape::V6P256 => None,
            KeyShape::V6MlDsa65 => Some(Tier::MlDsa65),
            KeyShape::V6MlDsa87 => Some(Tier::MlDsa87),
            KeyShape::V4Curve25519 | KeyShape::V6Curve25519 | KeyShape::V6Curve448 => {
                return Err(EngineError::Unsupported);
            }
        };
        let (creation, validity) = times(stamp, expiry)?;

        let (keys, halves) = match tier {
            None => (
                p256_keys(
                    shape == KeyShape::V4P256,
                    creation,
                    &signing_public_key,
                    &agreement_public_key,
                )?,
                None,
            ),
            Some(tier) => {
                let (halves, eddsa, ecdh) =
                    Halves::generate(tier).map_err(|_| EngineError::Internal)?;
                let keys = composite_keys(
                    tier,
                    creation,
                    (&eddsa, &signing_public_key),
                    (&ecdh, &agreement_public_key),
                )?;
                (keys, Some(halves))
            }
        };

        let signing = keys.primary.clone().role_into_unspecified();
        let (mut signer, hash): (Box<dyn Signer>, _) = match &halves {
            None => (
                Box::new(P256Signer::new(signing, device).ok_or(EngineError::Internal)?),
                HashAlgorithm::SHA256,
            ),
            Some(halves) => (
                Box::new(
                    CompositeSigner::new(signing, halves.tier(), halves.eddsa(), device)
                        .ok_or(EngineError::Internal)?,
                ),
                HashAlgorithm::SHA512,
            ),
        };
        let (cert, revocation) = assemble(
            keys,
            signer.as_mut(),
            &SelfSignatures {
                hash,
                creation,
                validity,
                features: features(shape),
                user: user_id(&user),
            },
        )?;

        Ok(NewKey {
            certificate: cert.to_vec().map_err(EngineError::internal)?,
            secret: halves.map(|halves| std::mem::take(&mut *halves.write())),
            revocation: Packet::from(revocation)
                .to_vec()
                .map_err(EngineError::internal)?,
        })
    })
}

/// The creation time of a key at `stamp`, and its validity period. The stamp
/// and its end must fit OpenPGP's 32-bit time. An expiry of zero days would
/// read as "never" in OpenPGP; no caller asks for it.
fn times(stamp: u64, expiry: Expiry) -> Result<(SystemTime, Option<Duration>), EngineError> {
    let period = match expiry {
        Expiry::Never => None,
        Expiry::After { days: 0 } => return Err(EngineError::Internal),
        Expiry::After { days } => Some(u64::from(days) * SECONDS_PER_DAY),
    };
    let end = stamp.checked_add(period.unwrap_or(0));
    if end.is_none_or(|end| end > u64::from(u32::MAX)) {
        return Err(EngineError::TimeOutOfRange);
    }
    Ok((
        UNIX_EPOCH + Duration::from_secs(stamp),
        period.map(Duration::from_secs),
    ))
}

/// The containers a key advertises. A Legacy key exists for GnuPG, which
/// cannot read SEIPDv2, so it advertises only SEIPDv1 and other
/// implementations write that to it.
fn features(shape: KeyShape) -> Features {
    match shape {
        KeyShape::V4Curve25519 | KeyShape::V4P256 => Features::empty().set_seipdv1(),
        _ => Features::sequoia(),
    }
}

fn user_id(user: &UserId) -> UserID {
    match &user.email {
        Some(email) => UserID::from(format!("{} <{email}>", user.name)),
        None => UserID::from(user.name.as_str()),
    }
}

/// The two keys of a device-bound certificate.
struct DeviceKeys {
    primary: Key<PublicParts, PrimaryRole>,
    subkey: Key<PublicParts, SubordinateRole>,
}

fn p256_keys(
    v4: bool,
    creation: SystemTime,
    signing: &[u8],
    agreement: &[u8],
) -> Result<DeviceKeys, EngineError> {
    if !custody::is_p256_point(signing)
        || !custody::is_p256_point(agreement)
        || signing == agreement
    {
        return Err(EngineError::Internal);
    }
    let primary = mpi::PublicKey::ECDSA {
        curve: Curve::NistP256,
        q: mpi::MPI::new(signing),
    };
    let subkey = mpi::PublicKey::ECDH {
        curve: Curve::NistP256,
        q: mpi::MPI::new(agreement),
        hash: HashAlgorithm::SHA256,
        sym: SymmetricAlgorithm::AES256,
    };
    let (primary, subkey): (
        Key<PublicParts, PrimaryRole>,
        Key<PublicParts, SubordinateRole>,
    ) = if v4 {
        (
            Key4::new(creation, PublicKeyAlgorithm::ECDSA, primary)
                .map_err(EngineError::internal)?
                .into(),
            Key4::new(creation, PublicKeyAlgorithm::ECDH, subkey)
                .map_err(EngineError::internal)?
                .into(),
        )
    } else {
        (
            Key6::new(creation, PublicKeyAlgorithm::ECDSA, primary)
                .map_err(EngineError::internal)?
                .into(),
            Key6::new(creation, PublicKeyAlgorithm::ECDH, subkey)
                .map_err(EngineError::internal)?
                .into(),
        )
    };
    Ok(DeviceKeys { primary, subkey })
}

/// FIPS 204 and FIPS 203 public-key sizes.
fn pq_key_lengths(tier: Tier) -> (usize, usize) {
    match tier {
        Tier::MlDsa65 => (1952, 1184),
        Tier::MlDsa87 => (2592, 1568),
    }
}

/// The keys of a post-quantum device-bound certificate, each from its
/// classical and its post-quantum public key.
fn composite_keys(
    tier: Tier,
    creation: SystemTime,
    (eddsa, mldsa): (&[u8], &[u8]),
    (ecdh, mlkem): (&[u8], &[u8]),
) -> Result<DeviceKeys, EngineError> {
    let (mldsa_length, mlkem_length) = pq_key_lengths(tier);
    if mldsa.len() != mldsa_length
        || mlkem.len() != mlkem_length
        || mldsa.iter().all(|byte| *byte == 0)
        || !mlkem_key_is_canonical(mlkem)
    {
        return Err(EngineError::Internal);
    }
    let primary = tier
        .signing_key(eddsa, mldsa)
        .ok_or(EngineError::Internal)?;
    let subkey = tier
        .agreement_key(ecdh, mlkem)
        .ok_or(EngineError::Internal)?;
    Ok(DeviceKeys {
        primary: Key6::new(creation, tier.signing_algorithm(), primary)
            .map_err(EngineError::internal)?
            .into(),
        subkey: Key6::new(creation, tier.agreement_algorithm(), subkey)
            .map_err(EngineError::internal)?
            .into(),
    })
}

/// The FIPS 203 check of an encapsulation key: every 12-bit coefficient packed
/// ahead of the 32-byte seed is below the modulus.
fn mlkem_key_is_canonical(key: &[u8]) -> bool {
    const Q: u16 = 3329;
    let Some(packed) = key.len().checked_sub(32).map(|length| &key[..length]) else {
        return false;
    };
    let (chunks, rest) = packed.as_chunks::<3>();
    rest.is_empty()
        && chunks.iter().all(|&[first, second, third]| {
            let low = u16::from(first) | (u16::from(second & 0x0F) << 8);
            let high = u16::from(second >> 4) | (u16::from(third) << 4);
            low < Q && high < Q
        })
}

/// What every self-signature of a device-bound certificate states. The
/// metadata is what `CertBuilder` writes for a portable key, so that the two
/// custodies give certificates of one form.
struct SelfSignatures {
    hash: HashAlgorithm,
    creation: SystemTime,
    validity: Option<Duration>,
    features: Features,
    user: UserID,
}

impl SelfSignatures {
    fn builder(&self, kind: SignatureType) -> openpgp::Result<SignatureBuilder> {
        SignatureBuilder::new(kind)
            .set_hash_algo(self.hash)
            .set_signature_creation_time(self.creation)
    }

    /// The primary key's metadata, on its direct-key signature and on the
    /// User ID's binding.
    fn primary(&self, kind: SignatureType) -> openpgp::Result<SignatureBuilder> {
        self.builder(kind)?
            .set_features(self.features.clone())?
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())?
            .set_key_validity_period(self.validity)?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])
    }
}

/// Self-sign a device-bound certificate and make its revocation, every
/// signature through `signer`.
fn assemble(
    keys: DeviceKeys,
    signer: &mut dyn Signer,
    signatures: &SelfSignatures,
) -> Result<(Cert, Signature), EngineError> {
    let built = |result: openpgp::Result<SignatureBuilder>| result.map_err(EngineError::internal);
    let signed = |result: openpgp::Result<Signature>| {
        result.map_err(|error| error::failed_operation(&error))
    };

    let cert =
        Cert::try_from(vec![Packet::from(keys.primary.clone())]).map_err(EngineError::internal)?;
    let direct = signed(
        built(signatures.primary(SignatureType::DirectKey))?
            .sign_direct_key(signer, keys.primary.parts_as_public()),
    )?;
    let user = signatures.user.clone();
    let user_binding = signed(
        user.bind(
            signer,
            &cert,
            built(
                signatures
                    .primary(SignatureType::PositiveCertification)
                    .and_then(|builder| builder.set_primary_userid(true)),
            )?,
        ),
    )?;
    let subkey_binding = signed(
        keys.subkey.bind(
            signer,
            &cert,
            built(
                signatures
                    .builder(SignatureType::SubkeyBinding)
                    .and_then(|builder| {
                        builder.set_key_flags(
                            KeyFlags::empty()
                                .set_transport_encryption()
                                .set_storage_encryption(),
                        )
                    })
                    .and_then(|builder| builder.set_key_validity_period(signatures.validity)),
            )?,
        ),
    )?;
    let (cert, _) = cert
        .insert_packets([
            Packet::from(direct),
            Packet::from(user),
            Packet::from(user_binding),
            Packet::from(keys.subkey),
            Packet::from(subkey_binding),
        ])
        .map_err(EngineError::internal)?;

    let revocation = signed(
        CertRevocationBuilder::new()
            .set_signature_creation_time(signatures.creation)
            .and_then(|builder| {
                builder.set_reason_for_revocation(ReasonForRevocation::Unspecified, b"Unspecified")
            })
            .map_err(EngineError::internal)?
            .build(signer, &cert, signatures.hash),
    )?;
    Ok((cert, revocation))
}
