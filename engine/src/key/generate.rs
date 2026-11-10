//! Making a portable key, born with its revocation certificate.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpgp::Packet;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::serialize::SerializeInto as _;
use openpgp::types::Features;
use openpgp::{Profile, packet::UserID};
use sequoia_openpgp as openpgp;

use super::material;
use crate::error::contained;
use crate::{EngineError, Expiry, KeyShape, NewKey, UserId};

/// How far a new key's creation time lies in the past, so that a device whose
/// clock is a little behind still sees the key as valid. Sequoia's own
/// default, made explicit because the expiry is computed from it.
const BACKDATE: Duration = Duration::from_secs(60);

/// Make a portable key in one of the three Curve shapes or the two
/// post-quantum shapes. The P-256 shapes are device-bound only: `Unsupported`.
/// An expiry that is not in the future is `Internal`.
#[uniffi::export]
pub fn generate_portable_key(
    shape: KeyShape,
    user: UserId,
    expiry: Expiry,
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

        let creation = whole_seconds(SystemTime::now()) - BACKDATE;
        let validity = match expiry {
            Expiry::Never => None,
            Expiry::At { unix_seconds } => {
                let at = UNIX_EPOCH + Duration::from_secs(unix_seconds);
                match at.duration_since(creation + BACKDATE) {
                    Ok(remaining) if !remaining.is_zero() => Some(remaining + BACKDATE),
                    _ => return Err(EngineError::Internal),
                }
            }
        };

        let mut builder = CertBuilder::general_purpose(Some(user_id(&user)))
            .set_cipher_suite(suite)
            .set_profile(profile)
            .map_err(EngineError::internal)?
            .set_creation_time(creation)
            // Unconditional: `general_purpose` seeds a validity period of its own.
            .set_validity_period(validity);
        if shape == KeyShape::V4Curve25519 {
            // Sequoia advertises SEIPDv2 for every key it makes. A Legacy key
            // exists for GnuPG, which cannot read SEIPDv2, so it advertises only
            // SEIPDv1 and other implementations write that to it.
            builder = builder
                .set_features(Features::empty().set_seipdv1())
                .map_err(EngineError::internal)?;
        }
        let (cert, revocation) = builder.generate().map_err(EngineError::internal)?;

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

fn user_id(user: &UserId) -> UserID {
    match &user.email {
        Some(email) => UserID::from(format!("{} <{email}>", user.name)),
        None => UserID::from(user.name.as_str()),
    }
}

fn whole_seconds(time: SystemTime) -> SystemTime {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    UNIX_EPOCH + Duration::from_secs(seconds)
}
