//! Device-bound keys: the callback Swift implements over the Secure Enclave,
//! the shape of a device-bound certificate, and the public keys the device's
//! keys must match.

use openpgp::cert::prelude::*;
use openpgp::crypto::mpi;
use openpgp::packet::Key;
use openpgp::packet::key::{PublicParts, UnspecifiedRole};
use openpgp::types::Curve;
use sequoia_openpgp as openpgp;

use super::material;
use crate::custody::{self, Tier};
use crate::error::contained;
use crate::{DeviceKeySlots, EngineError};

/// The private half of a device-bound key: its signing key and its
/// key-agreement key in the Secure Enclave. Swift implements it.
///
/// The engine calls it on the thread of the call that triggered it, and the
/// core holds the approval for the whole operation. Each call performs one
/// primitive, and the engine checks every answer.
#[uniffi::export(foreign)]
pub trait DeviceKey: Send + Sync {
    /// P-256: a SHA-256 digest in, r‖s (64 bytes) out. ML-DSA: the signature
    /// digest in, the raw signature out.
    fn sign(&self, input: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError>;
    /// P-256: the sender's ephemeral point in. ML-KEM: the ciphertext in.
    /// Both: the 32-byte shared secret out.
    fn agree(&self, input: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError>;
}

/// Why the device gave no answer. The operation stops with `Cancelled`,
/// `DeviceNotAuthenticated` or `DeviceFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum DeviceKeyError {
    #[error("cancelled")]
    Cancelled,
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("failed")]
    Failed,
}

/// Any other error thrown in Swift is a failure of the device. Without this,
/// UniFFI turns it into a panic.
impl From<uniffi::UnexpectedUniFFICallbackError> for DeviceKeyError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        DeviceKeyError::Failed
    }
}

pub(crate) type PublicKey = Key<PublicParts, UnspecifiedRole>;

/// A device-bound certificate: a primary key that certifies and signs, and
/// exactly one subkey, its key-agreement key, as `generate_device_key` makes
/// them.
pub(crate) struct DeviceLayout {
    /// `None` for P-256, which has no classical halves.
    pub(crate) tier: Option<Tier>,
    pub(crate) signing: PublicKey,
    pub(crate) agreement: PublicKey,
}

/// The layout of a device-bound certificate. A certificate of any other shape
/// is `Unsupported`.
pub(crate) fn layout(cert: &Cert) -> Result<DeviceLayout, EngineError> {
    let mut subkeys = cert.keys().subkeys();
    let (Some(agreement), None) = (subkeys.next(), subkeys.next()) else {
        return Err(EngineError::Unsupported);
    };
    let signing = cert.primary_key().key().clone().role_into_unspecified();
    let agreement = agreement.key().clone().role_into_unspecified();
    let tier = match (signing.mpis(), agreement.mpis()) {
        (
            mpi::PublicKey::ECDSA {
                curve: Curve::NistP256,
                q: signing_point,
            },
            mpi::PublicKey::ECDH {
                curve: Curve::NistP256,
                q: agreement_point,
                ..
            },
        ) if signing.version() == agreement.version()
            && custody::is_p256_point(signing_point.value())
            && custody::is_p256_point(agreement_point.value()) =>
        {
            None
        }
        _ => {
            let tier = Tier::of_signing_key(&signing).ok_or(EngineError::Unsupported)?;
            if signing.version() != 6 || agreement.pk_algo() != tier.agreement_algorithm() {
                return Err(EngineError::Unsupported);
            }
            Some(tier)
        }
    };
    Ok(DeviceLayout {
        tier,
        signing,
        agreement,
    })
}

impl DeviceLayout {
    /// The public keys of the two device keys, as the Secure Enclave states
    /// them: X9.63 points for P-256, the raw ML-DSA and ML-KEM keys for the
    /// post-quantum families.
    fn slots(&self) -> Result<DeviceKeySlots, EngineError> {
        let (signing, agreement) = match (self.tier, self.signing.mpis(), self.agreement.mpis()) {
            (None, mpi::PublicKey::ECDSA { q: s, .. }, mpi::PublicKey::ECDH { q: a, .. }) => {
                (s.value().to_vec(), a.value().to_vec())
            }
            (Some(tier), _, _) => {
                let (_, mldsa) = tier
                    .signing_halves(&self.signing)
                    .ok_or(EngineError::Internal)?;
                let (_, mlkem) = tier
                    .agreement_halves(&self.agreement)
                    .ok_or(EngineError::Internal)?;
                (mldsa.to_vec(), mlkem.to_vec())
            }
            _ => return Err(EngineError::Internal),
        };
        Ok(DeviceKeySlots {
            signing_public_key: signing,
            agreement_public_key: agreement,
        })
    }
}

/// The public keys that the device's two keys must have for this certificate.
/// A certificate that is not one of the four device-bound shapes is
/// `Unsupported`.
#[uniffi::export]
pub fn device_key_slots(certificate: Vec<u8>) -> Result<DeviceKeySlots, EngineError> {
    contained(|| layout(&material::certificate(&certificate)?)?.slots())
}
