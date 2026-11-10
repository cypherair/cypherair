//! Device custody: the signers and decryptors for keys whose private part
//! stays in the Secure Enclave, behind the `DeviceKey` callback.
//!
//! The device performs exactly one primitive per call: a P-256 signature or
//! key agreement, an ML-DSA signature, or an ML-KEM decapsulation. Everything
//! OpenPGP defines around it stays here: the classical halves of a composite
//! key, the KEM combiner, the key unwrap, and the check of every signature the
//! device makes before it is released.
//!
//! A decryptor decides what is not for its key before it asks the device: a
//! ciphertext of another shape, a P-256 point off the curve, a classical point
//! that gives no shared secret. Such a packet fails as Sequoia expects, and the
//! next is tried. A failure of the device itself is recorded, and the handle
//! stops the operation with it. A signer's failure of the device crosses
//! Sequoia as an `error::DeviceFailure`.

mod classical;
mod combiner;
mod composite_decryptor;
mod composite_signer;
mod p256_decryptor;
mod p256_signer;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::mpi;
use openpgp::packet::Key;
use openpgp::packet::key::{PublicParts, UnspecifiedRole};
use openpgp::types::PublicKeyAlgorithm;
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use crate::EngineError;
use crate::error::DeviceFailure;
use crate::key::DeviceKeyError;

pub(crate) use classical::is_p256_point;
pub(crate) use composite_decryptor::CompositeDecryptor;
pub(crate) use composite_signer::CompositeSigner;
pub(crate) use p256_decryptor::P256Decryptor;
pub(crate) use p256_signer::P256Signer;

use classical::{Curve, CurveError};

pub(crate) type PublicKey = Key<PublicParts, UnspecifiedRole>;

/// The two post-quantum families. In both, only the ML-DSA and ML-KEM halves
/// are in the device; the classical halves are software keys that the vault
/// seals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    /// ML-DSA-65+Ed25519 and ML-KEM-768+X25519.
    MlDsa65,
    /// ML-DSA-87+Ed448 and ML-KEM-1024+X448.
    MlDsa87,
}

impl Tier {
    fn signing_curve(self) -> Curve {
        match self {
            Tier::MlDsa65 => Curve::Ed25519,
            Tier::MlDsa87 => Curve::Ed448,
        }
    }

    fn agreement_curve(self) -> Curve {
        match self {
            Tier::MlDsa65 => Curve::X25519,
            Tier::MlDsa87 => Curve::X448,
        }
    }

    pub(crate) fn signing_algorithm(self) -> PublicKeyAlgorithm {
        match self {
            Tier::MlDsa65 => PublicKeyAlgorithm::MLDSA65_Ed25519,
            Tier::MlDsa87 => PublicKeyAlgorithm::MLDSA87_Ed448,
        }
    }

    pub(crate) fn agreement_algorithm(self) -> PublicKeyAlgorithm {
        match self {
            Tier::MlDsa65 => PublicKeyAlgorithm::MLKEM768_X25519,
            Tier::MlDsa87 => PublicKeyAlgorithm::MLKEM1024_X448,
        }
    }

    /// The tier whose signing key `key` is.
    pub(crate) fn of_signing_key(key: &PublicKey) -> Option<Tier> {
        match key.mpis() {
            mpi::PublicKey::MLDSA65_Ed25519 { .. } => Some(Tier::MlDsa65),
            mpi::PublicKey::MLDSA87_Ed448 { .. } => Some(Tier::MlDsa87),
            _ => None,
        }
    }

    /// The classical and the post-quantum public key of this tier's signing
    /// key.
    pub(crate) fn signing_halves(self, key: &PublicKey) -> Option<(&[u8], &[u8])> {
        match (self, key.mpis()) {
            (Tier::MlDsa65, mpi::PublicKey::MLDSA65_Ed25519 { eddsa, mldsa }) => {
                Some((&eddsa[..], &mldsa[..]))
            }
            (Tier::MlDsa87, mpi::PublicKey::MLDSA87_Ed448 { eddsa, mldsa }) => {
                Some((&eddsa[..], &mldsa[..]))
            }
            _ => None,
        }
    }

    /// The classical and the post-quantum public key of this tier's
    /// key-agreement key.
    pub(crate) fn agreement_halves(self, key: &PublicKey) -> Option<(&[u8], &[u8])> {
        match (self, key.mpis()) {
            (Tier::MlDsa65, mpi::PublicKey::MLKEM768_X25519 { ecdh, mlkem }) => {
                Some((&ecdh[..], &mlkem[..]))
            }
            (Tier::MlDsa87, mpi::PublicKey::MLKEM1024_X448 { ecdh, mlkem }) => {
                Some((&ecdh[..], &mlkem[..]))
            }
            _ => None,
        }
    }

    /// The public key of this tier's signing key, from its two halves.
    pub(crate) fn signing_key(self, eddsa: &[u8], mldsa: &[u8]) -> Option<mpi::PublicKey> {
        Some(match self {
            Tier::MlDsa65 => mpi::PublicKey::MLDSA65_Ed25519 {
                eddsa: boxed(eddsa)?,
                mldsa: boxed(mldsa)?,
            },
            Tier::MlDsa87 => mpi::PublicKey::MLDSA87_Ed448 {
                eddsa: boxed(eddsa)?,
                mldsa: boxed(mldsa)?,
            },
        })
    }

    /// The public key of this tier's key-agreement key, from its two halves.
    pub(crate) fn agreement_key(self, ecdh: &[u8], mlkem: &[u8]) -> Option<mpi::PublicKey> {
        Some(match self {
            Tier::MlDsa65 => mpi::PublicKey::MLKEM768_X25519 {
                ecdh: boxed(ecdh)?,
                mlkem: boxed(mlkem)?,
            },
            Tier::MlDsa87 => mpi::PublicKey::MLKEM1024_X448 {
                ecdh: boxed(ecdh)?,
                mlkem: boxed(mlkem)?,
            },
        })
    }
}

fn boxed<const N: usize>(bytes: &[u8]) -> Option<Box<[u8; N]>> {
    bytes.to_vec().into_boxed_slice().try_into().ok()
}

/// The classical halves of a post-quantum device-bound key: the EdDSA secret,
/// then the ECDH secret, raw. The engine makes this value and reads it; the
/// vault seals it unread.
pub(crate) struct Halves {
    tier: Tier,
    eddsa: Protected,
    ecdh: Protected,
}

impl Halves {
    /// Fresh halves, with their two public keys.
    pub(crate) fn generate(tier: Tier) -> Result<(Self, Vec<u8>, Vec<u8>), CurveError> {
        let (eddsa, eddsa_public) = classical::generate(tier.signing_curve())?;
        let (ecdh, ecdh_public) = classical::generate(tier.agreement_curve())?;
        let halves = Self {
            tier,
            eddsa: Protected::from(&eddsa[..]),
            ecdh: Protected::from(&ecdh[..]),
        };
        Ok((halves, eddsa_public, ecdh_public))
    }

    /// The halves of a key of this tier, if `bytes` has their length.
    pub(crate) fn read(tier: Tier, bytes: &[u8]) -> Option<Self> {
        let eddsa_length = tier.signing_curve().key_length();
        if bytes.len() != eddsa_length + tier.agreement_curve().key_length() {
            return None;
        }
        let (eddsa, ecdh) = bytes.split_at(eddsa_length);
        Some(Self {
            tier,
            eddsa: Protected::from(eddsa),
            ecdh: Protected::from(ecdh),
        })
    }

    pub(crate) fn write(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(self.eddsa.len() + self.ecdh.len()));
        bytes.extend_from_slice(&self.eddsa);
        bytes.extend_from_slice(&self.ecdh);
        bytes
    }

    pub(crate) fn tier(&self) -> Tier {
        self.tier
    }

    pub(crate) fn eddsa(&self) -> &[u8] {
        &self.eddsa
    }

    pub(crate) fn ecdh(&self) -> &[u8] {
        &self.ecdh
    }
}

impl From<DeviceKeyError> for EngineError {
    fn from(error: DeviceKeyError) -> Self {
        match error {
            DeviceKeyError::Cancelled => EngineError::Cancelled,
            DeviceKeyError::NotAuthenticated => EngineError::DeviceNotAuthenticated,
            DeviceKeyError::Failed => EngineError::DeviceFailed,
        }
    }
}

/// A signer's failure of the device, as it crosses Sequoia.
fn device_failed(failure: EngineError) -> openpgp::anyhow::Error {
    DeviceFailure(failure).into_sequoia_error()
}

/// What a decryptor returns for a packet that is not for its key. Sequoia
/// turns it into "did not unwrap", and the helper decides what that means.
fn not_this_key() -> openpgp::anyhow::Error {
    openpgp::anyhow::anyhow!("not this key")
}

/// What a decryptor returns once it recorded a failure of the device. Sequoia
/// swallows it; the handle reads the record and stops.
fn stopped() -> openpgp::anyhow::Error {
    openpgp::anyhow::anyhow!("the device failed")
}

/// A shared secret or key share the device returned: 32 bytes, not all zero.
fn plausible_share(share: &[u8]) -> bool {
    share.len() == combiner::MLKEM_KEY_SHARE_LENGTH && share.iter().any(|byte| *byte != 0)
}
