//! The P-256 signer: the device signs a SHA-256 digest, and the signature is
//! verified against the certificate's key before Sequoia sees it.

use std::sync::Arc;

use openpgp::crypto::{Signer, mpi};
use openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};
use sequoia_openpgp as openpgp;

use super::{PublicKey, device_failed};
use crate::EngineError;
use crate::key::DeviceKey;

const SCALAR_LENGTH: usize = 32;

pub(crate) struct P256Signer {
    public: PublicKey,
    device: Arc<dyn DeviceKey>,
}

impl P256Signer {
    /// A signer for an ECDSA P-256 key; `None` for any other key.
    pub(crate) fn new(public: PublicKey, device: Arc<dyn DeviceKey>) -> Option<Self> {
        match (public.pk_algo(), public.mpis()) {
            (
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA {
                    curve: Curve::NistP256,
                    ..
                },
            ) => Some(Self { public, device }),
            _ => None,
        }
    }
}

impl Signer for P256Signer {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA256]
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        if hash_algo != HashAlgorithm::SHA256 || digest.len() != SCALAR_LENGTH {
            return Err(openpgp::Error::InvalidOperation("SHA-256 only".into()).into());
        }
        let answer = self
            .device
            .sign(digest.to_vec())
            .map_err(|error| device_failed(error.into()))?;
        verified(&self.public, digest, &answer)
            .ok_or_else(|| device_failed(EngineError::DeviceFailed))
    }
}

/// The device's answer as a signature, if it is r‖s and verifies.
fn verified(public: &PublicKey, digest: &[u8], answer: &[u8]) -> Option<mpi::Signature> {
    if answer.len() != 2 * SCALAR_LENGTH {
        return None;
    }
    let (r, s) = answer.split_at(SCALAR_LENGTH);
    let signature = mpi::Signature::ECDSA {
        r: mpi::MPI::new(r),
        s: mpi::MPI::new(s),
    };
    public
        .verify(&signature, HashAlgorithm::SHA256, digest)
        .ok()
        .map(|()| signature)
}
