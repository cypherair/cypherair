//! The split-custody composite signer (RFC 9980): the EdDSA half signs here
//! with the classical half, the device makes the ML-DSA half, and the
//! composite signature is verified against the certificate's key before
//! Sequoia sees it. Composite verification needs both halves, so that also
//! proves the device's half.
//!
//! RFC 9980 section 5.3.1 requires a hash of at least 256 bits for a
//! composite signature, so the signer accepts no other.

use std::sync::Arc;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::{Signer, mpi};
use openpgp::types::HashAlgorithm;
use sequoia_openpgp as openpgp;

use super::{PublicKey, Tier, classical, device_failed};
use crate::EngineError;
use crate::key::DeviceKey;

/// The hashes of at least 256 bits, in the order of their numbers.
const ACCEPTABLE_HASHES: &[HashAlgorithm] = &[
    HashAlgorithm::SHA256,
    HashAlgorithm::SHA384,
    HashAlgorithm::SHA512,
    HashAlgorithm::SHA3_256,
    HashAlgorithm::SHA3_512,
];

pub(crate) struct CompositeSigner {
    public: PublicKey,
    tier: Tier,
    eddsa: Protected,
    device: Arc<dyn DeviceKey>,
}

impl CompositeSigner {
    /// A signer for this tier's composite signing key, with `eddsa` as its
    /// classical half. `None` for another key, or for a half that does not
    /// belong to it: a wrong half fails here, before the device is asked.
    pub(crate) fn new(
        public: PublicKey,
        tier: Tier,
        eddsa: &[u8],
        device: Arc<dyn DeviceKey>,
    ) -> Option<Self> {
        let (expected, _) = tier.signing_halves(&public)?;
        if classical::public_key(tier.signing_curve(), eddsa).ok()? != expected {
            return None;
        }
        Some(Self {
            public,
            tier,
            eddsa: Protected::from(eddsa),
            device,
        })
    }

    fn signature(&self, eddsa: Vec<u8>, mldsa: Vec<u8>) -> Option<mpi::Signature> {
        Some(match self.tier {
            Tier::MlDsa65 => mpi::Signature::MLDSA65_Ed25519 {
                eddsa: eddsa.into_boxed_slice().try_into().ok()?,
                mldsa: mldsa.into_boxed_slice().try_into().ok()?,
            },
            Tier::MlDsa87 => mpi::Signature::MLDSA87_Ed448 {
                eddsa: eddsa.into_boxed_slice().try_into().ok()?,
                mldsa: mldsa.into_boxed_slice().try_into().ok()?,
            },
        })
    }
}

impl Signer for CompositeSigner {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        ACCEPTABLE_HASHES
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        if !ACCEPTABLE_HASHES.contains(&hash_algo) || hash_algo.digest_size()? != digest.len() {
            return Err(
                openpgp::Error::InvalidOperation("a hash of at least 256 bits".into()).into(),
            );
        }
        let eddsa =
            classical::sign(self.tier.signing_curve(), &self.eddsa, digest).map_err(|_| {
                openpgp::Error::InvalidOperation("the classical half did not sign".into())
            })?;
        let mldsa = self
            .device
            .sign(digest.to_vec())
            .map_err(|error| device_failed(error.into()))?;
        let signature = self
            .signature(eddsa, mldsa)
            .ok_or_else(|| device_failed(EngineError::DeviceFailed))?;
        self.public
            .verify(&signature, hash_algo, digest)
            .map_err(|_| device_failed(EngineError::DeviceFailed))?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use openpgp::packet::key::Key6;

    use super::*;
    use crate::key::DeviceKeyError;

    #[derive(Default)]
    struct CountingDevice(AtomicUsize);

    impl DeviceKey for CountingDevice {
        fn sign(&self, _: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(DeviceKeyError::Failed)
        }
        fn agree(&self, _: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(DeviceKeyError::Failed)
        }
    }

    /// RFC 9980 section 5.3.1: a composite signature uses a hash of at least
    /// 256 bits. The signer offers no other to Sequoia, and refuses one it is
    /// asked for before the device is asked.
    #[test]
    fn composite_signer_takes_only_hashes_of_256_bits_or_more() {
        let (eddsa, eddsa_public) = classical::generate(Tier::MlDsa65.signing_curve()).unwrap();
        let mpis = Tier::MlDsa65
            .signing_key(&eddsa_public, &[0x01; 1952])
            .unwrap();
        let public = Key6::new(
            std::time::UNIX_EPOCH,
            Tier::MlDsa65.signing_algorithm(),
            mpis,
        )
        .unwrap()
        .into();
        let device = Arc::new(CountingDevice::default());
        let mut signer =
            CompositeSigner::new(public, Tier::MlDsa65, &eddsa, device.clone()).unwrap();

        assert!(
            signer
                .acceptable_hashes()
                .iter()
                .all(|hash| hash.digest_size().unwrap() >= 32)
        );
        #[allow(deprecated)]
        let short = [
            HashAlgorithm::SHA224,
            HashAlgorithm::SHA1,
            HashAlgorithm::RipeMD,
            HashAlgorithm::MD5,
        ];
        for hash in short {
            let digest = vec![0x42; hash.digest_size().unwrap()];
            assert!(signer.sign(hash, &digest).is_err(), "{hash:?}");
        }
        assert_eq!(device.0.load(Ordering::SeqCst), 0);
    }
}
