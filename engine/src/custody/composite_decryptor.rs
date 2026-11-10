//! The split-custody composite decryptor (RFC 9980): the ECDH key share comes
//! from the classical half here, the device decapsulates the ML-KEM half, and
//! the combiner and the key unwrap run here. The device sees only the ML-KEM
//! ciphertext and returns only the 32-byte key share.
//!
//! The classical half goes first. It is cheap, and a ciphertext of another
//! shape, or a classical point that gives no shared secret, is not for this
//! key: it is decided before the device is asked.

use std::sync::Arc;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::{Decryptor, SessionKey, mpi};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use super::{PublicKey, Tier, classical, combiner, not_this_key, plausible_share, stopped};
use crate::EngineError;
use crate::key::DeviceKey;

pub(crate) struct CompositeDecryptor {
    public: PublicKey,
    tier: Tier,
    ecdh: Protected,
    device: Arc<dyn DeviceKey>,
    failure: Option<EngineError>,
}

impl CompositeDecryptor {
    /// A decryptor for this tier's composite key-agreement key, with `ecdh` as
    /// its classical half. `None` for another key, or for a half that does not
    /// belong to it: a wrong half fails here, before the device is asked.
    pub(crate) fn new(
        public: PublicKey,
        tier: Tier,
        ecdh: &[u8],
        device: Arc<dyn DeviceKey>,
    ) -> Option<Self> {
        let (expected, _) = tier.agreement_halves(&public)?;
        if classical::public_key(tier.agreement_curve(), ecdh).ok()? != expected {
            return None;
        }
        Some(Self {
            public,
            tier,
            ecdh: Protected::from(ecdh),
            device,
            failure: None,
        })
    }

    /// The failure of the device during the last unwrap, which stops the
    /// operation.
    pub(crate) fn take_failure(&mut self) -> Option<EngineError> {
        self.failure.take()
    }

    /// The ECDH ciphertext, the ML-KEM ciphertext and the wrapped session key,
    /// if `ciphertext` is this tier's.
    fn parts<'a>(&self, ciphertext: &'a mpi::Ciphertext) -> Option<(&'a [u8], &'a [u8], &'a [u8])> {
        match (self.tier, ciphertext) {
            (Tier::MlDsa65, mpi::Ciphertext::MLKEM768_X25519 { ecdh, mlkem, esk }) => {
                Some((&ecdh[..], &mlkem[..], &esk[..]))
            }
            (Tier::MlDsa87, mpi::Ciphertext::MLKEM1024_X448 { ecdh, mlkem, esk }) => {
                Some((&ecdh[..], &mlkem[..], &esk[..]))
            }
            _ => None,
        }
    }
}

impl Decryptor for CompositeDecryptor {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let Some((ecdh_ciphertext, mlkem_ciphertext, wrapped)) = self.parts(ciphertext) else {
            return Err(not_this_key());
        };
        let Ok(ecdh_share) =
            classical::agree(self.tier.agreement_curve(), &self.ecdh, ecdh_ciphertext)
        else {
            return Err(not_this_key());
        };
        let mlkem_share = match self.device.agree(mlkem_ciphertext.to_vec()) {
            Ok(share) => Zeroizing::new(share),
            Err(error) => {
                self.failure = Some(error.into());
                return Err(stopped());
            }
        };
        if !plausible_share(&mlkem_share) {
            self.failure = Some(EngineError::DeviceFailed);
            return Err(stopped());
        }
        let (ecdh_public, _) = self
            .tier
            .agreement_halves(&self.public)
            .ok_or_else(not_this_key)?;
        let kek = combiner::combine(
            &mlkem_share,
            &ecdh_share,
            ecdh_ciphertext,
            ecdh_public,
            self.tier.agreement_algorithm(),
        )?;
        combiner::unwrap_session_key(&kek, wrapped)
    }
}
