//! The P-256 decryptor: the device agrees on a shared secret with the sender's
//! ephemeral point, and the KDF and the key unwrap run here.
//!
//! The point is checked before the device is asked. A point off the curve is
//! not for this key: in a hidden packet the next packet is tried, in a packet
//! that names the key it is `Tampered`. Asked with such a point, the device
//! would fail, and a failure of the device stops the whole decryption, so one
//! bad packet in front of the real one would block a valid message.

use std::sync::Arc;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::{Decryptor, SessionKey, ecdh, mpi};
use openpgp::types::{Curve, PublicKeyAlgorithm};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use super::{PublicKey, classical, not_this_key, plausible_share, stopped};
use crate::EngineError;
use crate::key::DeviceKey;

pub(crate) struct P256Decryptor {
    public: PublicKey,
    device: Arc<dyn DeviceKey>,
    failure: Option<EngineError>,
}

impl P256Decryptor {
    /// A decryptor for an ECDH P-256 key whose point is valid; `None` for any
    /// other key.
    pub(crate) fn new(public: PublicKey, device: Arc<dyn DeviceKey>) -> Option<Self> {
        match (public.pk_algo(), public.mpis()) {
            (
                PublicKeyAlgorithm::ECDH,
                mpi::PublicKey::ECDH {
                    curve: Curve::NistP256,
                    q,
                    ..
                },
            ) if classical::is_p256_point(q.value()) => Some(Self {
                public,
                device,
                failure: None,
            }),
            _ => None,
        }
    }

    /// The failure of the device during the last unwrap, which stops the
    /// operation.
    pub(crate) fn take_failure(&mut self) -> Option<EngineError> {
        self.failure.take()
    }
}

impl Decryptor for P256Decryptor {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let mpi::Ciphertext::ECDH { e, .. } = ciphertext else {
            return Err(not_this_key());
        };
        if !classical::is_p256_point(e.value()) {
            return Err(not_this_key());
        }
        let shared = match self.device.agree(e.value().to_vec()) {
            Ok(shared) => Zeroizing::new(shared),
            Err(error) => {
                self.failure = Some(error.into());
                return Err(stopped());
            }
        };
        if !plausible_share(&shared) {
            self.failure = Some(EngineError::DeviceFailed);
            return Err(stopped());
        }
        ecdh::decrypt_unwrap(
            &self.public,
            &Protected::from(&shared[..]),
            ciphertext,
            plaintext_len,
        )
    }
}
