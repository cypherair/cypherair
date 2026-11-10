//! The private-key handle. It is the only code that branches on custody: an
//! operation picks a key from the certificate and asks the handle for a signer
//! or a decryptor for it.
//!
//! A decryptor unwraps a session key itself and answers one of three things:
//! unwrapped, not this key, or an error, which stops the operation. Sequoia
//! would turn a failure of the device into "did not unwrap". A signer's
//! failure of the device crosses Sequoia as an `error::DeviceFailure`.

use std::sync::Arc;
use std::time::SystemTime;

use openpgp::cert::prelude::*;
use openpgp::crypto::{self, KeyPair, SessionKey};
use openpgp::packet::PKESK;
use openpgp::packet::key::{PublicParts, UnspecifiedRole};
use openpgp::types::{KeyFlags, RevocationStatus, SymmetricAlgorithm};
use openpgp::{Fingerprint, KeyHandle};
use sequoia_openpgp as openpgp;

use super::device::{self, DeviceKey};
use super::material::{self, SecretKey};
use crate::custody::{CompositeDecryptor, CompositeSigner, Halves, P256Decryptor, P256Signer};
use crate::error::contained;
use crate::{EngineError, POLICY};

type PublicKey = openpgp::packet::Key<PublicParts, UnspecifiedRole>;
pub(crate) type BoxedSigner = Box<dyn crypto::Signer + Send + Sync>;

/// A certificate and the means to use its private keys.
#[derive(uniffi::Object)]
pub struct PrivateKey {
    /// Public only. It is the authority for expiry and revocation.
    certificate: Cert,
    custody: Custody,
}

enum Custody {
    /// The secret keys, joined from what the vault sealed.
    Portable { secrets: Vec<SecretKey> },
    /// The device's two keys and, for the post-quantum families, the classical
    /// halves.
    Device {
        device: Arc<dyn DeviceKey>,
        signing: Fingerprint,
        agreement: Fingerprint,
        halves: Option<Halves>,
    },
}

#[uniffi::export]
impl PrivateKey {
    /// A portable key, from the stored certificate and the secret the vault
    /// unsealed. A secret that belongs to another certificate is `KeyMismatch`.
    #[uniffi::constructor]
    pub fn portable(certificate: Vec<u8>, secret: &[u8]) -> Result<Arc<Self>, EngineError> {
        contained(|| {
            let certificate = material::certificate(&certificate)?.strip_secret_key_material();
            let secrets = material::secret_keys(secret)?;

            if secrets[0].fingerprint() != certificate.fingerprint() {
                return Err(EngineError::KeyMismatch);
            }
            let belongs = |secret: &SecretKey| {
                certificate
                    .keys()
                    .subkeys()
                    .any(|subkey| subkey.key().fingerprint() == secret.fingerprint())
            };
            if !secrets[1..].iter().all(belongs) {
                return Err(EngineError::KeyMismatch);
            }

            Ok(Arc::new(Self {
                certificate,
                custody: Custody::Portable { secrets },
            }))
        })
    }

    /// A device-bound key, from the stored certificate, the classical halves
    /// the vault unsealed (empty for P-256, which has none), and the device.
    ///
    /// A certificate that is not one of the four device-bound shapes is
    /// `Unsupported`. Halves that do not belong to the certificate are
    /// `KeyMismatch`, before the device is ever asked. Whether the device's
    /// keys belong to the certificate cannot be seen here: the vault compares
    /// their public keys with `device_key_slots`, every signature is verified
    /// before it is released, and a wrong shared secret unwraps nothing.
    #[uniffi::constructor]
    pub fn device(
        certificate: Vec<u8>,
        secret: &[u8],
        device: Arc<dyn DeviceKey>,
    ) -> Result<Arc<Self>, EngineError> {
        contained(|| {
            let certificate = material::certificate(&certificate)?.strip_secret_key_material();
            let layout = device::layout(&certificate)?;
            let halves = match layout.tier {
                None if secret.is_empty() => None,
                None => return Err(EngineError::KeyMismatch),
                Some(tier) => {
                    let halves = Halves::read(tier, secret).ok_or(EngineError::KeyMismatch)?;
                    let belong = CompositeSigner::new(
                        layout.signing.clone(),
                        tier,
                        halves.eddsa(),
                        Arc::clone(&device),
                    )
                    .is_some()
                        && CompositeDecryptor::new(
                            layout.agreement.clone(),
                            tier,
                            halves.ecdh(),
                            Arc::clone(&device),
                        )
                        .is_some();
                    if !belong {
                        return Err(EngineError::KeyMismatch);
                    }
                    Some(halves)
                }
            };
            Ok(Arc::new(Self {
                custody: Custody::Device {
                    device,
                    signing: layout.signing.fingerprint(),
                    agreement: layout.agreement.fingerprint(),
                    halves,
                },
                certificate,
            }))
        })
    }
}

impl PrivateKey {
    /// The signer for this certificate now: its signing subkey where there is
    /// one, else its primary key. An expired or revoked key does not sign.
    pub(crate) fn signer(&self, now: SystemTime) -> Result<BoxedSigner, EngineError> {
        let valid = self
            .certificate
            .with_policy(&POLICY, now)
            .map_err(|_| EngineError::KeyUnusable)?;
        if let RevocationStatus::Revoked(_) = valid.revocation_status() {
            return Err(EngineError::KeyRevoked);
        }
        if valid.alive().is_err() {
            return Err(EngineError::KeyExpired);
        }

        let mut candidates: Vec<_> = valid.keys().supported().for_signing().collect();
        // Subkeys first, in the certificate's order; the primary key last.
        candidates.sort_by_key(|key| key.primary());
        let mut refusal = EngineError::KeyUnusable;
        for key in candidates {
            if let RevocationStatus::Revoked(_) = key.revocation_status() {
                refusal = EngineError::KeyRevoked;
            } else if key.alive().is_err() {
                if refusal != EngineError::KeyRevoked {
                    refusal = EngineError::KeyExpired;
                }
            } else if let Some(signer) = self.signer_for(key.key()) {
                return Ok(signer);
            }
        }
        Err(refusal)
    }

    /// A decryptor for every key of the certificate that may decrypt. Expiry
    /// and revocation do not matter here, so that old messages stay readable.
    pub(crate) fn decryptors(&self, now: SystemTime) -> Vec<Decryptor> {
        let Ok(valid) = self.certificate.with_policy(&POLICY, now) else {
            return Vec::new();
        };
        let encryption = KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption();
        valid
            .keys()
            .supported()
            .key_flags(encryption)
            .filter_map(|key| self.decryptor_for(key.key()))
            .collect()
    }

    fn signer_for(&self, key: &PublicKey) -> Option<BoxedSigner> {
        match &self.custody {
            Custody::Portable { secrets } => {
                let pair = secret_for(secrets, key)?.clone().into_keypair().ok()?;
                Some(Box::new(pair))
            }
            Custody::Device {
                device,
                signing,
                halves,
                ..
            } if key.fingerprint() == *signing => {
                let device = Arc::clone(device);
                match halves {
                    None => Some(Box::new(P256Signer::new(key.clone(), device)?)),
                    Some(halves) => Some(Box::new(CompositeSigner::new(
                        key.clone(),
                        halves.tier(),
                        halves.eddsa(),
                        device,
                    )?)),
                }
            }
            Custody::Device { .. } => None,
        }
    }

    fn decryptor_for(&self, key: &PublicKey) -> Option<Decryptor> {
        let custody = match &self.custody {
            Custody::Portable { secrets } => {
                CustodyDecryptor::Portable(secret_for(secrets, key)?.clone().into_keypair().ok()?)
            }
            Custody::Device {
                device,
                agreement,
                halves,
                ..
            } if key.fingerprint() == *agreement => {
                let device = Arc::clone(device);
                match halves {
                    None => CustodyDecryptor::P256(P256Decryptor::new(key.clone(), device)?),
                    Some(halves) => CustodyDecryptor::Composite(CompositeDecryptor::new(
                        key.clone(),
                        halves.tier(),
                        halves.ecdh(),
                        device,
                    )?),
                }
            }
            Custody::Device { .. } => return None,
        };
        Some(Decryptor(custody))
    }
}

/// One of the key's decryption keys, as an operation sees it.
pub(crate) struct Decryptor(CustodyDecryptor);

enum CustodyDecryptor {
    Portable(KeyPair),
    P256(P256Decryptor),
    Composite(CompositeDecryptor),
}

/// A session key with the cipher a v3 session-key packet names.
pub(crate) type Unwrapped = (Option<SymmetricAlgorithm>, SessionKey);

impl Decryptor {
    pub(crate) fn key_handle(&self) -> KeyHandle {
        self.public().key_handle()
    }

    fn public(&self) -> &PublicKey {
        use crypto::Decryptor as _;
        match &self.0 {
            CustodyDecryptor::Portable(pair) => pair.public(),
            CustodyDecryptor::P256(decryptor) => decryptor.public(),
            CustodyDecryptor::Composite(decryptor) => decryptor.public(),
        }
    }

    /// Unwrap the session key of `pkesk`: `Some` when it unwrapped, `None`
    /// when the packet is not for this key, and an error when the custody
    /// failed, which stops the operation.
    pub(crate) fn unwrap(
        &mut self,
        pkesk: &PKESK,
        sym_algo: Option<SymmetricAlgorithm>,
    ) -> Result<Option<Unwrapped>, EngineError> {
        match &mut self.0 {
            CustodyDecryptor::Portable(pair) => Ok(pkesk.decrypt(pair, sym_algo)),
            CustodyDecryptor::P256(decryptor) => {
                let unwrapped = pkesk.decrypt(decryptor, sym_algo);
                decryptor.take_failure().map_or(Ok(unwrapped), Err)
            }
            CustodyDecryptor::Composite(decryptor) => {
                let unwrapped = pkesk.decrypt(decryptor, sym_algo);
                decryptor.take_failure().map_or(Ok(unwrapped), Err)
            }
        }
    }
}

fn secret_for<'a>(secrets: &'a [SecretKey], key: &PublicKey) -> Option<&'a SecretKey> {
    secrets
        .iter()
        .find(|secret| secret.fingerprint() == key.fingerprint())
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("fingerprint", &self.certificate.fingerprint())
            .finish_non_exhaustive()
    }
}
