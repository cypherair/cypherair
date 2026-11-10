//! The private-key handle. It is the only code that branches on custody: an
//! operation picks a key from the certificate and asks the handle for a signer
//! or a decryptor for it.

use std::sync::Arc;
use std::time::SystemTime;

use openpgp::cert::prelude::*;
use openpgp::crypto;
use openpgp::packet::key::{PublicParts, UnspecifiedRole};
use openpgp::types::{KeyFlags, RevocationStatus};
use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use super::material::{self, SecretKey};
use crate::error::contained;
use crate::{EngineError, POLICY};

type PublicKey = openpgp::packet::Key<PublicParts, UnspecifiedRole>;
pub(crate) type BoxedSigner = Box<dyn crypto::Signer + Send + Sync>;
pub(crate) type BoxedDecryptor = Box<dyn crypto::Decryptor + Send + Sync>;

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
}

#[uniffi::export]
impl PrivateKey {
    /// A portable key, from the stored certificate and the secret the vault
    /// unsealed. A secret that belongs to another certificate is `KeyMismatch`.
    #[uniffi::constructor]
    pub fn portable(certificate: Vec<u8>, secret: Vec<u8>) -> Result<Arc<Self>, EngineError> {
        contained(|| {
            let secret = Zeroizing::new(secret);
            let certificate = material::certificate(&certificate)?.strip_secret_key_material();
            let secrets = material::secret_keys(&secret)?;

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
    pub(crate) fn decryptors(&self, now: SystemTime) -> Vec<BoxedDecryptor> {
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
        }
    }

    fn decryptor_for(&self, key: &PublicKey) -> Option<BoxedDecryptor> {
        match &self.custody {
            Custody::Portable { secrets } => {
                let pair = secret_for(secrets, key)?.clone().into_keypair().ok()?;
                Some(Box::new(pair))
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
