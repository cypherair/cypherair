use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use openpgp::crypto::{ecdh, mem::Protected, mpi, Decryptor, SessionKey};
use openpgp::packet::{key, Key};
use openpgp::types::{Curve, PublicKeyAlgorithm};

use crate::keys::{ExternalP256KeyAgreementFailureCategory, ExternalP256KeyAgreementRequest};

pub(crate) const P256_PUBLIC_KEY_LENGTH: usize = 65;
pub(crate) const P256_SHARED_SECRET_LENGTH: usize = 32;
pub(crate) const P256_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// Validate that `public_key` is an ECDH P-256 key with a well-formed
/// uncompressed public point. Shared by `ExternalP256Decryptor::new` and the
/// key-agreement subkey selector so both validate identically without building
/// a throwaway decryptor.
pub(crate) fn validate_p256_ecdh_public_key(
    public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
) -> Result<(), ExternalP256DecryptorError> {
    match (public_key.pk_algo(), public_key.mpis()) {
        (
            PublicKeyAlgorithm::ECDH,
            mpi::PublicKey::ECDH {
                curve: Curve::NistP256,
                q,
                ..
            },
        ) => validate_public_point(q.value()),
        _ => Err(ExternalP256DecryptorError::InvalidRequest(
            "external P-256 decryptor requires an ECDH P-256 public key",
        )),
    }
}

fn validate_public_point(bytes: &[u8]) -> Result<(), ExternalP256DecryptorError> {
    if bytes.len() != P256_PUBLIC_KEY_LENGTH
        || bytes.first().copied() != Some(P256_UNCOMPRESSED_POINT_TAG)
    {
        return Err(ExternalP256DecryptorError::InvalidRequest(
            "external P-256 decryptor received an invalid public point",
        ));
    }

    Ok(())
}

impl ExternalP256KeyAgreementRequest {
    pub(crate) fn new(recipient_public_key: Vec<u8>, ephemeral_public_key: Vec<u8>) -> Self {
        Self {
            recipient_public_key,
            ephemeral_public_key,
        }
    }

    pub fn recipient_public_key(&self) -> &[u8] {
        &self.recipient_public_key
    }

    pub fn ephemeral_public_key(&self) -> &[u8] {
        &self.ephemeral_public_key
    }
}

pub(crate) struct ExternalP256SharedSecret {
    raw: Zeroizing<Vec<u8>>,
}

impl ExternalP256SharedSecret {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self {
            raw: Zeroizing::new(raw),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ExternalP256DecryptorError {
    #[error("external P-256 decryptor invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("external P-256 decryptor invalid response: {0}")]
    InvalidResponse(&'static str),
    #[error("external P-256 key agreement failed: {}", .0.stable_reason())]
    ExternalFailure(ExternalP256KeyAgreementFailureCategory),
    #[error("external P-256 key agreement operation cancelled")]
    OperationCancelled,
}

pub(crate) struct ExternalP256Decryptor<F>
where
    F: FnMut(
        ExternalP256KeyAgreementRequest,
    ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    key_agreement_operation: F,
    last_error: Option<ExternalP256DecryptorError>,
}

impl<F> ExternalP256Decryptor<F>
where
    F: FnMut(
        ExternalP256KeyAgreementRequest,
    ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>,
{
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        key_agreement_operation: F,
    ) -> openpgp::Result<Self> {
        validate_p256_ecdh_public_key(&public_key)?;

        Ok(Self {
            public_key,
            key_agreement_operation,
            last_error: None,
        })
    }

    pub(crate) fn take_last_error(&mut self) -> Option<ExternalP256DecryptorError> {
        self.last_error.take()
    }

    /// Build the external key-agreement request from the ciphertext and the
    /// recipient public key. Validation only — borrows `self` immutably and
    /// returns the typed error so `decrypt` records every failure in one place.
    fn prepare_request(
        &self,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<ExternalP256KeyAgreementRequest, ExternalP256DecryptorError> {
        let ephemeral_public_key = match ciphertext {
            mpi::Ciphertext::ECDH { e, .. } => {
                validate_public_point(e.value())?;
                e.value().to_vec()
            }
            _ => {
                return Err(ExternalP256DecryptorError::InvalidRequest(
                    "external P-256 decryptor supports ECDH ciphertext only",
                ))
            }
        };

        let recipient_public_key = match self.public_key.mpis() {
            mpi::PublicKey::ECDH { q, .. } => q.value().to_vec(),
            _ => {
                return Err(ExternalP256DecryptorError::InvalidRequest(
                    "external P-256 decryptor requires an ECDH public key",
                ))
            }
        };

        Ok(ExternalP256KeyAgreementRequest::new(
            recipient_public_key,
            ephemeral_public_key,
        ))
    }

    /// Record a failure for out-of-band retrieval and convert it for return.
    /// Sequoia's `PKESK::decrypt` swallows the returned `Err` into `None`, so
    /// every error path in `decrypt` funnels through here; the helper loop then
    /// hard-aborts via `take_last_error` instead of silently downgrading to a
    /// generic "no matching key".
    fn record(&mut self, error: ExternalP256DecryptorError) -> openpgp::anyhow::Error {
        self.last_error = Some(error);
        error.into()
    }

    fn validate_shared_secret(
        shared_secret: &ExternalP256SharedSecret,
    ) -> Result<(), ExternalP256DecryptorError> {
        if shared_secret.raw.len() != P256_SHARED_SECRET_LENGTH {
            return Err(ExternalP256DecryptorError::InvalidResponse(
                "external P-256 decryptor returned an invalid shared secret shape",
            ));
        }

        if shared_secret.raw.iter().all(|byte| *byte == 0) {
            return Err(ExternalP256DecryptorError::InvalidResponse(
                "external P-256 decryptor returned an invalid zero shared secret",
            ));
        }

        Ok(())
    }
}

impl<F> Decryptor for ExternalP256Decryptor<F>
where
    F: FnMut(
            ExternalP256KeyAgreementRequest,
        ) -> Result<ExternalP256SharedSecret, ExternalP256DecryptorError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let request = match self.prepare_request(ciphertext) {
            Ok(request) => request,
            Err(error) => return Err(self.record(error)),
        };
        let shared_secret = match (self.key_agreement_operation)(request) {
            Ok(shared_secret) => shared_secret,
            Err(error) => return Err(self.record(error)),
        };
        if let Err(error) = Self::validate_shared_secret(&shared_secret) {
            return Err(self.record(error));
        }

        let shared_secret = Protected::from(shared_secret.raw.as_slice());
        ecdh::decrypt_unwrap(&self.public_key, &shared_secret, ciphertext, plaintext_len)
    }
}
