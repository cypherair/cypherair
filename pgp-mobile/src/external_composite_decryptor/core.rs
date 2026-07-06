use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::{mpi, Decryptor, SessionKey};
use openpgp::packet::{key, Key};
use openpgp::types::PublicKeyAlgorithm;

use crate::composite_classical;
use crate::composite_kem;
use crate::keys::{
    ExternalCompositeKeyAgreementFailureCategory, ExternalMlKem1024DecapsulationRequest,
    ExternalMlKem768DecapsulationRequest,
};

#[cfg(test)]
pub(crate) const MLKEM768_PUBLIC_KEY_LENGTH: usize = 1184;
#[cfg(test)]
pub(crate) const MLKEM768_CIPHERTEXT_LENGTH: usize = 1088;
#[cfg(test)]
pub(crate) const MLKEM1024_PUBLIC_KEY_LENGTH: usize = 1568;
#[cfg(test)]
pub(crate) const MLKEM1024_CIPHERTEXT_LENGTH: usize = 1568;

/// Validate that `public_key` is an RFC 9980 ML-KEM-768 + X25519 composite
/// key-agreement key. Shared by `ExternalCompositeDecryptor::new` and the
/// key-agreement subkey selector so both validate identically.
pub(crate) fn validate_composite_key_agreement_public_key(
    public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
) -> Result<(), ExternalCompositeDecryptorError> {
    match (public_key.pk_algo(), public_key.mpis()) {
        (PublicKeyAlgorithm::MLKEM768_X25519, mpi::PublicKey::MLKEM768_X25519 { .. }) => Ok(()),
        _ => Err(ExternalCompositeDecryptorError::InvalidRequest(
            "external composite decryptor requires an ML-KEM-768+X25519 public key",
        )),
    }
}

impl ExternalMlKem768DecapsulationRequest {
    pub(crate) fn new(recipient_mlkem_public_key: Vec<u8>, mlkem_ciphertext: Vec<u8>) -> Self {
        Self {
            recipient_mlkem_public_key,
            mlkem_ciphertext,
        }
    }
}

pub(crate) struct ExternalMlKem768Share {
    raw: Zeroizing<Vec<u8>>,
}

impl ExternalMlKem768Share {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self {
            raw: Zeroizing::new(raw),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ExternalCompositeDecryptorError {
    #[error("external composite decryptor invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("external composite decryptor invalid response: {0}")]
    InvalidResponse(&'static str),
    #[error("external composite decryptor classical component failed: {0}")]
    ClassicalComponentFailure(&'static str),
    #[error("external composite key agreement failed: {}", .0.stable_reason())]
    ExternalFailure(ExternalCompositeKeyAgreementFailureCategory),
    #[error("external composite key agreement operation cancelled")]
    OperationCancelled,
}

impl ExternalCompositeDecryptorError {
    /// Distinguish a genuinely attempted external decapsulation that failed
    /// from a pre-callback "this PKESK is not a valid composite request for
    /// this key" rejection.
    ///
    /// `InvalidRequest` is recorded by `prepare_request` *before* the external
    /// operation runs (non-composite ciphertext addressed to a different
    /// recipient). For a wildcard/hidden recipient that speculatively matches
    /// every key, such a rejection means "this packet is addressed to someone
    /// else", so the helper can skip it and keep trying later PKESKs. The
    /// remaining variants mean the classical component or the external callback
    /// was actually exercised and failed, which must fail closed instead of
    /// being skipped.
    pub(crate) fn is_external_operation_failure(&self) -> bool {
        match self {
            ExternalCompositeDecryptorError::InvalidRequest(_) => false,
            ExternalCompositeDecryptorError::InvalidResponse(_)
            | ExternalCompositeDecryptorError::ClassicalComponentFailure(_)
            | ExternalCompositeDecryptorError::ExternalFailure(_)
            | ExternalCompositeDecryptorError::OperationCancelled => true,
        }
    }
}

/// RFC 9980 composite ML-KEM-768 + X25519 decryptor with split custody.
///
/// The X25519 key share is derived inside Rust from the supplied classical
/// component secret; the ML-KEM-768 decapsulation is delegated to the external
/// (Secure Enclave) callback. The vendored RFC 9980 KEM combiner and the
/// AES-256 key unwrap both stay on the Rust side, so the callback sees only
/// public material and returns only the 32-byte ML-KEM key share.
pub(crate) struct ExternalCompositeDecryptor<F>
where
    F: FnMut(
        ExternalMlKem768DecapsulationRequest,
    ) -> Result<ExternalMlKem768Share, ExternalCompositeDecryptorError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_ecdh_secret: Protected,
    decapsulation_operation: F,
    last_error: Option<ExternalCompositeDecryptorError>,
}

impl<F> ExternalCompositeDecryptor<F>
where
    F: FnMut(
        ExternalMlKem768DecapsulationRequest,
    ) -> Result<ExternalMlKem768Share, ExternalCompositeDecryptorError>,
{
    /// Build a composite decryptor after validating that the classical
    /// component secret matches the X25519 half bound into the certificate.
    /// A mismatched envelope payload fails closed here instead of deriving
    /// key shares that can never unwrap the session key.
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        classical_ecdh_secret: &[u8],
        decapsulation_operation: F,
    ) -> openpgp::Result<Self> {
        validate_composite_key_agreement_public_key(&public_key)?;
        let expected_ecdh_public = match public_key.mpis() {
            mpi::PublicKey::MLKEM768_X25519 { ecdh, .. } => **ecdh,
            _ => unreachable!("validated above"),
        };

        let derived_ecdh_public = composite_classical::x25519_public_key(classical_ecdh_secret)
            .map_err(|error| {
                openpgp::Error::InvalidOperation(format!(
                    "external composite decryptor rejected the classical component: {error}"
                ))
            })?;
        if derived_ecdh_public != expected_ecdh_public {
            return Err(openpgp::Error::InvalidOperation(
                "external composite decryptor classical component does not match the certificate"
                    .to_string(),
            )
            .into());
        }

        Ok(Self {
            public_key,
            classical_ecdh_secret: Protected::from(classical_ecdh_secret),
            decapsulation_operation,
            last_error: None,
        })
    }

    pub(crate) fn take_last_error(&mut self) -> Option<ExternalCompositeDecryptorError> {
        self.last_error.take()
    }

    /// Build the external decapsulation request from the ciphertext and the
    /// recipient public key. Validation only — borrows `self` immutably and
    /// returns the typed error so `decrypt` records every failure in one place.
    fn prepare_request(
        &self,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<ExternalMlKem768DecapsulationRequest, ExternalCompositeDecryptorError> {
        let mlkem_ciphertext = match ciphertext {
            mpi::Ciphertext::MLKEM768_X25519 { mlkem, .. } => mlkem.to_vec(),
            _ => {
                return Err(ExternalCompositeDecryptorError::InvalidRequest(
                    "external composite decryptor supports ML-KEM-768+X25519 ciphertext only",
                ))
            }
        };

        let recipient_mlkem_public_key = match self.public_key.mpis() {
            mpi::PublicKey::MLKEM768_X25519 { mlkem, .. } => mlkem.to_vec(),
            _ => {
                return Err(ExternalCompositeDecryptorError::InvalidRequest(
                    "external composite decryptor requires an ML-KEM-768+X25519 public key",
                ))
            }
        };

        Ok(ExternalMlKem768DecapsulationRequest::new(
            recipient_mlkem_public_key,
            mlkem_ciphertext,
        ))
    }

    /// Record a failure for out-of-band retrieval and convert it for return.
    /// Sequoia's `PKESK::decrypt` swallows the returned `Err` into `None`, so
    /// every error path in `decrypt` funnels through here; the helper loop then
    /// hard-aborts via `take_last_error` instead of silently downgrading to a
    /// generic "no matching key".
    fn record(&mut self, error: ExternalCompositeDecryptorError) -> openpgp::anyhow::Error {
        self.last_error = Some(error);
        error.into()
    }

    fn validate_key_share(
        key_share: &ExternalMlKem768Share,
    ) -> Result<(), ExternalCompositeDecryptorError> {
        if key_share.raw.len() != composite_kem::MLKEM768_KEY_SHARE_LENGTH {
            return Err(ExternalCompositeDecryptorError::InvalidResponse(
                "external composite decryptor returned an invalid key share shape",
            ));
        }

        if key_share.raw.iter().all(|byte| *byte == 0) {
            return Err(ExternalCompositeDecryptorError::InvalidResponse(
                "external composite decryptor returned an invalid zero key share",
            ));
        }

        Ok(())
    }
}

impl<F> Decryptor for ExternalCompositeDecryptor<F>
where
    F: FnMut(
            ExternalMlKem768DecapsulationRequest,
        ) -> Result<ExternalMlKem768Share, ExternalCompositeDecryptorError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let request = match self.prepare_request(ciphertext) {
            Ok(request) => request,
            Err(error) => return Err(self.record(error)),
        };

        let (ecdh_ciphertext, ecdh_public, wrapped_session_key) =
            match (self.public_key.mpis(), ciphertext) {
                (
                    mpi::PublicKey::MLKEM768_X25519 {
                        ecdh: ecdh_public, ..
                    },
                    mpi::Ciphertext::MLKEM768_X25519 {
                        ecdh: ecdh_ciphertext,
                        esk,
                        ..
                    },
                ) => (**ecdh_ciphertext, **ecdh_public, esk.to_vec()),
                _ => {
                    return Err(self.record(ExternalCompositeDecryptorError::InvalidRequest(
                        "external composite decryptor supports ML-KEM-768+X25519 ciphertext only",
                    )))
                }
            };

        // Classical half first: it is cheap, deterministic, and failing here
        // avoids a user-visible Secure Enclave operation for broken key material.
        let ecdh_key_share = match composite_classical::x25519_shared_secret(
            &self.classical_ecdh_secret,
            &ecdh_ciphertext,
        ) {
            Ok(share) => share,
            Err(_) => {
                return Err(self.record(
                    ExternalCompositeDecryptorError::ClassicalComponentFailure(
                        "external composite decryptor classical key agreement failed",
                    ),
                ))
            }
        };

        let mlkem_key_share = match (self.decapsulation_operation)(request) {
            Ok(share) => share,
            Err(error) => return Err(self.record(error)),
        };
        if let Err(error) = Self::validate_key_share(&mlkem_key_share) {
            return Err(self.record(error));
        }

        // Combiner and unwrap failures are returned raw, matching the native
        // Sequoia composite path: `PKESK::decrypt` maps them to a non-match and
        // the message fails closed with "no key to decrypt".
        let kek = composite_kem::multi_key_combine_mlkem768_x25519(
            &mlkem_key_share.raw,
            &ecdh_key_share,
            &ecdh_ciphertext,
            &ecdh_public,
        )?;
        composite_kem::unwrap_session_key(&kek, &wrapped_session_key)
    }
}

/// Validate that `public_key` is an RFC 9980 ML-KEM-1024 + X448 composite
/// key-agreement key (· High tier). Shared by `ExternalCompositeHighDecryptor::new`
/// and the key-agreement subkey selector so both validate identically.
pub(crate) fn validate_composite_high_key_agreement_public_key(
    public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
) -> Result<(), ExternalCompositeDecryptorError> {
    match (public_key.pk_algo(), public_key.mpis()) {
        (PublicKeyAlgorithm::MLKEM1024_X448, mpi::PublicKey::MLKEM1024_X448 { .. }) => Ok(()),
        _ => Err(ExternalCompositeDecryptorError::InvalidRequest(
            "external composite decryptor requires an ML-KEM-1024+X448 public key",
        )),
    }
}

impl ExternalMlKem1024DecapsulationRequest {
    pub(crate) fn new(recipient_mlkem_public_key: Vec<u8>, mlkem_ciphertext: Vec<u8>) -> Self {
        Self {
            recipient_mlkem_public_key,
            mlkem_ciphertext,
        }
    }
}

pub(crate) struct ExternalMlKem1024Share {
    raw: Zeroizing<Vec<u8>>,
}

impl ExternalMlKem1024Share {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self {
            raw: Zeroizing::new(raw),
        }
    }
}

/// RFC 9980 composite ML-KEM-1024 + X448 decryptor with split custody (· High tier).
///
/// The X448 key share is derived inside Rust from the supplied classical
/// component secret; the ML-KEM-1024 decapsulation is delegated to the external
/// (Secure Enclave) callback. The vendored RFC 9980 KEM combiner and the
/// AES-256 key unwrap both stay on the Rust side, so the callback sees only
/// public material and returns only the 32-byte ML-KEM key share.
pub(crate) struct ExternalCompositeHighDecryptor<F>
where
    F: FnMut(
        ExternalMlKem1024DecapsulationRequest,
    ) -> Result<ExternalMlKem1024Share, ExternalCompositeDecryptorError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_ecdh_secret: Protected,
    decapsulation_operation: F,
    last_error: Option<ExternalCompositeDecryptorError>,
}

impl<F> ExternalCompositeHighDecryptor<F>
where
    F: FnMut(
        ExternalMlKem1024DecapsulationRequest,
    ) -> Result<ExternalMlKem1024Share, ExternalCompositeDecryptorError>,
{
    /// Build a · High composite decryptor after validating that the classical
    /// component secret matches the X448 half bound into the certificate. A
    /// mismatched envelope payload fails closed here instead of deriving key
    /// shares that can never unwrap the session key.
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        classical_ecdh_secret: &[u8],
        decapsulation_operation: F,
    ) -> openpgp::Result<Self> {
        validate_composite_high_key_agreement_public_key(&public_key)?;
        let expected_ecdh_public = match public_key.mpis() {
            mpi::PublicKey::MLKEM1024_X448 { ecdh, .. } => **ecdh,
            _ => unreachable!("validated above"),
        };

        let derived_ecdh_public = composite_classical::x448_public_key(classical_ecdh_secret)
            .map_err(|error| {
                openpgp::Error::InvalidOperation(format!(
                    "external composite decryptor rejected the classical component: {error}"
                ))
            })?;
        if derived_ecdh_public != expected_ecdh_public {
            return Err(openpgp::Error::InvalidOperation(
                "external composite decryptor classical component does not match the certificate"
                    .to_string(),
            )
            .into());
        }

        Ok(Self {
            public_key,
            classical_ecdh_secret: Protected::from(classical_ecdh_secret),
            decapsulation_operation,
            last_error: None,
        })
    }

    pub(crate) fn take_last_error(&mut self) -> Option<ExternalCompositeDecryptorError> {
        self.last_error.take()
    }

    fn prepare_request(
        &self,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<ExternalMlKem1024DecapsulationRequest, ExternalCompositeDecryptorError> {
        let mlkem_ciphertext = match ciphertext {
            mpi::Ciphertext::MLKEM1024_X448 { mlkem, .. } => mlkem.to_vec(),
            _ => {
                return Err(ExternalCompositeDecryptorError::InvalidRequest(
                    "external composite decryptor supports ML-KEM-1024+X448 ciphertext only",
                ))
            }
        };

        let recipient_mlkem_public_key = match self.public_key.mpis() {
            mpi::PublicKey::MLKEM1024_X448 { mlkem, .. } => mlkem.to_vec(),
            _ => {
                return Err(ExternalCompositeDecryptorError::InvalidRequest(
                    "external composite decryptor requires an ML-KEM-1024+X448 public key",
                ))
            }
        };

        Ok(ExternalMlKem1024DecapsulationRequest::new(
            recipient_mlkem_public_key,
            mlkem_ciphertext,
        ))
    }

    fn record(&mut self, error: ExternalCompositeDecryptorError) -> openpgp::anyhow::Error {
        self.last_error = Some(error);
        error.into()
    }

    fn validate_key_share(
        key_share: &ExternalMlKem1024Share,
    ) -> Result<(), ExternalCompositeDecryptorError> {
        if key_share.raw.len() != composite_kem::MLKEM1024_KEY_SHARE_LENGTH {
            return Err(ExternalCompositeDecryptorError::InvalidResponse(
                "external composite decryptor returned an invalid key share shape",
            ));
        }

        if key_share.raw.iter().all(|byte| *byte == 0) {
            return Err(ExternalCompositeDecryptorError::InvalidResponse(
                "external composite decryptor returned an invalid zero key share",
            ));
        }

        Ok(())
    }
}

impl<F> Decryptor for ExternalCompositeHighDecryptor<F>
where
    F: FnMut(
            ExternalMlKem1024DecapsulationRequest,
        ) -> Result<ExternalMlKem1024Share, ExternalCompositeDecryptorError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let request = match self.prepare_request(ciphertext) {
            Ok(request) => request,
            Err(error) => return Err(self.record(error)),
        };

        let (ecdh_ciphertext, ecdh_public, wrapped_session_key) =
            match (self.public_key.mpis(), ciphertext) {
                (
                    mpi::PublicKey::MLKEM1024_X448 {
                        ecdh: ecdh_public, ..
                    },
                    mpi::Ciphertext::MLKEM1024_X448 {
                        ecdh: ecdh_ciphertext,
                        esk,
                        ..
                    },
                ) => (**ecdh_ciphertext, **ecdh_public, esk.to_vec()),
                _ => {
                    return Err(self.record(ExternalCompositeDecryptorError::InvalidRequest(
                        "external composite decryptor supports ML-KEM-1024+X448 ciphertext only",
                    )))
                }
            };

        // Classical half first: it is cheap, deterministic, and failing here
        // avoids a user-visible Secure Enclave operation for broken key material.
        let ecdh_key_share = match composite_classical::x448_shared_secret(
            &self.classical_ecdh_secret,
            &ecdh_ciphertext,
        ) {
            Ok(share) => share,
            Err(_) => {
                return Err(self.record(
                    ExternalCompositeDecryptorError::ClassicalComponentFailure(
                        "external composite decryptor classical key agreement failed",
                    ),
                ))
            }
        };

        let mlkem_key_share = match (self.decapsulation_operation)(request) {
            Ok(share) => share,
            Err(error) => return Err(self.record(error)),
        };
        if let Err(error) = Self::validate_key_share(&mlkem_key_share) {
            return Err(self.record(error));
        }

        // Combiner and unwrap failures are returned raw, matching the native
        // Sequoia composite path: `PKESK::decrypt` maps them to a non-match and
        // the message fails closed with "no key to decrypt".
        let kek = composite_kem::multi_key_combine_mlkem1024_x448(
            &mlkem_key_share.raw,
            &ecdh_key_share,
            &ecdh_ciphertext,
            &ecdh_public,
        )?;
        composite_kem::unwrap_session_key(&kek, &wrapped_session_key)
    }
}
