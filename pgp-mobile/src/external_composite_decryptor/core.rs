use std::marker::PhantomData;

use sequoia_openpgp as openpgp;
use zeroize::Zeroizing;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::{mpi, Decryptor, SessionKey};
use openpgp::packet::{key, Key};
use openpgp::types::PublicKeyAlgorithm;

use crate::composite_classical::{self, ClassicalComponentError};
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
/// key-agreement key. Shared by the tier descriptor and the key-agreement subkey
/// selector so both validate identically.
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

/// Validate that `public_key` is an RFC 9980 ML-KEM-1024 + X448 composite
/// key-agreement key (· High tier).
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

impl ExternalMlKem768DecapsulationRequest {
    pub(crate) fn new(recipient_mlkem_public_key: Vec<u8>, mlkem_ciphertext: Vec<u8>) -> Self {
        Self {
            recipient_mlkem_public_key,
            mlkem_ciphertext,
        }
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
    /// Whether this error must hard-abort decryption even when it surfaced from a
    /// wildcard / hidden-recipient PKESK that only speculatively matched this key.
    ///
    /// Two variants are inducible by an anonymous PKESK addressed to a *different*
    /// recipient, so for a wildcard recipient they are non-matches to skip — not
    /// failures to abort on:
    /// - `InvalidRequest` is recorded *before* the external operation runs
    ///   (non-composite ciphertext addressed to someone else).
    /// - `ClassicalComponentFailure` is the classical X25519/X448 key agreement
    ///   failing on the peer ephemeral carried by *this* PKESK. A crafted
    ///   low-order / all-zero point makes it fail without the packet being ours,
    ///   so for a wildcard recipient this too means "addressed to someone else".
    ///   (An explicitly-addressed PKESK still hard-aborts here — that is handled
    ///   by the `explicit_recipient` check at the call site, not by this method.)
    ///
    /// Skipping these mirrors Sequoia's decrypt-and-continue behavior for
    /// non-matching PKESKs, so a later legitimately-addressed PKESK can still
    /// decrypt a multi-recipient message instead of the whole message failing.
    ///
    /// The remaining variants — a malformed or zero external key share, a genuine
    /// external decapsulation failure, or user cancellation — are real failures of
    /// this device/operation and must fail closed even for a wildcard recipient.
    pub(crate) fn hard_aborts_anonymous_recipient(&self) -> bool {
        match self {
            ExternalCompositeDecryptorError::InvalidRequest(_)
            | ExternalCompositeDecryptorError::ClassicalComponentFailure(_) => false,
            ExternalCompositeDecryptorError::InvalidResponse(_)
            | ExternalCompositeDecryptorError::ExternalFailure(_)
            | ExternalCompositeDecryptorError::OperationCancelled => true,
        }
    }
}

/// The per-parameter-set deltas of an RFC 9980 composite KEM (ML-KEM + ECDH)
/// split-custody decryptor. Everything security-relevant — the fail-closed error
/// taxonomy, the classical-half-first ordering, key-share validation, and the
/// combiner/unwrap funnelling — lives once in `CompositeDecryptor`; a tier
/// supplies only the algorithm-specific MPI shapes, classical curve operations,
/// and combiner.
pub(crate) trait CompositeKemTier {
    /// The decapsulation request carrier crossing to the external callback.
    type Request;
    /// The key-share carrier the external callback returns.
    type Share;
    /// ML-KEM shared-secret length (32 for every FIPS 203 parameter set).
    const KEY_SHARE_LENGTH: usize;
    /// Validate `public_key` is this tier's composite key-agreement key.
    fn validate_public_key(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Result<(), ExternalCompositeDecryptorError>;
    /// The classical ECDH public key bound into the certificate, or `None` if it
    /// is not this tier's composite key.
    fn cert_ecdh_public_key(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Option<Vec<u8>>;
    /// Derive the classical ECDH public key from the component secret.
    fn classical_public_key(secret: &[u8]) -> Result<Vec<u8>, ClassicalComponentError>;
    /// Build the external decapsulation request from the certificate and PKESK
    /// ciphertext (validation only), or the typed error to record.
    fn make_request(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<Self::Request, ExternalCompositeDecryptorError>;
    /// Extract `(ecdh_ciphertext, ecdh_public, wrapped_session_key)` from the
    /// certificate and PKESK ciphertext, or the typed error to record.
    fn ecdh_components(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ExternalCompositeDecryptorError>;
    /// Derive the classical ECDH shared secret with the peer public key.
    fn classical_shared_secret(
        secret: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ClassicalComponentError>;
    /// Raw key-share bytes from the tier's carrier.
    fn share_raw(share: &Self::Share) -> &[u8];
    /// Combine the ML-KEM and ECDH key shares into the AES-256 KEK.
    fn combine(
        mlkem_key_share: &[u8],
        ecdh_key_share: &[u8],
        ecdh_ciphertext: &[u8],
        ecdh_public_key: &[u8],
    ) -> openpgp::Result<SessionKey>;
}

/// ML-KEM-768 + X25519 (RFC 9980 algorithm 35).
pub(crate) enum CompositeKem65Tier {}

impl CompositeKemTier for CompositeKem65Tier {
    type Request = ExternalMlKem768DecapsulationRequest;
    type Share = ExternalMlKem768Share;
    const KEY_SHARE_LENGTH: usize = composite_kem::MLKEM768_KEY_SHARE_LENGTH;

    fn validate_public_key(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Result<(), ExternalCompositeDecryptorError> {
        validate_composite_key_agreement_public_key(public_key)
    }

    fn cert_ecdh_public_key(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Option<Vec<u8>> {
        match public_key.mpis() {
            mpi::PublicKey::MLKEM768_X25519 { ecdh, .. } => Some(ecdh.to_vec()),
            _ => None,
        }
    }

    fn classical_public_key(secret: &[u8]) -> Result<Vec<u8>, ClassicalComponentError> {
        composite_classical::x25519_public_key(secret).map(|key| key.to_vec())
    }

    fn make_request(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<Self::Request, ExternalCompositeDecryptorError> {
        let mlkem_ciphertext = match ciphertext {
            mpi::Ciphertext::MLKEM768_X25519 { mlkem, .. } => mlkem.to_vec(),
            _ => {
                return Err(ExternalCompositeDecryptorError::InvalidRequest(
                    "external composite decryptor supports ML-KEM-768+X25519 ciphertext only",
                ))
            }
        };
        let recipient_mlkem_public_key = match public_key.mpis() {
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

    fn ecdh_components(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ExternalCompositeDecryptorError> {
        match (public_key.mpis(), ciphertext) {
            (
                mpi::PublicKey::MLKEM768_X25519 {
                    ecdh: ecdh_public, ..
                },
                mpi::Ciphertext::MLKEM768_X25519 {
                    ecdh: ecdh_ciphertext,
                    esk,
                    ..
                },
            ) => Ok((ecdh_ciphertext.to_vec(), ecdh_public.to_vec(), esk.to_vec())),
            _ => Err(ExternalCompositeDecryptorError::InvalidRequest(
                "external composite decryptor supports ML-KEM-768+X25519 ciphertext only",
            )),
        }
    }

    fn classical_shared_secret(
        secret: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ClassicalComponentError> {
        composite_classical::x25519_shared_secret(secret, peer_public_key)
    }

    fn share_raw(share: &Self::Share) -> &[u8] {
        &share.raw
    }

    fn combine(
        mlkem_key_share: &[u8],
        ecdh_key_share: &[u8],
        ecdh_ciphertext: &[u8],
        ecdh_public_key: &[u8],
    ) -> openpgp::Result<SessionKey> {
        composite_kem::multi_key_combine_mlkem768_x25519(
            mlkem_key_share,
            ecdh_key_share,
            ecdh_ciphertext,
            ecdh_public_key,
        )
    }
}

/// ML-KEM-1024 + X448 (RFC 9980 algorithm 36) — the · High tier.
pub(crate) enum CompositeKem87Tier {}

impl CompositeKemTier for CompositeKem87Tier {
    type Request = ExternalMlKem1024DecapsulationRequest;
    type Share = ExternalMlKem1024Share;
    const KEY_SHARE_LENGTH: usize = composite_kem::MLKEM1024_KEY_SHARE_LENGTH;

    fn validate_public_key(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Result<(), ExternalCompositeDecryptorError> {
        validate_composite_high_key_agreement_public_key(public_key)
    }

    fn cert_ecdh_public_key(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Option<Vec<u8>> {
        match public_key.mpis() {
            mpi::PublicKey::MLKEM1024_X448 { ecdh, .. } => Some(ecdh.to_vec()),
            _ => None,
        }
    }

    fn classical_public_key(secret: &[u8]) -> Result<Vec<u8>, ClassicalComponentError> {
        composite_classical::x448_public_key(secret).map(|key| key.to_vec())
    }

    fn make_request(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<Self::Request, ExternalCompositeDecryptorError> {
        let mlkem_ciphertext = match ciphertext {
            mpi::Ciphertext::MLKEM1024_X448 { mlkem, .. } => mlkem.to_vec(),
            _ => {
                return Err(ExternalCompositeDecryptorError::InvalidRequest(
                    "external composite decryptor supports ML-KEM-1024+X448 ciphertext only",
                ))
            }
        };
        let recipient_mlkem_public_key = match public_key.mpis() {
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

    fn ecdh_components(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        ciphertext: &mpi::Ciphertext,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ExternalCompositeDecryptorError> {
        match (public_key.mpis(), ciphertext) {
            (
                mpi::PublicKey::MLKEM1024_X448 {
                    ecdh: ecdh_public, ..
                },
                mpi::Ciphertext::MLKEM1024_X448 {
                    ecdh: ecdh_ciphertext,
                    esk,
                    ..
                },
            ) => Ok((ecdh_ciphertext.to_vec(), ecdh_public.to_vec(), esk.to_vec())),
            _ => Err(ExternalCompositeDecryptorError::InvalidRequest(
                "external composite decryptor supports ML-KEM-1024+X448 ciphertext only",
            )),
        }
    }

    fn classical_shared_secret(
        secret: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ClassicalComponentError> {
        composite_classical::x448_shared_secret(secret, peer_public_key)
    }

    fn share_raw(share: &Self::Share) -> &[u8] {
        &share.raw
    }

    fn combine(
        mlkem_key_share: &[u8],
        ecdh_key_share: &[u8],
        ecdh_ciphertext: &[u8],
        ecdh_public_key: &[u8],
    ) -> openpgp::Result<SessionKey> {
        composite_kem::multi_key_combine_mlkem1024_x448(
            mlkem_key_share,
            ecdh_key_share,
            ecdh_ciphertext,
            ecdh_public_key,
        )
    }
}

/// RFC 9980 composite ML-KEM + ECDH decryptor with split custody, generic over
/// the parameter-set tier.
///
/// The ECDH key share is derived inside Rust from the supplied classical
/// component secret; the ML-KEM decapsulation is delegated to the external
/// (Secure Enclave) callback. The vendored RFC 9980 KEM combiner and the
/// AES-256 key unwrap both stay on the Rust side, so the callback sees only
/// public material and returns only the 32-byte ML-KEM key share.
pub(crate) struct CompositeDecryptor<T, F>
where
    T: CompositeKemTier,
    F: FnMut(T::Request) -> Result<T::Share, ExternalCompositeDecryptorError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_ecdh_secret: Protected,
    decapsulation_operation: F,
    last_error: Option<ExternalCompositeDecryptorError>,
    _tier: PhantomData<fn() -> T>,
}

impl<T, F> CompositeDecryptor<T, F>
where
    T: CompositeKemTier,
    F: FnMut(T::Request) -> Result<T::Share, ExternalCompositeDecryptorError>,
{
    /// Build a composite decryptor after validating that the classical component
    /// secret matches the ECDH half bound into the certificate. A mismatched
    /// envelope payload fails closed here instead of deriving key shares that can
    /// never unwrap the session key.
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        classical_ecdh_secret: &[u8],
        decapsulation_operation: F,
    ) -> openpgp::Result<Self> {
        T::validate_public_key(&public_key)?;
        let expected_ecdh_public = T::cert_ecdh_public_key(&public_key).expect("validated above");

        let derived_ecdh_public =
            T::classical_public_key(classical_ecdh_secret).map_err(|error| {
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
            _tier: PhantomData,
        })
    }

    pub(crate) fn take_last_error(&mut self) -> Option<ExternalCompositeDecryptorError> {
        self.last_error.take()
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

    fn validate_key_share(key_share: &T::Share) -> Result<(), ExternalCompositeDecryptorError> {
        let raw = T::share_raw(key_share);
        if raw.len() != T::KEY_SHARE_LENGTH {
            return Err(ExternalCompositeDecryptorError::InvalidResponse(
                "external composite decryptor returned an invalid key share shape",
            ));
        }

        if raw.iter().all(|byte| *byte == 0) {
            return Err(ExternalCompositeDecryptorError::InvalidResponse(
                "external composite decryptor returned an invalid zero key share",
            ));
        }

        Ok(())
    }
}

impl<T, F> Decryptor for CompositeDecryptor<T, F>
where
    T: CompositeKemTier,
    F: FnMut(T::Request) -> Result<T::Share, ExternalCompositeDecryptorError> + Send + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        let request = match T::make_request(&self.public_key, ciphertext) {
            Ok(request) => request,
            Err(error) => return Err(self.record(error)),
        };

        let (ecdh_ciphertext, ecdh_public, wrapped_session_key) =
            match T::ecdh_components(&self.public_key, ciphertext) {
                Ok(components) => components,
                Err(error) => return Err(self.record(error)),
            };

        // Classical half first: it is cheap, deterministic, and failing here
        // avoids a user-visible Secure Enclave operation for broken key material.
        let ecdh_key_share =
            match T::classical_shared_secret(&self.classical_ecdh_secret, &ecdh_ciphertext) {
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
        let kek = T::combine(
            T::share_raw(&mlkem_key_share),
            &ecdh_key_share,
            &ecdh_ciphertext,
            &ecdh_public,
        )?;
        composite_kem::unwrap_session_key(&kek, &wrapped_session_key)
    }
}

/// ML-KEM-768 + X25519 split-custody decryptor (Device-Bound Post-Quantum).
pub(crate) type ExternalCompositeDecryptor<F> = CompositeDecryptor<CompositeKem65Tier, F>;

/// ML-KEM-1024 + X448 split-custody decryptor (Device-Bound Post-Quantum · High).
pub(crate) type ExternalCompositeHighDecryptor<F> = CompositeDecryptor<CompositeKem87Tier, F>;
