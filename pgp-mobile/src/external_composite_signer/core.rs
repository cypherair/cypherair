use sequoia_openpgp as openpgp;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::{mpi, Signer};
use openpgp::packet::{key, Key};
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};

use crate::composite_classical;

pub(crate) const MLDSA65_SIGNATURE_LENGTH: usize = 3309;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalMlDsa65SignatureBytes {
    pub(crate) raw: Vec<u8>,
}

impl ExternalMlDsa65SignatureBytes {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }
}

/// RFC 9980 composite ML-DSA-65 + Ed25519 signer with split custody.
///
/// The Ed25519 half is computed inside Rust from the supplied classical
/// component secret; the ML-DSA-65 half is delegated to the external
/// (Secure Enclave) callback. Both halves sign the same OpenPGP signature
/// digest, and the assembled composite signature is verified against the
/// certificate's public key before it is released — an unverified external
/// response is never trusted.
pub(crate) struct ExternalCompositeSigner<F>
where
    F: FnMut(&[u8]) -> Result<ExternalMlDsa65SignatureBytes, super::ExternalCompositeSignerError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_eddsa_secret: Protected,
    sign_operation: F,
}

impl<F> ExternalCompositeSigner<F>
where
    F: FnMut(&[u8]) -> Result<ExternalMlDsa65SignatureBytes, super::ExternalCompositeSignerError>,
{
    /// Build a composite signer after validating that the classical component
    /// secret matches the Ed25519 half bound into the certificate. A mismatched
    /// envelope payload fails closed here instead of producing signatures that
    /// can never verify.
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        classical_eddsa_secret: &[u8],
        sign_operation: F,
    ) -> openpgp::Result<Self> {
        let expected_eddsa_public = match (public_key.pk_algo(), public_key.mpis()) {
            (
                PublicKeyAlgorithm::MLDSA65_Ed25519,
                mpi::PublicKey::MLDSA65_Ed25519 { eddsa, .. },
            ) => **eddsa,
            _ => {
                return Err(openpgp::Error::InvalidOperation(
                    "external composite signer requires an ML-DSA-65+Ed25519 public key"
                        .to_string(),
                )
                .into())
            }
        };

        let derived_eddsa_public = composite_classical::ed25519_public_key(classical_eddsa_secret)
            .map_err(|error| {
                openpgp::Error::InvalidOperation(format!(
                    "external composite signer rejected the classical component: {error}"
                ))
            })?;
        if derived_eddsa_public != expected_eddsa_public {
            return Err(openpgp::Error::InvalidOperation(
                "external composite signer classical component does not match the certificate"
                    .to_string(),
            )
            .into());
        }

        Ok(Self {
            public_key,
            classical_eddsa_secret: Protected::from(classical_eddsa_secret),
            sign_operation,
        })
    }

    fn validate_request(
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<(), super::ExternalCompositeSignerError> {
        let expected_length = hash_algo.digest_size().map_err(|_| {
            super::ExternalCompositeSignerError::InvalidRequest(
                "external composite signer received an unsupported hash algorithm",
            )
        })?;
        if digest.len() != expected_length {
            return Err(super::ExternalCompositeSignerError::InvalidRequest(
                "external composite signer received an invalid digest length",
            ));
        }

        Ok(())
    }

    fn validate_response(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        hash_algo: HashAlgorithm,
        digest: &[u8],
        eddsa_signature: [u8; composite_classical::ED25519_SIGNATURE_LENGTH],
        mldsa_signature: ExternalMlDsa65SignatureBytes,
    ) -> Result<mpi::Signature, super::ExternalCompositeSignerError> {
        if mldsa_signature.raw.len() != MLDSA65_SIGNATURE_LENGTH {
            return Err(super::ExternalCompositeSignerError::InvalidResponse(
                "external composite signer returned an invalid signature shape",
            ));
        }
        if mldsa_signature.raw.iter().all(|byte| *byte == 0) {
            return Err(super::ExternalCompositeSignerError::InvalidResponse(
                "external composite signer returned an all-zero signature",
            ));
        }

        let mldsa: Box<[u8; MLDSA65_SIGNATURE_LENGTH]> = mldsa_signature
            .raw
            .into_boxed_slice()
            .try_into()
            .map_err(|_| {
                super::ExternalCompositeSignerError::InvalidResponse(
                    "external composite signer returned an invalid signature shape",
                )
            })?;

        let signature = mpi::Signature::MLDSA65_Ed25519 {
            eddsa: Box::new(eddsa_signature),
            mldsa,
        };

        // RFC 9980 composite verification is an AND over both component
        // signatures, so this also proves the external ML-DSA half.
        public_key
            .verify(&signature, hash_algo, digest)
            .map_err(|_| {
                super::ExternalCompositeSignerError::InvalidResponse(
                    "external composite signer returned an unverified signature",
                )
            })?;

        Ok(signature)
    }
}

impl<F> Signer for ExternalCompositeSigner<F>
where
    F: FnMut(&[u8]) -> Result<ExternalMlDsa65SignatureBytes, super::ExternalCompositeSignerError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        Self::validate_request(hash_algo, digest)?;
        let eddsa_signature =
            composite_classical::ed25519_sign(&self.classical_eddsa_secret, digest).map_err(
                |_| {
                    super::ExternalCompositeSignerError::ClassicalComponentFailure(
                        "external composite signer classical component signing failed",
                    )
                },
            )?;
        let mldsa_signature = (self.sign_operation)(digest)?;
        Ok(Self::validate_response(
            &self.public_key,
            hash_algo,
            digest,
            eddsa_signature,
            mldsa_signature,
        )?)
    }
}

pub(crate) const MLDSA87_SIGNATURE_LENGTH: usize = 4627;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalMlDsa87SignatureBytes {
    pub(crate) raw: Vec<u8>,
}

impl ExternalMlDsa87SignatureBytes {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }
}

/// RFC 9980 composite ML-DSA-87 + Ed448 signer with split custody (· High tier).
///
/// The Ed448 half is computed inside Rust from the supplied classical component
/// secret; the ML-DSA-87 half is delegated to the external (Secure Enclave)
/// callback. Both halves sign the same OpenPGP signature digest, and the
/// assembled composite signature is verified against the certificate's public
/// key before it is released — an unverified external response is never trusted.
pub(crate) struct ExternalCompositeHighSigner<F>
where
    F: FnMut(&[u8]) -> Result<ExternalMlDsa87SignatureBytes, super::ExternalCompositeSignerError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_eddsa_secret: Protected,
    sign_operation: F,
}

impl<F> ExternalCompositeHighSigner<F>
where
    F: FnMut(&[u8]) -> Result<ExternalMlDsa87SignatureBytes, super::ExternalCompositeSignerError>,
{
    /// Build a · High composite signer after validating that the classical
    /// component secret matches the Ed448 half bound into the certificate. A
    /// mismatched envelope payload fails closed here instead of producing
    /// signatures that can never verify.
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        classical_eddsa_secret: &[u8],
        sign_operation: F,
    ) -> openpgp::Result<Self> {
        let expected_eddsa_public = match (public_key.pk_algo(), public_key.mpis()) {
            (PublicKeyAlgorithm::MLDSA87_Ed448, mpi::PublicKey::MLDSA87_Ed448 { eddsa, .. }) => {
                **eddsa
            }
            _ => {
                return Err(openpgp::Error::InvalidOperation(
                    "external composite signer requires an ML-DSA-87+Ed448 public key".to_string(),
                )
                .into())
            }
        };

        let derived_eddsa_public = composite_classical::ed448_public_key(classical_eddsa_secret)
            .map_err(|error| {
                openpgp::Error::InvalidOperation(format!(
                    "external composite signer rejected the classical component: {error}"
                ))
            })?;
        if derived_eddsa_public != expected_eddsa_public {
            return Err(openpgp::Error::InvalidOperation(
                "external composite signer classical component does not match the certificate"
                    .to_string(),
            )
            .into());
        }

        Ok(Self {
            public_key,
            classical_eddsa_secret: Protected::from(classical_eddsa_secret),
            sign_operation,
        })
    }

    fn validate_request(
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<(), super::ExternalCompositeSignerError> {
        let expected_length = hash_algo.digest_size().map_err(|_| {
            super::ExternalCompositeSignerError::InvalidRequest(
                "external composite signer received an unsupported hash algorithm",
            )
        })?;
        if digest.len() != expected_length {
            return Err(super::ExternalCompositeSignerError::InvalidRequest(
                "external composite signer received an invalid digest length",
            ));
        }

        Ok(())
    }

    fn validate_response(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        hash_algo: HashAlgorithm,
        digest: &[u8],
        eddsa_signature: [u8; composite_classical::ED448_SIGNATURE_LENGTH],
        mldsa_signature: ExternalMlDsa87SignatureBytes,
    ) -> Result<mpi::Signature, super::ExternalCompositeSignerError> {
        if mldsa_signature.raw.len() != MLDSA87_SIGNATURE_LENGTH {
            return Err(super::ExternalCompositeSignerError::InvalidResponse(
                "external composite signer returned an invalid signature shape",
            ));
        }
        if mldsa_signature.raw.iter().all(|byte| *byte == 0) {
            return Err(super::ExternalCompositeSignerError::InvalidResponse(
                "external composite signer returned an all-zero signature",
            ));
        }

        let mldsa: Box<[u8; MLDSA87_SIGNATURE_LENGTH]> = mldsa_signature
            .raw
            .into_boxed_slice()
            .try_into()
            .map_err(|_| {
                super::ExternalCompositeSignerError::InvalidResponse(
                    "external composite signer returned an invalid signature shape",
                )
            })?;

        let signature = mpi::Signature::MLDSA87_Ed448 {
            eddsa: Box::new(eddsa_signature),
            mldsa,
        };

        // RFC 9980 composite verification is an AND over both component
        // signatures, so this also proves the external ML-DSA half.
        public_key
            .verify(&signature, hash_algo, digest)
            .map_err(|_| {
                super::ExternalCompositeSignerError::InvalidResponse(
                    "external composite signer returned an unverified signature",
                )
            })?;

        Ok(signature)
    }
}

impl<F> Signer for ExternalCompositeHighSigner<F>
where
    F: FnMut(&[u8]) -> Result<ExternalMlDsa87SignatureBytes, super::ExternalCompositeSignerError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        Self::validate_request(hash_algo, digest)?;
        let eddsa_signature = composite_classical::ed448_sign(&self.classical_eddsa_secret, digest)
            .map_err(|_| {
                super::ExternalCompositeSignerError::ClassicalComponentFailure(
                    "external composite signer classical component signing failed",
                )
            })?;
        let mldsa_signature = (self.sign_operation)(digest)?;
        Ok(Self::validate_response(
            &self.public_key,
            hash_algo,
            digest,
            eddsa_signature,
            mldsa_signature,
        )?)
    }
}
