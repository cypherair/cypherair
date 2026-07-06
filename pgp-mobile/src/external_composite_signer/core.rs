use std::marker::PhantomData;

use sequoia_openpgp as openpgp;

use openpgp::crypto::mem::Protected;
use openpgp::crypto::{mpi, Signer};
use openpgp::packet::{key, Key};
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};

use crate::composite_classical::{self, ClassicalComponentError};

pub(crate) const MLDSA65_SIGNATURE_LENGTH: usize = 3309;
pub(crate) const MLDSA87_SIGNATURE_LENGTH: usize = 4627;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalMlDsa65SignatureBytes {
    pub(crate) raw: Vec<u8>,
}

impl ExternalMlDsa65SignatureBytes {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalMlDsa87SignatureBytes {
    pub(crate) raw: Vec<u8>,
}

impl ExternalMlDsa87SignatureBytes {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }
}

/// The per-parameter-set deltas of an RFC 9980 composite (ML-DSA + EdDSA)
/// split-custody signer. Everything security-relevant — the classical-component
/// binding check, digest validation, and the self-verify-before-release step —
/// lives once in `CompositeSigner`; a tier supplies only the algorithm-specific
/// MPI shapes, classical curve operations, and signature length.
pub(crate) trait CompositeSignerTier {
    /// The ML-DSA signature carrier the external callback returns.
    type SignatureBytes;
    /// FIPS 204 ML-DSA signature length for this parameter set.
    const MLDSA_SIGNATURE_LENGTH: usize;
    /// Error detail when `new` is handed a public key that is not this tier's
    /// composite signing key.
    const REQUIRED_PUBLIC_KEY_DESCRIPTION: &'static str;
    /// Raw ML-DSA signature bytes from the carrier.
    fn signature_raw(signature: Self::SignatureBytes) -> Vec<u8>;
    /// The classical EdDSA public key bound into `public_key`, or `None` if it
    /// is not this tier's composite key.
    fn expected_eddsa_public(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Option<Vec<u8>>;
    /// Derive the classical EdDSA public key from the component secret.
    fn classical_public_key(secret: &[u8]) -> Result<Vec<u8>, ClassicalComponentError>;
    /// Produce the classical EdDSA signature over an OpenPGP signature digest.
    fn classical_sign(secret: &[u8], digest: &[u8]) -> Result<Vec<u8>, ClassicalComponentError>;
    /// Assemble the composite signature MPI from the two validated component
    /// signatures, or `None` if either has the wrong shape.
    fn build_signature(
        eddsa_signature: Vec<u8>,
        mldsa_signature: Vec<u8>,
    ) -> Option<mpi::Signature>;
}

/// ML-DSA-65 + Ed25519 (RFC 9980 algorithm 30).
pub(crate) enum CompositeSigner65Tier {}

impl CompositeSignerTier for CompositeSigner65Tier {
    type SignatureBytes = ExternalMlDsa65SignatureBytes;
    const MLDSA_SIGNATURE_LENGTH: usize = MLDSA65_SIGNATURE_LENGTH;
    const REQUIRED_PUBLIC_KEY_DESCRIPTION: &'static str =
        "external composite signer requires an ML-DSA-65+Ed25519 public key";

    fn signature_raw(signature: Self::SignatureBytes) -> Vec<u8> {
        signature.raw
    }

    fn expected_eddsa_public(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Option<Vec<u8>> {
        match (public_key.pk_algo(), public_key.mpis()) {
            (
                PublicKeyAlgorithm::MLDSA65_Ed25519,
                mpi::PublicKey::MLDSA65_Ed25519 { eddsa, .. },
            ) => Some(eddsa.to_vec()),
            _ => None,
        }
    }

    fn classical_public_key(secret: &[u8]) -> Result<Vec<u8>, ClassicalComponentError> {
        composite_classical::ed25519_public_key(secret).map(|key| key.to_vec())
    }

    fn classical_sign(secret: &[u8], digest: &[u8]) -> Result<Vec<u8>, ClassicalComponentError> {
        composite_classical::ed25519_sign(secret, digest).map(|signature| signature.to_vec())
    }

    fn build_signature(
        eddsa_signature: Vec<u8>,
        mldsa_signature: Vec<u8>,
    ) -> Option<mpi::Signature> {
        let eddsa: Box<[u8; composite_classical::ED25519_SIGNATURE_LENGTH]> =
            eddsa_signature.into_boxed_slice().try_into().ok()?;
        let mldsa: Box<[u8; MLDSA65_SIGNATURE_LENGTH]> =
            mldsa_signature.into_boxed_slice().try_into().ok()?;
        Some(mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa })
    }
}

/// ML-DSA-87 + Ed448 (RFC 9980 algorithm 31) — the · High tier.
pub(crate) enum CompositeSigner87Tier {}

impl CompositeSignerTier for CompositeSigner87Tier {
    type SignatureBytes = ExternalMlDsa87SignatureBytes;
    const MLDSA_SIGNATURE_LENGTH: usize = MLDSA87_SIGNATURE_LENGTH;
    const REQUIRED_PUBLIC_KEY_DESCRIPTION: &'static str =
        "external composite signer requires an ML-DSA-87+Ed448 public key";

    fn signature_raw(signature: Self::SignatureBytes) -> Vec<u8> {
        signature.raw
    }

    fn expected_eddsa_public(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
    ) -> Option<Vec<u8>> {
        match (public_key.pk_algo(), public_key.mpis()) {
            (PublicKeyAlgorithm::MLDSA87_Ed448, mpi::PublicKey::MLDSA87_Ed448 { eddsa, .. }) => {
                Some(eddsa.to_vec())
            }
            _ => None,
        }
    }

    fn classical_public_key(secret: &[u8]) -> Result<Vec<u8>, ClassicalComponentError> {
        composite_classical::ed448_public_key(secret).map(|key| key.to_vec())
    }

    fn classical_sign(secret: &[u8], digest: &[u8]) -> Result<Vec<u8>, ClassicalComponentError> {
        composite_classical::ed448_sign(secret, digest).map(|signature| signature.to_vec())
    }

    fn build_signature(
        eddsa_signature: Vec<u8>,
        mldsa_signature: Vec<u8>,
    ) -> Option<mpi::Signature> {
        let eddsa: Box<[u8; composite_classical::ED448_SIGNATURE_LENGTH]> =
            eddsa_signature.into_boxed_slice().try_into().ok()?;
        let mldsa: Box<[u8; MLDSA87_SIGNATURE_LENGTH]> =
            mldsa_signature.into_boxed_slice().try_into().ok()?;
        Some(mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa })
    }
}

/// RFC 9980 composite ML-DSA + EdDSA signer with split custody, generic over the
/// parameter-set tier.
///
/// The EdDSA half is computed inside Rust from the supplied classical component
/// secret; the ML-DSA half is delegated to the external (Secure Enclave)
/// callback. Both halves sign the same OpenPGP signature digest, and the
/// assembled composite signature is verified against the certificate's public
/// key before it is released — an unverified external response is never trusted.
pub(crate) struct CompositeSigner<T, F>
where
    T: CompositeSignerTier,
    F: FnMut(&[u8]) -> Result<T::SignatureBytes, super::ExternalCompositeSignerError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_eddsa_secret: Protected,
    sign_operation: F,
    _tier: PhantomData<fn() -> T>,
}

impl<T, F> CompositeSigner<T, F>
where
    T: CompositeSignerTier,
    F: FnMut(&[u8]) -> Result<T::SignatureBytes, super::ExternalCompositeSignerError>,
{
    /// Build a composite signer after validating that the classical component
    /// secret matches the EdDSA half bound into the certificate. A mismatched
    /// envelope payload fails closed here instead of producing signatures that
    /// can never verify.
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        classical_eddsa_secret: &[u8],
        sign_operation: F,
    ) -> openpgp::Result<Self> {
        let expected_eddsa_public = T::expected_eddsa_public(&public_key).ok_or_else(|| {
            openpgp::Error::InvalidOperation(T::REQUIRED_PUBLIC_KEY_DESCRIPTION.to_string())
        })?;

        let derived_eddsa_public =
            T::classical_public_key(classical_eddsa_secret).map_err(|error| {
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
            _tier: PhantomData,
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
        eddsa_signature: Vec<u8>,
        mldsa_signature: Vec<u8>,
    ) -> Result<mpi::Signature, super::ExternalCompositeSignerError> {
        if mldsa_signature.len() != T::MLDSA_SIGNATURE_LENGTH {
            return Err(super::ExternalCompositeSignerError::InvalidResponse(
                "external composite signer returned an invalid signature shape",
            ));
        }
        if mldsa_signature.iter().all(|byte| *byte == 0) {
            return Err(super::ExternalCompositeSignerError::InvalidResponse(
                "external composite signer returned an all-zero signature",
            ));
        }

        let signature = T::build_signature(eddsa_signature, mldsa_signature).ok_or(
            super::ExternalCompositeSignerError::InvalidResponse(
                "external composite signer returned an invalid signature shape",
            ),
        )?;

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

impl<T, F> Signer for CompositeSigner<T, F>
where
    T: CompositeSignerTier,
    F: FnMut(&[u8]) -> Result<T::SignatureBytes, super::ExternalCompositeSignerError> + Send + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        Self::validate_request(hash_algo, digest)?;
        let eddsa_signature =
            T::classical_sign(&self.classical_eddsa_secret, digest).map_err(|_| {
                super::ExternalCompositeSignerError::ClassicalComponentFailure(
                    "external composite signer classical component signing failed",
                )
            })?;
        let mldsa_signature = T::signature_raw((self.sign_operation)(digest)?);
        Ok(Self::validate_response(
            &self.public_key,
            hash_algo,
            digest,
            eddsa_signature,
            mldsa_signature,
        )?)
    }
}

/// ML-DSA-65 + Ed25519 split-custody signer (Device-Bound Post-Quantum).
pub(crate) type ExternalCompositeSigner<F> = CompositeSigner<CompositeSigner65Tier, F>;

/// ML-DSA-87 + Ed448 split-custody signer (Device-Bound Post-Quantum · High).
pub(crate) type ExternalCompositeHighSigner<F> = CompositeSigner<CompositeSigner87Tier, F>;
