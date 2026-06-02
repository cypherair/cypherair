use sequoia_openpgp as openpgp;

use openpgp::crypto::{mpi, Signer};
use openpgp::packet::{key, Key};
use openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

pub(crate) const P256_SCALAR_LENGTH: usize = 32;
const P256_ACCEPTABLE_HASHES: &[HashAlgorithm] = &[HashAlgorithm::SHA256];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalP256Signature {
    pub(crate) r: Vec<u8>,
    pub(crate) s: Vec<u8>,
}

impl ExternalP256Signature {
    pub(crate) fn new(r: Vec<u8>, s: Vec<u8>) -> Self {
        Self { r, s }
    }
}

pub(crate) struct ExternalP256Signer<F>
where
    F: FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, super::ExternalP256SignerError>,
{
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    sign_operation: F,
}

impl<F> ExternalP256Signer<F>
where
    F: FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, super::ExternalP256SignerError>,
{
    pub(crate) fn new(
        public_key: Key<key::PublicParts, key::UnspecifiedRole>,
        sign_operation: F,
    ) -> openpgp::Result<Self> {
        match (public_key.pk_algo(), public_key.mpis()) {
            (
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA {
                    curve: Curve::NistP256,
                    ..
                },
            ) => Ok(Self {
                public_key,
                sign_operation,
            }),
            _ => Err(openpgp::Error::InvalidOperation(
                "external P-256 signer requires an ECDSA P-256 public key".to_string(),
            )
            .into()),
        }
    }

    fn validate_request(
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<(), super::ExternalP256SignerError> {
        if hash_algo != HashAlgorithm::SHA256 {
            return Err(super::ExternalP256SignerError::InvalidRequest(
                "external P-256 signer supports SHA-256 only",
            ));
        }

        if digest.len() != P256_SCALAR_LENGTH {
            return Err(super::ExternalP256SignerError::InvalidRequest(
                "external P-256 signer received an invalid digest length",
            ));
        }

        Ok(())
    }

    fn validate_response(
        public_key: &Key<key::PublicParts, key::UnspecifiedRole>,
        hash_algo: HashAlgorithm,
        digest: &[u8],
        signature: ExternalP256Signature,
    ) -> Result<mpi::Signature, super::ExternalP256SignerError> {
        if signature.r.len() != P256_SCALAR_LENGTH || signature.s.len() != P256_SCALAR_LENGTH {
            return Err(super::ExternalP256SignerError::InvalidResponse(
                "external P-256 signer returned an invalid signature shape",
            ));
        }

        if signature.r.iter().all(|byte| *byte == 0) || signature.s.iter().all(|byte| *byte == 0) {
            return Err(super::ExternalP256SignerError::InvalidResponse(
                "external P-256 signer returned an invalid zero scalar",
            ));
        }

        let signature = mpi::Signature::ECDSA {
            r: mpi::MPI::new(&signature.r),
            s: mpi::MPI::new(&signature.s),
        };

        public_key
            .verify(&signature, hash_algo, digest)
            .map_err(|_| {
                super::ExternalP256SignerError::InvalidResponse(
                    "external P-256 signer returned an unverified signature",
                )
            })?;

        Ok(signature)
    }
}

impl<F> Signer for ExternalP256Signer<F>
where
    F: FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, super::ExternalP256SignerError>
        + Send
        + Sync,
{
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public_key
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        P256_ACCEPTABLE_HASHES
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> openpgp::Result<mpi::Signature> {
        Self::validate_request(hash_algo, digest)?;
        let signature = (self.sign_operation)(hash_algo, digest)?;
        Ok(Self::validate_response(
            &self.public_key,
            hash_algo,
            digest,
            signature,
        )?)
    }
}
