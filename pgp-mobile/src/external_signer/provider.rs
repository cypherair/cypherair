use std::sync::Arc;

use sequoia_openpgp as openpgp;

use openpgp::packet::{key, Key};
use openpgp::types::HashAlgorithm;

use crate::keys::{ExternalP256SigningError, ExternalP256SigningProvider};

use super::{ExternalP256Signature, ExternalP256Signer, ExternalP256SignerError};

pub(crate) fn signer_for_provider(
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    provider: Arc<dyn ExternalP256SigningProvider>,
) -> openpgp::Result<
    ExternalP256Signer<
        impl FnMut(HashAlgorithm, &[u8]) -> Result<ExternalP256Signature, ExternalP256SignerError>
            + Send
            + Sync,
    >,
> {
    ExternalP256Signer::new(public_key, move |hash_algorithm, digest| {
        if hash_algorithm != HashAlgorithm::SHA256 {
            return Err(ExternalP256SignerError::InvalidRequest(
                "external P-256 signer supports SHA-256 only",
            ));
        }
        let signature = provider
            .sign_sha256_digest(digest.to_vec())
            .map_err(external_signing_error_to_signer_error)?;
        Ok(ExternalP256Signature::new(signature.r, signature.s))
    })
}

fn external_signing_error_to_signer_error(
    error: ExternalP256SigningError,
) -> ExternalP256SignerError {
    match error {
        ExternalP256SigningError::Failed { category } => {
            ExternalP256SignerError::ExternalFailure(category)
        }
        ExternalP256SigningError::OperationCancelled => ExternalP256SignerError::OperationCancelled,
    }
}
