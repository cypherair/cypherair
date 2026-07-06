use std::sync::Arc;

use sequoia_openpgp as openpgp;

use openpgp::packet::{key, Key};

use crate::keys::{
    ExternalCompositeSigningError, ExternalMlDsa65SigningProvider, ExternalMlDsa87SigningProvider,
};

use super::{
    ExternalCompositeHighSigner, ExternalCompositeSigner, ExternalCompositeSignerError,
    ExternalMlDsa65SignatureBytes, ExternalMlDsa87SignatureBytes,
};

pub(crate) fn composite_signer_for_provider(
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_eddsa_secret: &[u8],
    provider: Arc<dyn ExternalMlDsa65SigningProvider>,
) -> openpgp::Result<
    ExternalCompositeSigner<
        impl FnMut(&[u8]) -> Result<ExternalMlDsa65SignatureBytes, ExternalCompositeSignerError>
            + Send
            + Sync,
    >,
> {
    ExternalCompositeSigner::new(public_key, classical_eddsa_secret, move |digest| {
        let signature = provider
            .sign_mldsa65_digest(digest.to_vec())
            .map_err(external_signing_error_to_signer_error)?;
        Ok(ExternalMlDsa65SignatureBytes::new(signature.raw))
    })
}

pub(crate) fn composite_high_signer_for_provider(
    public_key: Key<key::PublicParts, key::UnspecifiedRole>,
    classical_eddsa_secret: &[u8],
    provider: Arc<dyn ExternalMlDsa87SigningProvider>,
) -> openpgp::Result<
    ExternalCompositeHighSigner<
        impl FnMut(&[u8]) -> Result<ExternalMlDsa87SignatureBytes, ExternalCompositeSignerError>
            + Send
            + Sync,
    >,
> {
    ExternalCompositeHighSigner::new(public_key, classical_eddsa_secret, move |digest| {
        let signature = provider
            .sign_mldsa87_digest(digest.to_vec())
            .map_err(external_signing_error_to_signer_error)?;
        Ok(ExternalMlDsa87SignatureBytes::new(signature.raw))
    })
}

fn external_signing_error_to_signer_error(
    error: ExternalCompositeSigningError,
) -> ExternalCompositeSignerError {
    match error {
        ExternalCompositeSigningError::Failed { category } => {
            ExternalCompositeSignerError::ExternalFailure(category)
        }
        ExternalCompositeSigningError::OperationCancelled => {
            ExternalCompositeSignerError::OperationCancelled
        }
    }
}
