mod core;
mod error;
mod provider;

pub(crate) use core::{
    ExternalCompositeHighSigner, ExternalCompositeSigner, ExternalMlDsa65SignatureBytes,
    ExternalMlDsa87SignatureBytes,
};
pub(crate) use error::ExternalCompositeSignerError;
pub(crate) use provider::{composite_high_signer_for_provider, composite_signer_for_provider};

#[cfg(test)]
mod tests;
