mod core;
mod error;
mod provider;

pub(crate) use core::{ExternalCompositeSigner, ExternalMlDsa65SignatureBytes};
pub(crate) use error::ExternalCompositeSignerError;
pub(crate) use provider::composite_signer_for_provider;

#[cfg(test)]
mod tests;
