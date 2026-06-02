mod core;
mod error;
mod provider;

#[cfg(test)]
pub(crate) use core::P256_SCALAR_LENGTH;
pub(crate) use core::{ExternalP256Signature, ExternalP256Signer};
pub(crate) use error::{map_external_signing_error, ExternalP256SignerError};
pub(crate) use provider::signer_for_provider;

#[cfg(test)]
mod tests;
