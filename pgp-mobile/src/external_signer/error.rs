use crate::error::PgpError;
use crate::keys::ExternalP256SigningFailureCategory;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ExternalP256SignerError {
    #[error("external P-256 signer invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("external P-256 signer invalid response: {0}")]
    InvalidResponse(&'static str),
    #[error("external P-256 signer failed: {}", .0.stable_reason())]
    ExternalFailure(ExternalP256SigningFailureCategory),
    #[error("external P-256 signer operation cancelled")]
    OperationCancelled,
}

impl ExternalP256SignerError {
    #[cfg(test)]
    pub(crate) fn external_operation_failed() -> Self {
        Self::ExternalFailure(ExternalP256SigningFailureCategory::ExternalOperationFailed)
    }
}

pub(crate) fn map_external_signing_error(
    error: sequoia_openpgp::anyhow::Error,
    fallback: impl FnOnce(String) -> PgpError,
) -> PgpError {
    if let Some(external_error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ExternalP256SignerError>().copied())
    {
        match external_error {
            ExternalP256SignerError::OperationCancelled => PgpError::OperationCancelled,
            ExternalP256SignerError::ExternalFailure(category) => {
                PgpError::ExternalP256SigningFailed { category }
            }
            ExternalP256SignerError::InvalidRequest(reason)
            | ExternalP256SignerError::InvalidResponse(reason) => fallback(reason.to_string()),
        }
    } else {
        fallback(error.to_string())
    }
}
