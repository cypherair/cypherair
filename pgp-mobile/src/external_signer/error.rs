use crate::error::PgpError;
use crate::external_composite_signer::ExternalCompositeSignerError;
use crate::keys::{ExternalCompositeSigningFailureCategory, ExternalP256SigningFailureCategory};

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

/// Map any typed external-signer failure buried in an error chain to its
/// `PgpError`, falling back to the caller's generic mapping.
///
/// Shared signing pipelines (`sign_cleartext_with_signer`, message/streaming
/// finalize, detached signing) are generic over `Signer`, so a single chain
/// may carry either the P-256 or the composite signer error; both downcasts
/// are attempted here so neither custody family degrades typed failures
/// (cancellation, sanitized categories) into opaque strings.
pub(crate) fn map_external_signing_error(
    error: sequoia_openpgp::anyhow::Error,
    fallback: impl FnOnce(String) -> PgpError,
) -> PgpError {
    if let Some(external_error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ExternalP256SignerError>().copied())
    {
        return match external_error {
            ExternalP256SignerError::OperationCancelled => PgpError::OperationCancelled,
            ExternalP256SignerError::ExternalFailure(category) => {
                PgpError::ExternalP256SigningFailed { category }
            }
            ExternalP256SignerError::InvalidRequest(reason)
            | ExternalP256SignerError::InvalidResponse(reason) => fallback(reason.to_string()),
        };
    }

    if let Some(external_error) = error.chain().find_map(|cause| {
        cause
            .downcast_ref::<ExternalCompositeSignerError>()
            .copied()
    }) {
        return match external_error {
            ExternalCompositeSignerError::OperationCancelled => PgpError::OperationCancelled,
            ExternalCompositeSignerError::ExternalFailure(category) => {
                PgpError::ExternalCompositeSigningFailed { category }
            }
            ExternalCompositeSignerError::ClassicalComponentFailure(_) => {
                PgpError::ExternalCompositeSigningFailed {
                    category: ExternalCompositeSigningFailureCategory::ClassicalComponentFailed,
                }
            }
            ExternalCompositeSignerError::InvalidRequest(reason)
            | ExternalCompositeSignerError::InvalidResponse(reason) => fallback(reason.to_string()),
        };
    }

    fallback(error.to_string())
}
