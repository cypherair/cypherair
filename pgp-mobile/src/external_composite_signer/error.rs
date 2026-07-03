use crate::keys::ExternalCompositeSigningFailureCategory;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ExternalCompositeSignerError {
    #[error("external composite signer invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("external composite signer invalid response: {0}")]
    InvalidResponse(&'static str),
    #[error("external composite signer classical component failed: {0}")]
    ClassicalComponentFailure(&'static str),
    #[error("external composite signer failed: {}", .0.stable_reason())]
    ExternalFailure(ExternalCompositeSigningFailureCategory),
    #[error("external composite signer operation cancelled")]
    OperationCancelled,
}

impl ExternalCompositeSignerError {
    #[cfg(test)]
    pub(crate) fn external_operation_failed() -> Self {
        Self::ExternalFailure(ExternalCompositeSigningFailureCategory::ExternalOperationFailed)
    }
}
