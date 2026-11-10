//! The engine's one error type, and the only place where a Sequoia error
//! becomes one.

use sequoia_openpgp as openpgp;

use crate::bounded_walk;

/// Every failure the engine reports. It is `Copy`, so it cannot carry text;
/// where an error points at a recipient, it carries the recipient's position
/// in the list the caller passed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error, uniffi::Error)]
pub enum EngineError {
    /// Not OpenPGP data, or damaged before any key was tried.
    #[error("malformed")]
    Malformed,
    /// Valid, but not what this function takes.
    #[error("wrong kind")]
    WrongKind,
    /// Valid OpenPGP that this engine refuses or cannot handle.
    #[error("unsupported")]
    Unsupported,
    /// A bound on hostile input fired.
    #[error("limits exceeded")]
    LimitsExceeded,
    #[error("key expired")]
    KeyExpired,
    #[error("key revoked")]
    KeyRevoked,
    /// No key in the certificate can do this.
    #[error("key unusable")]
    KeyUnusable,
    /// The secret key does not belong to the certificate.
    #[error("key mismatch")]
    KeyMismatch,
    #[error("not exportable")]
    NotExportable,
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// A key derivation asked for parameters outside the allowed range.
    #[error("key derivation out of range")]
    KdfOutOfRange,
    #[error("recipient unusable")]
    RecipientUnusable { position: u32 },
    #[error("no matching key")]
    NoMatchingKey,
    #[error("tampered")]
    Tampered,
    #[error("cancelled")]
    Cancelled,
    #[error("device not authenticated")]
    DeviceNotAuthenticated,
    #[error("device failed")]
    DeviceFailed,
    #[error("out of space")]
    OutOfSpace,
    #[error("file failed")]
    FileFailed,
    /// A failure no input can cause, or a caller that broke a precondition.
    #[error("internal")]
    Internal,
}

/// Runs the body of an exported function. Every exported function runs its
/// body through this, so that a panic anywhere below the boundary becomes
/// `Internal`: it neither crashes the app nor reaches Swift as UniFFI's panic
/// error, which would carry the panic's text.
pub(crate) fn contained<T>(
    body: impl FnOnce() -> Result<T, EngineError>,
) -> Result<T, EngineError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
        .unwrap_or(Err(EngineError::Internal))
}

impl EngineError {
    /// For a Sequoia failure on a path that only the engine's own data reaches:
    /// generating, serializing, signing with a software key.
    pub(crate) fn internal(_: openpgp::anyhow::Error) -> Self {
        Self::Internal
    }
}

/// How far a decryption got before it failed.
///
/// Sequoia reports a failed decryption without saying where it happened, and
/// it swallows the error a decryption helper returns. So the helper records
/// both as it goes, and the failure is classified from that record.
#[derive(Default)]
pub(crate) struct DecryptionProgress {
    /// The helper's own verdict on the session-key packets, when it refused.
    pub(crate) refusal: std::cell::Cell<Option<EngineError>>,
    /// A session key was unwrapped and accepted by the container.
    pub(crate) unwrapped: std::cell::Cell<bool>,
}

/// The error of a failed decryption. The first line that applies wins:
/// a bound that fired, then the helper's refusal, then any failure after the
/// session key was unwrapped, and otherwise input that did not parse.
pub(crate) fn failed_decryption(
    error: &openpgp::anyhow::Error,
    progress: &DecryptionProgress,
) -> EngineError {
    if bounded_walk::is_bound(error) {
        EngineError::LimitsExceeded
    } else if let Some(refusal) = progress.refusal.get() {
        refusal
    } else if progress.unwrapped.get() {
        EngineError::Tampered
    } else {
        EngineError::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like every exported function, and present only in test builds.
    fn export_that_panics() -> Result<(), EngineError> {
        contained(|| panic!("a deliberate panic below the boundary"))
    }

    #[test]
    fn e3_panic_below_the_boundary_is_internal() {
        assert_eq!(export_that_panics(), Err(EngineError::Internal));
    }
}
