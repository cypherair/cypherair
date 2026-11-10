//! The engine's one error type, the containment of panics, and the
//! classification of a failed decryption or stream. Elsewhere a Sequoia error is
//! replaced by the error its place implies; no code reads an error's text.

use std::cell::Cell;
use std::fmt;
use std::sync::Once;

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
    /// The secret key or the classical halves do not belong to the certificate.
    #[error("key mismatch")]
    KeyMismatch,
    #[error("not exportable")]
    NotExportable,
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// A key derivation asked for parameters outside the allowed range.
    #[error("key derivation out of range")]
    KdfOutOfRange,
    /// A later stamp that is not strictly later, or a time beyond OpenPGP's
    /// 32-bit range.
    #[error("time out of range")]
    TimeOutOfRange,
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

thread_local! {
    /// Whether this thread is inside `contained`, where a panic is caught.
    static CONTAINING: Cell<bool> = const { Cell::new(false) };
}

/// Runs the body of an exported function. Every exported function runs its
/// body through this, so that a panic anywhere below the boundary becomes
/// `Internal`: it neither crashes the app nor reaches Swift as UniFFI's panic
/// error, which would carry the panic's text.
///
/// A caught panic is also kept off standard error: the first call wraps the
/// process's panic hook so that it stays silent inside `contained` and works
/// as before everywhere else. The engine is the only Rust code in the app. The
/// accepted cost: a panic inside `contained` that cannot unwind, such as one
/// during another panic's unwinding, aborts the app without a message; the
/// crash report still has the stack.
pub(crate) fn contained<T>(
    body: impl FnOnce() -> Result<T, EngineError>,
) -> Result<T, EngineError> {
    static QUIET_HOOK: Once = Once::new();
    QUIET_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !CONTAINING.with(Cell::get) {
                previous(info);
            }
        }));
    });
    let outer = CONTAINING.with(|containing| containing.replace(true));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    CONTAINING.with(|containing| containing.set(outer));
    result.unwrap_or(Err(EngineError::Internal))
}

impl EngineError {
    /// For a Sequoia failure on a path that only the engine's own data reaches:
    /// generating, serializing, signing with a software key.
    pub(crate) fn internal(_: openpgp::anyhow::Error) -> Self {
        Self::Internal
    }
}

/// The device failed, refused or was cancelled while it signed. Its own type,
/// so that it can be recognised after the trip through Sequoia, which reports
/// a signer's error as one failure among others.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeviceFailure(pub(crate) EngineError);

impl fmt::Display for DeviceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the device failed")
    }
}

impl std::error::Error for DeviceFailure {}

impl DeviceFailure {
    /// Hand the failure to Sequoia as an `io::Error`, the shape that survives
    /// every route through its writers and readers, as a bound does.
    pub(crate) fn into_sequoia_error(self) -> openpgp::anyhow::Error {
        std::io::Error::other(self).into()
    }
}

/// The device failure an error chain carries, also inside `io::Error`s,
/// whose `source()` skips the error they wrap.
fn device_failure(error: &openpgp::anyhow::Error) -> Option<EngineError> {
    fn inside(error: &(dyn std::error::Error + 'static)) -> Option<EngineError> {
        if let Some(DeviceFailure(failure)) = error.downcast_ref::<DeviceFailure>() {
            return Some(*failure);
        }
        error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .and_then(|inner| inside(inner))
    }
    error.chain().find_map(inside)
}

/// The error of a Sequoia step that failed outside a decryption: writing or
/// finishing a stream, or making a signature. A bound that fired is
/// `LimitsExceeded`, a failure of the device is its own case, anything else is
/// `Internal`.
pub(crate) fn failed_operation(error: &openpgp::anyhow::Error) -> EngineError {
    if bounded_walk::is_bound(error) {
        EngineError::LimitsExceeded
    } else if let Some(failure) = device_failure(error) {
        failure
    } else {
        EngineError::Internal
    }
}

/// How far a decryption got before it failed.
///
/// Sequoia reports a failed decryption without saying where it happened, and
/// it swallows the error a decryption helper returns. So the helper records
/// both as it goes, and the failure is classified from that record.
pub(crate) struct DecryptionProgress {
    /// The container is the old one (SEIPDv1), which proves that it is
    /// genuine only at its end.
    pub(crate) old_container: bool,
    /// The device failed, refused or was cancelled while it unwrapped.
    pub(crate) device: Cell<Option<EngineError>>,
    /// The helper's own verdict on the session-key packets, when it refused.
    pub(crate) refusal: Cell<Option<EngineError>>,
    /// A session key was unwrapped and accepted by the container.
    pub(crate) unwrapped: Cell<bool>,
}

impl DecryptionProgress {
    pub(crate) fn new(old_container: bool) -> Self {
        Self {
            old_container,
            device: Cell::new(None),
            refusal: Cell::new(None),
            unwrapped: Cell::new(false),
        }
    }
}

/// What stopped a decryption.
pub(crate) enum DecryptionFailure<'a> {
    /// An error out of Sequoia.
    Sequoia(&'a openpgp::anyhow::Error),
    /// The plaintext grew past what decrypting into memory may hold.
    Ceiling,
}

/// The error of a failed decryption. The first line that applies wins:
///
/// 1. A bound fired, or the plaintext ceiling: `LimitsExceeded`. Not once a
///    session key was unwrapped in the old container: until its end, that
///    container's content may have been changed, so nothing the content
///    decides is reported.
/// 2. The device failed, refused or was cancelled: that error. A failure of
///    the device is not a failure of the message.
/// 3. A session key was unwrapped: `Tampered`, also for a refusal from a later
///    call of the helper for a nested container.
/// 4. The helper's refusal.
/// 5. Input that did not parse: `Malformed`.
pub(crate) fn failed_decryption(
    failure: DecryptionFailure,
    progress: &DecryptionProgress,
) -> EngineError {
    let bound = match failure {
        DecryptionFailure::Sequoia(error) => bounded_walk::is_bound(error),
        DecryptionFailure::Ceiling => true,
    };
    if bound && !(progress.unwrapped.get() && progress.old_container) {
        EngineError::LimitsExceeded
    } else if let Some(failure) = progress.device.get() {
        failure
    } else if progress.unwrapped.get() {
        EngineError::Tampered
    } else if let Some(refusal) = progress.refusal.get() {
        refusal
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
