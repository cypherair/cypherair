import LocalAuthentication
import os

/// The constraint an approval satisfies. It follows the key: a portable key is
/// sealed under the identity wrapping key, which allows the device passcode as
/// the system's fallback; a device-bound key demands biometrics alone.
public enum ApprovalKind: Sendable {
    case presence
    case biometrics
}

/// One evaluated authentication context for one private-key operation.
///
/// The context has passed its one evaluation and disallows interaction, so the
/// enclave calls that consume it can never show a sheet of their own. Ending
/// the approval, or releasing it, invalidates the context, and every call that
/// takes an approval refuses one that has ended or whose session is locked.
///
/// The approval belongs to the session that gave it, and its consumers take
/// the identity credential from that session.
///
/// `@unchecked Sendable` carries the context off the caller's actor to the one
/// operation that consumes it; the operation uses it on one thread.
public final class OperationApproval: @unchecked Sendable {
    public let kind: ApprovalKind
    package let context: LAContext
    package let session: UnlockedSession
    private let ended = OSAllocatedUnfairLock(initialState: false)

    init(kind: ApprovalKind, context: LAContext, session: UnlockedSession) {
        self.kind = kind
        self.context = context
        self.session = session
    }

    public func end() {
        ended.withLock { $0 = true }
        context.invalidate()
    }

    /// Throws unless the approval may still be used: not ended, and its
    /// session not locked.
    package func checkUsable() throws(VaultError) {
        guard !ended.withLock({ $0 }) else { throw .approvalEnded }
        guard !session.isLocked else { throw .locked }
    }

    deinit {
        context.invalidate()
    }
}
