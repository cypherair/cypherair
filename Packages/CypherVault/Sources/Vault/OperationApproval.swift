import LocalAuthentication

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
/// the approval, or releasing it, invalidates the context.
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

    init(kind: ApprovalKind, context: LAContext, session: UnlockedSession) {
        self.kind = kind
        self.context = context
        self.session = session
    }

    public func end() {
        context.invalidate()
    }

    deinit {
        context.invalidate()
    }
}
