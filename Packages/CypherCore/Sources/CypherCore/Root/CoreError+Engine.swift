internal import CypherEngine

/// The mapping from the engine's errors. `recipients` are the recipients in
/// the order the engine was given them, so that a position can name one.
extension CoreError {
    init(_ error: EngineError, recipients: [Recipient] = []) {
        self = switch error {
        case .Malformed: .notOpenPGP
        case .WrongKind: .wrongKindOfData
        case .Unsupported: .unsupported
        case .LimitsExceeded, .KdfOutOfRange: .tooComplex
        case .KeyExpired: .keyExpired
        case .KeyRevoked: .keyRevoked
        case .KeyUnusable: .keyUnusable
        case .KeyMismatch: .keyMaterialMissing
        case .NotExportable: .notExportable
        case .WrongPassphrase: .wrongPassphrase
        case .RecipientUnusable(let position):
            Int(exactly: position).flatMap { recipients.indices.contains($0) ? CoreError.recipientUnusable(recipients[$0]) : nil } ?? .internalFailure
        case .NoMatchingKey: .noMatchingKey
        case .Tampered: .tampered
        case .Cancelled: .cancelled
        case .DeviceNotAuthenticated: .authenticationFailed
        case .DeviceFailed: .deviceKeyFailed
        case .OutOfSpace: .outOfSpace
        case .FileFailed: .fileFailed
        case .TimeOutOfRange, .Internal: .internalFailure
        }
    }
}
