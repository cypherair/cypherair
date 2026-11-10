/// Encrypt, decrypt, sign and verify, for text and files.
@MainActor
public final class Messages {
    let session: OpenSession

    init(session: OpenSession) {
        self.session = session
    }
}

/// Whether a message to these recipients uses the modern container, and which
/// recipients hold it back.
public struct OutgoingFormat: Sendable, Equatable {
    public let modern: Bool
    public let heldBackBy: [Recipient]
}

public enum InputKind: Sendable {
    case encryptedMessage
    case signedMessage
    case detachedSignature
    case certificate
    case privateKey
    case revocation
    case unknown
}
