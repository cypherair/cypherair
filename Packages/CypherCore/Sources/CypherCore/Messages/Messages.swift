/// Encrypt, decrypt, sign and verify, for text and files.
@MainActor
public final class Messages {
    let session: OpenSession
    let composition: Composition
    let keys: Keys
    let contacts: Contacts
    weak var core: AppCore?

    init(session: OpenSession, composition: Composition, core: AppCore?, keys: Keys, contacts: Contacts) {
        self.session = session
        self.composition = composition
        self.core = core
        self.keys = keys
        self.contacts = contacts
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
