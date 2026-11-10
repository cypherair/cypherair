import Foundation

/// The stored shapes, one per sealed file. Names, expiry dates, shapes and
/// "revoked" are not stored: the engine computes them from the certificate at
/// unlock, so they cannot disagree with it.
struct KeysPayload: Codable, Sendable, Equatable {
    var keys: [StoredKey]
    /// The default key's fingerprint.
    var defaultKey: String?

    static let firstValue = KeysPayload(keys: [], defaultKey: nil)
}

struct StoredKey: Codable, Sendable, Equatable {
    /// The key's identity inside the sealed list.
    let fingerprint: String
    /// The authority for expiry and revocation.
    var certificate: Data
    let material: KeyMaterial
    /// Made with the key.
    let revocation: Data
    /// The real moment the key was made or imported here. It never leaves this
    /// file; the key itself carries an earlier stamp.
    let added: Date
    var backedUp: Bool
}

/// The private part in its stored form. It also says the custody.
enum KeyMaterial: Codable, Sendable, Equatable {
    /// The secret key packets, sealed to the identity wrapping key.
    case portable(sealedSecret: Data)
    /// The two Secure Enclave key blobs and, for a post-quantum key, the sealed
    /// classical halves.
    case deviceBound(signing: Data, agreement: Data, sealedHalves: Data?)
}

struct ContactsPayload: Codable, Sendable, Equatable {
    var contacts: [StoredContact]

    static let firstValue = ContactsPayload(contacts: [])
}

struct StoredContact: Codable, Sendable, Equatable {
    let id: UUID
    var certificate: Data
    var verified: Bool
    let added: Date
}

struct SettingsPayload: Codable, Sendable, Equatable {
    var signByDefault: Bool
    var encryptToSelfByDefault: Bool
    var clipboardNotice: Bool
    var relockAfter: RelockDelay

    static let firstValue = SettingsPayload(signByDefault: true, encryptToSelfByDefault: true, clipboardNotice: true, relockAfter: .threeMinutes)
}

extension RelockDelay: Codable {}

/// The three payloads together, as first run writes them and unlock reads them.
struct Payloads: Sendable {
    var keys: KeysPayload
    var contacts: ContactsPayload
    var settings: SettingsPayload

    static let firstValues = Payloads(keys: .firstValue, contacts: .firstValue, settings: .firstValue)
}
