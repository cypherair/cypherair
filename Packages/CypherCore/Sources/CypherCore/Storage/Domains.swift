internal import CryptoKit
internal import Stores

/// The three sealed files.
struct Domains: Sendable {
    /// Versions 1 and 2 belong to 1.x. The vault refuses a file of another
    /// version before it decrypts it.
    static let schemaVersion = 3

    let keys: SealedDomain<KeysPayload>
    let contacts: SealedDomain<ContactsPayload>
    let settings: SealedDomain<SettingsPayload>

    init(files: any DomainFiles) {
        keys = SealedDomain(domain: "keys", schemaVersion: Self.schemaVersion, files: files)
        contacts = SealedDomain(domain: "contacts", schemaVersion: Self.schemaVersion, files: files)
        settings = SealedDomain(domain: "settings", schemaVersion: Self.schemaVersion, files: files)
    }

    struct Keys: Sendable {
        let keys: SymmetricKey
        let contacts: SymmetricKey
        let settings: SymmetricKey
    }

    @MainActor
    func keys(from session: OpenSession) throws(CoreError) -> Keys {
        Keys(
            keys: try session.domainKey(keys.domain),
            contacts: try session.domainKey(contacts.domain),
            settings: try session.domainKey(settings.domain)
        )
    }

    /// Writes all three files. Blocking.
    func write(_ payloads: Payloads, with keys: Keys) throws(StoreError) {
        try self.keys.save(payloads.keys, key: keys.keys)
        try contacts.save(payloads.contacts, key: keys.contacts)
        try settings.save(payloads.settings, key: keys.settings)
    }

    enum Reading: Sendable {
        case intact(Payloads)
        case damaged(DamageReport)
    }

    /// Reads all three files. Any file that cannot be used makes the whole
    /// reading damaged: no file ever falls back to a first value. Blocking.
    func read(with keys: Keys) -> Reading {
        let keysFile = Self.read(self.keys, key: keys.keys)
        let contactsFile = Self.read(contacts, key: keys.contacts)
        let settingsFile = Self.read(settings, key: keys.settings)
        if let keysPayload = keysFile.payload, let contactsPayload = contactsFile.payload, let settingsPayload = settingsFile.payload {
            return .intact(Payloads(keys: keysPayload, contacts: contactsPayload, settings: settingsPayload))
        }
        return .damaged(DamageReport(keys: keysFile.state, contacts: contactsFile.state, settings: settingsFile.state))
    }

    private static func read<Payload>(_ domain: SealedDomain<Payload>, key: SymmetricKey) -> (payload: Payload?, state: FileState) {
        do {
            return (try domain.load(key: key), .intact)
        } catch .missing {
            return (nil, .missing)
        } catch .otherVersion {
            return (nil, .madeByAnotherVersion)
        } catch {
            return (nil, .damaged)
        }
    }
}
