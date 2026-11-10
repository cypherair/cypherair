internal import CryptoKit
internal import Stores

/// The three sealed files, and one turn for each that outlives every session:
/// a store holds a file's turn while it writes, and unlock and first run hold
/// all three while they read or write. So a write that began before a lock
/// ends before the next unlock reads the file.
struct Domains: Sendable {
    /// Versions 1 and 2 belong to 1.x. The vault refuses a file of another
    /// version before it decrypts it.
    static let schemaVersion = 3

    let keys: SealedDomain<KeysPayload>
    let contacts: SealedDomain<ContactsPayload>
    let settings: SealedDomain<SettingsPayload>
    let turns: (keys: Turn, contacts: Turn, settings: Turn)

    @MainActor
    init(files: any DomainFiles) {
        keys = SealedDomain(domain: "keys", schemaVersion: Self.schemaVersion, files: files)
        contacts = SealedDomain(domain: "contacts", schemaVersion: Self.schemaVersion, files: files)
        settings = SealedDomain(domain: "settings", schemaVersion: Self.schemaVersion, files: files)
        turns = (Turn(), Turn(), Turn())
    }

    /// Takes the three turns, always in the same order.
    @MainActor
    func takeAllTurns() async {
        await turns.keys.take()
        await turns.contacts.take()
        await turns.settings.take()
    }

    @MainActor
    func passAllTurns() {
        turns.settings.pass()
        turns.contacts.pass()
        turns.keys.pass()
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
        /// The key list, when it is intact, so that its portable keys can
        /// still be backed up.
        case damaged(DamageReport, keys: KeysPayload?)
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
        return .damaged(DamageReport(keys: keysFile.state, contacts: contactsFile.state, settings: settingsFile.state), keys: keysFile.payload)
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
