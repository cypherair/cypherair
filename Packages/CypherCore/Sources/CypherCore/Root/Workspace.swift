/// Everything that exists only while the app is unlocked. At lock it is gone:
/// every later call through an old reference throws `CoreError.locked`.
@MainActor
public final class Workspace {
    public let keys: Keys
    public let contacts: Contacts
    public let messages: Messages
    public let settings: Settings

    let session: OpenSession
    private let stores: (keys: Store<KeysPayload>, contacts: Store<ContactsPayload>, settings: Store<SettingsPayload>)
    private weak var core: AppCore?

    init(core: AppCore, composition: Composition, session: OpenSession, contents: WorkspaceContents) {
        self.core = core
        self.session = session
        let domains = composition.domains
        let payloads = contents.payloads
        stores = (
            Store(domain: domains.keys, turn: domains.turns.keys, session: session, payload: payloads.keys),
            Store(domain: domains.contacts, turn: domains.turns.contacts, session: session, payload: payloads.contacts),
            Store(domain: domains.settings, turn: domains.turns.settings, session: session, payload: payloads.settings)
        )
        keys = Keys(all: contents.keys, store: stores.keys, session: session, composition: composition, core: core)
        contacts = Contacts(all: contents.contacts, store: stores.contacts, session: session, composition: composition, core: core)
        messages = Messages(session: session, composition: composition, core: core, keys: keys, contacts: contacts)
        settings = Settings(store: stores.settings, values: SettingsValues(payloads.settings))
    }

    public func lock() {
        guard session.isOpen else { return }
        if let core {
            core.lock()
        } else {
            close()
        }
    }

    /// Erases the session values in the vault, which also tells running file
    /// operations to stop, and drops the decoded values.
    func close() {
        session.close()
        stores.keys.drop()
        stores.contacts.drop()
        stores.settings.drop()
        keys.drop()
        contacts.drop()
    }
}

/// What a workspace opens with: the three payloads and the lists computed from
/// them. Blocking to make, because the lists read every certificate.
struct WorkspaceContents: Sendable {
    let payloads: Payloads
    let keys: [Key]
    let contacts: [Contact]

    init(_ payloads: Payloads) {
        self.payloads = payloads
        keys = Keys.list(of: payloads.keys)
        contacts = Contacts.list(of: payloads.contacts)
    }
}
