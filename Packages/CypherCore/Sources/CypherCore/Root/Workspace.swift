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

    init(core: AppCore, session: OpenSession, domains: Domains, payloads: Payloads) {
        self.core = core
        self.session = session
        stores = (
            Store(domain: domains.keys, session: session, payload: payloads.keys),
            Store(domain: domains.contacts, session: session, payload: payloads.contacts),
            Store(domain: domains.settings, session: session, payload: payloads.settings)
        )
        keys = Keys(store: stores.keys, session: session)
        contacts = Contacts(store: stores.contacts, session: session)
        messages = Messages(session: session)
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
    /// operations to stop, and drops every decoded value.
    func close() {
        session.close()
        stores.keys.drop()
        stores.contacts.drop()
        stores.settings.drop()
        keys.drop()
        contacts.drop()
    }
}
