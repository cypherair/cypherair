import Observation

/// The user's contacts.
@MainActor
@Observable
public final class Contacts {
    public private(set) var all: [Contact]

    @ObservationIgnored let store: Store<ContactsPayload>
    @ObservationIgnored let session: OpenSession
    @ObservationIgnored let composition: Composition
    @ObservationIgnored weak var core: AppCore?

    init(all: [Contact], store: Store<ContactsPayload>, session: OpenSession, composition: Composition, core: AppCore?) {
        self.all = all
        self.store = store
        self.session = session
        self.composition = composition
        self.core = core
    }

    /// The contacts as screens see them, computed from each stored
    /// certificate. Unlock runs it off the main actor, before the workspace
    /// exists. Until the engine reads certificates for the core, the list is
    /// empty.
    nonisolated static func list(of payload: ContactsPayload) -> [Contact] {
        []
    }

    func drop() {
        all = []
    }
}
