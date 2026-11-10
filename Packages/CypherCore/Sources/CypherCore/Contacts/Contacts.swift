import Observation

/// The user's contacts.
@MainActor
@Observable
public final class Contacts {
    public private(set) var all: [Contact] = []

    @ObservationIgnored let store: Store<ContactsPayload>
    @ObservationIgnored let session: OpenSession

    init(store: Store<ContactsPayload>, session: OpenSession) {
        self.store = store
        self.session = session
    }

    func drop() {
        all = []
    }
}
