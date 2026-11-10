import Observation

/// The user's keys.
@MainActor
@Observable
public final class Keys {
    public private(set) var all: [Key] = []

    @ObservationIgnored let store: Store<KeysPayload>
    @ObservationIgnored let session: OpenSession

    init(store: Store<KeysPayload>, session: OpenSession) {
        self.store = store
        self.session = session
    }

    func drop() {
        all = []
    }
}
