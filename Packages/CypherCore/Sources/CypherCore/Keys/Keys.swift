import Observation

/// The user's keys.
@MainActor
@Observable
public final class Keys {
    public private(set) var all: [Key]

    @ObservationIgnored let store: Store<KeysPayload>
    @ObservationIgnored let session: OpenSession
    @ObservationIgnored let composition: Composition
    @ObservationIgnored weak var core: AppCore?

    init(all: [Key], store: Store<KeysPayload>, session: OpenSession, composition: Composition, core: AppCore?) {
        self.all = all
        self.store = store
        self.session = session
        self.composition = composition
        self.core = core
    }

    /// The keys as screens see them, computed from each stored certificate.
    /// Unlock runs it off the main actor, before the workspace exists. Until
    /// the engine reads certificates for the core, the list is empty.
    nonisolated static func list(of payload: KeysPayload) -> [Key] {
        []
    }

    func drop() {
        all = []
    }
}
