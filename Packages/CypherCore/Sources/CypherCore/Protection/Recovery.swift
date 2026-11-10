/// The phase of an app whose sealed files cannot all be used. Nothing was
/// repaired and nothing fell back to a first value.
@MainActor
public final class Recovery {
    public let report: DamageReport
    /// The keys of the key list when it is intact; empty when it is not.
    public let recoverableKeys: [Key]

    let keys: KeysPayload?
    let session: OpenSession
    let composition: Composition
    weak var core: AppCore?

    init(core: AppCore, composition: Composition, session: OpenSession, report: DamageReport, keys: KeysPayload?, recoverableKeys: [Key]) {
        self.core = core
        self.composition = composition
        self.session = session
        self.report = report
        self.keys = keys
        self.recoverableKeys = recoverableKeys
    }

    func close() {
        session.close()
    }
}

/// The state of each sealed file at unlock.
public struct DamageReport: Sendable, Equatable {
    public let keys: FileState
    public let contacts: FileState
    public let settings: FileState
}

public enum FileState: Sendable {
    case intact
    case missing
    case damaged
    case madeByAnotherVersion
}
