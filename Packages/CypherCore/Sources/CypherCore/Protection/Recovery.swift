/// The phase of an app whose sealed files cannot all be used. Nothing was
/// repaired, nothing fell back to a first value, and nothing is rescued: the
/// report says what is wrong, and the only way on is a reset.
@MainActor
public final class Recovery {
    public let report: DamageReport

    let session: OpenSession
    let composition: Composition
    weak var core: AppCore?

    init(core: AppCore, composition: Composition, session: OpenSession, report: DamageReport) {
        self.core = core
        self.composition = composition
        self.session = session
        self.report = report
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
