/// The phase of an app whose sealed files cannot all be used. Nothing was
/// repaired and nothing fell back to a first value.
@MainActor
public final class Recovery {
    public let report: DamageReport

    let session: OpenSession

    init(report: DamageReport, session: OpenSession) {
        self.report = report
        self.session = session
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
