import Observation

/// The user's settings. Their values hold no user content, so they stay
/// readable after lock; changing them does not.
@MainActor
@Observable
public final class Settings {
    public private(set) var values: SettingsValues

    @ObservationIgnored private let store: Store<SettingsPayload>

    init(store: Store<SettingsPayload>, values: SettingsValues) {
        self.store = store
        self.values = values
    }

    /// Applies `change` and saves it. When saving fails, `values` stays as it was.
    public func update(_ change: (inout SettingsValues) -> Void) async throws(CoreError) {
        let saved = try await store.update { (payload) throws(CoreError) -> SettingsPayload in
            var values = SettingsValues(payload)
            change(&values)
            payload = SettingsPayload(values)
            return payload
        }
        values = SettingsValues(saved)
    }
}

public struct SettingsValues: Sendable, Equatable {
    public var signByDefault: Bool
    public var encryptToSelfByDefault: Bool
    public var clipboardNotice: Bool
    /// How long the app may be away before unlock is asked again.
    public var relockAfter: RelockDelay
}

public enum RelockDelay: Int, Sendable, CaseIterable {
    case immediately = 0
    case oneMinute = 60
    case threeMinutes = 180
    case fiveMinutes = 300
}

extension SettingsValues {
    init(_ payload: SettingsPayload) {
        self.init(
            signByDefault: payload.signByDefault,
            encryptToSelfByDefault: payload.encryptToSelfByDefault,
            clipboardNotice: payload.clipboardNotice,
            relockAfter: payload.relockAfter
        )
    }
}

extension SettingsPayload {
    init(_ values: SettingsValues) {
        self.init(
            signByDefault: values.signByDefault,
            encryptToSelfByDefault: values.encryptToSelfByDefault,
            clipboardNotice: values.clipboardNotice,
            relockAfter: values.relockAfter
        )
    }
}
