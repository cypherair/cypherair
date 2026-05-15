import Foundation

struct SettingsGracePeriodOption: Identifiable, Equatable {
    let value: Int
    let label: String

    var id: Int { value }
}

enum SettingsGracePeriodPresentation {
    static var options: [SettingsGracePeriodOption] {
        AppConfiguration.validGracePeriodValues.map { value in
            SettingsGracePeriodOption(value: value, label: label(for: value))
        }
    }

    private static func label(for value: Int) -> String {
        switch value {
        case 0:
            return String(localized: "grace.immediately", defaultValue: "Immediately")
        case 60:
            return String(localized: "grace.1min", defaultValue: "1 minute")
        case 180:
            return String(localized: "grace.3min", defaultValue: "3 minutes")
        case 300:
            return String(localized: "grace.5min", defaultValue: "5 minutes")
        default:
            assertionFailure("Unexpected grace period option: \(value)")
            return "\(value)"
        }
    }
}
