import SwiftUI

extension ContactKeyUsageState {
    var contactDetailLabel: String {
        switch self {
        case .preferred:
            String(localized: "contactdetail.usage.preferred", defaultValue: "Preferred")
        case .additionalActive:
            String(localized: "contactdetail.usage.additional", defaultValue: "Active")
        case .historical:
            String(localized: "contactdetail.usage.historical", defaultValue: "Historical")
        }
    }

    var statusColor: Color {
        switch self {
        case .preferred:
            .green
        case .additionalActive:
            .blue
        case .historical:
            .gray
        }
    }

    var systemImage: String {
        switch self {
        case .preferred:
            "key.fill"
        case .additionalActive:
            "key"
        case .historical:
            "clock.arrow.circlepath"
        }
    }
}
