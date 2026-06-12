import SwiftUI

/// Shared custody presentation for a device-bound Secure Enclave key. Rendered
/// where the backup-status badge would sit for portable keys: device-bound keys
/// have no backup to nag about, so the custody fact takes that slot instead.
struct KeyCustodyBadge: View {
    enum Style {
        /// Capsule status badge (Home identity card).
        case badge
        /// Compact icon-only indicator (key list rows).
        case compact
    }

    var style: Style = .badge

    var body: some View {
        switch style {
        case .badge:
            CypherStatusBadge(title: title, systemImage: "cpu", color: .blue)
                .accessibilityLabel(accessibilityLabel)
        case .compact:
            Image(systemName: "cpu")
                .foregroundStyle(.blue)
                .font(.caption)
                .accessibilityLabel(accessibilityLabel)
        }
    }

    private var title: String {
        String(localized: "keys.deviceBound", defaultValue: "Device-Bound")
    }

    private var accessibilityLabel: String {
        String(
            localized: "keys.deviceBound.accessibility",
            defaultValue: "Device-bound key; cannot be backed up"
        )
    }
}
