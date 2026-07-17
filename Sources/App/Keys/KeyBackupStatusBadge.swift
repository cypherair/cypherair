import SwiftUI

/// Shared backup-status presentation for a key: backed-up (green check) vs
/// needs-backup (orange triangle). Single source of truth for the icon and color
/// so the Home identity card, Key Detail, and the key list stay consistent. The
/// `style` selects the structural variant (and its context-appropriate copy)
/// instead of duplicating the backed-up / needs-backup decision at each call site.
struct KeyBackupStatusBadge: View {
    enum Style {
        /// Capsule status badge (Home identity card).
        case badge
        /// Inline label shown as the value in a detail row (Key Detail).
        case inline
        /// Compact icon-only warning, rendered only when not backed up (key list rows).
        case compact
    }

    let isBackedUp: Bool
    var style: Style = .badge

    var body: some View {
        switch style {
        case .badge:
            CypherStatusBadge(title: badgeTitle, systemImage: systemImage, color: color)
                // The badge is folded into the Home card's combined accessibility
                // element; without this override the bare imperative "Back up now"
                // reads as an offered action. A declarative status phrase frames it.
                .accessibilityLabel(badgeAccessibilityLabel)
        case .inline:
            Label(inlineTitle, systemImage: systemImage)
                .foregroundStyle(color)
        case .compact:
            if !isBackedUp {
                Image(systemName: systemImage)
                    .foregroundStyle(color)
                    .font(.caption)
                    .accessibilityLabel(compactLabel)
            }
        }
    }

    private var systemImage: String {
        isBackedUp ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
    }

    private var color: Color {
        isBackedUp ? .green : .orange
    }

    // This badge intentionally owns its per-style copy (badgeTitle / inlineTitle /
    // compactLabel) as the single source of truth for the backed-up vs needs-backup
    // decision. Relocating those strings to the three call sites would fragment
    // ownership and risk cross-surface drift for no real gain.
    private var badgeTitle: String {
        isBackedUp
            ? String(localized: "home.defaultKey.backedUp", defaultValue: "Backed up")
            : String(localized: "home.defaultKey.backUpNow", defaultValue: "Back up now")
    }

    /// A declarative status phrase (not the imperative visible title) for VoiceOver,
    /// used only by `.badge` where the chip joins the Home card's combined element.
    private var badgeAccessibilityLabel: String {
        isBackedUp
            ? String(localized: "home.defaultKey.backupStatus.backedUp", defaultValue: "Backup status: backed up")
            : String(localized: "home.defaultKey.backupStatus.needsBackup", defaultValue: "Backup status: needs backup")
    }

    private var inlineTitle: String {
        isBackedUp
            ? String(localized: "keydetail.backed", defaultValue: "Backed Up")
            : String(localized: "keydetail.notBacked", defaultValue: "Not Backed Up")
    }

    private var compactLabel: String {
        String(localized: "keys.notBackedUp", defaultValue: "Not backed up")
    }
}
