import SwiftUI

/// A small, pill-shaped tag chip with a selected / unselected appearance.
///
/// Shared by the Contacts tag-filter strip and the Encrypt recipient chooser so
/// both surfaces speak the same tag language. Tag-type-agnostic — callers pass a
/// plain title and selection state.
struct CypherTagChip: View {
    let title: String
    let isSelected: Bool
    var selectedSystemImage: String = "checkmark.circle.fill"
    var unselectedSystemImage: String = "tag"
    let toggle: () -> Void

    var body: some View {
        if isSelected {
            Button(action: toggle) {
                Label(title, systemImage: selectedSystemImage)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .accessibilityLabel(title)
            .accessibilityAddTraits(.isSelected)
        } else {
            Button(action: toggle) {
                Label(title, systemImage: unselectedSystemImage)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .accessibilityLabel(title)
        }
    }
}
