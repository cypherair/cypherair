import SwiftUI

/// One selectable key-family row in the generation form's Key Type section.
struct KeyFamilySelectionRow: View {
    let family: PGPKeyConfiguration.Identity
    let isSelected: Bool
    let isEnabled: Bool
    let onSelect: () -> Void

    var body: some View {
        Button {
            onSelect()
        } label: {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(family.familyDisplayName)
                        .font(.body)
                        .foregroundStyle(.primary)
                    Text(family.familyDescription)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if isSelected {
                    Image(systemName: "checkmark")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(Color.accentColor)
                        .accessibilityHidden(true)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!isEnabled)
        .accessibilityIdentifier("keygen.family.\(family.rawValue)")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}
