import SwiftUI

/// One selectable key-family row in the generation form's Key Type section.
struct KeyFamilySelectionRow: View {
    let family: PGPKeyConfiguration.Identity
    let isSelected: Bool
    let isEnabled: Bool
    let onSelect: () -> Void
    let onInfo: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
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
                    Spacer(minLength: 8)
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

            Button {
                onInfo()
            } label: {
                Image(systemName: "info.circle")
                    .font(.body)
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 32, height: 32, alignment: .center)
                    .contentShape(Rectangle())
                    .accessibilityHidden(true)
            }
            .buttonStyle(.borderless)
            .accessibilityIdentifier("keygen.family.\(family.rawValue).info")
            .accessibilityLabel(
                String(localized: "keygen.family.info.accessibility", defaultValue: "Show key type details")
            )
        }
        .contentShape(Rectangle())
    }
}
