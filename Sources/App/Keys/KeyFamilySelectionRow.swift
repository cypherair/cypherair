import SwiftUI

/// One selectable key-family cell in the generation picker. Shared by the
/// compact single-column list and the regular-width custody columns. Custody is
/// conveyed by the surrounding segmented control / column header, so the cell
/// leads with the tier and its concise algorithm line.
struct KeyFamilySelectionRow: View {
    let family: PGPKeyConfiguration.Identity
    let isSelected: Bool
    let isEnabled: Bool
    let onSelect: () -> Void
    let onInfo: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: CypherSpacing.tight) {
            Button(action: onSelect) {
                content
            }
            .buttonStyle(.plain)
            .disabled(!isEnabled)
            .accessibilityIdentifier("keygen.family.\(family.rawValue)")
            .accessibilityLabel(family.familyDisplayName)
            .accessibilityValue(family.familyAlgorithmSubtitle)
            .accessibilityAddTraits(isSelected ? .isSelected : [])

            infoButton
        }
        .contentShape(Rectangle())
    }

    private var content: some View {
        HStack(alignment: .top, spacing: CypherSpacing.compact) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: CypherSpacing.compact) {
                    Text(family.tierDisplayName)
                        .font(.body)
                        .foregroundStyle(.primary)
                    if family.isRecommended {
                        CypherStatusBadge(
                            title: String(localized: "keyFamily.recommended", defaultValue: "Recommended"),
                            color: .accentColor
                        )
                    }
                }
                Text(family.familyAlgorithmSubtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let tagline = family.familyPositioningTagline {
                    Text(tagline)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer(minLength: CypherSpacing.compact)
            if isSelected {
                Image(systemName: "checkmark")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(Color.accentColor)
                    .accessibilityHidden(true)
            }
        }
        .contentShape(Rectangle())
    }

    private var infoButton: some View {
        Button(action: onInfo) {
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
}
