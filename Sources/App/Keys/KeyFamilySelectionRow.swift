import SwiftUI

/// One selectable key-family cell in the generation picker. Shared by the
/// compact single-column list and the regular-width custody columns. Custody is
/// conveyed by the surrounding segmented control / column header, so the cell
/// leads with the tier and its concise algorithm line.
struct KeyFamilySelectionRow: View {
    let family: PGPKeyFamily
    let isSelected: Bool
    let isEnabled: Bool
    let onSelect: () -> Void
    let onInfo: () -> Void

    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

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
                titleAndRecommendation
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

    /// Tier title plus the optional "Recommended" badge. At accessibility Dynamic
    /// Type sizes the badge stacks under the title so the fixed-width badge can't
    /// squeeze the (now-wrapping) title into truncation; below that it stays inline.
    @ViewBuilder
    private var titleAndRecommendation: some View {
        if family.isRecommended {
            if dynamicTypeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: CypherSpacing.tight) {
                    titleText
                    recommendedBadge
                }
            } else {
                HStack(spacing: CypherSpacing.compact) {
                    titleText
                    recommendedBadge
                }
            }
        } else {
            titleText
        }
    }

    /// The tier title. Intentionally carries no line limit: at large Dynamic Type
    /// sizes it must wrap to show the full name, never tail-truncate.
    private var titleText: some View {
        Text(family.tierDisplayName)
            .font(.body)
            .foregroundStyle(.primary)
    }

    private var recommendedBadge: some View {
        CypherStatusBadge(
            title: String(localized: "keyFamily.recommended", defaultValue: "Recommended"),
            color: .accentColor
        )
        .fixedSize(horizontal: true, vertical: false)
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
