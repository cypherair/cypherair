import SwiftUI

/// Grid-based color theme selection view.
/// Works on both iOS and macOS (pure SwiftUI, no UIKit dependency).
struct ThemePickerView: View {
    @Environment(ProtectedOrdinarySettingsCoordinator.self) private var protectedOrdinarySettings
    #if os(macOS)
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 20), count: 4)
    #else
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 20), count: 3)
    #endif

    var body: some View {
        Group {
            if protectedOrdinarySettings.isLoaded {
                ScrollView {
                    LazyVGrid(columns: columns, spacing: 20) {
                        ForEach(ColorTheme.allCases) { theme in
                            ThemeCell(
                                theme: theme,
                                isSelected: protectedOrdinarySettings.colorTheme == theme
                            ) {
                                protectedOrdinarySettings.setColorTheme(theme)
                            }
                        }
                    }
                    .padding()
                    .cypherMacReadableContent(maxWidth: MacPresentationWidth.themeGrid)
                }
            } else {
                ContentUnavailableView {
                    Label(
                        String(localized: "protectedSettings.locked.title", defaultValue: "Preferences Locked"),
                        systemImage: "lock"
                    )
                } description: {
                    Text(
                        String(
                            localized: "protectedSettings.locked.message",
                            defaultValue: "Authenticate to view and change this preference."
                        )
                    )
                }
            }
        }
        .accessibilityIdentifier("theme.root")
        .screenReady("theme.ready")
        .navigationTitle(String(localized: "settings.theme", defaultValue: "Color Theme"))
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

// MARK: - Cell View

/// A single theme swatch cell with label and selection indicator.
private struct ThemeCell: View {
    let theme: ColorTheme
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                ZStack(alignment: .bottomTrailing) {
                    swatch
                        .frame(width: 56, height: 56)
                        .clipShape(RoundedRectangle(cornerRadius: swatchCornerRadius, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: swatchCornerRadius, style: .continuous)
                                .strokeBorder(isSelected ? Color.accentColor : Color.clear, lineWidth: 2.5)
                        )

                    if isSelected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 18))
                            .foregroundStyle(.white, .blue)
                            .accessibilityHidden(true)
                            .offset(x: 4, y: 4)
                    }
                }

                Text(theme.displayName)
                    .font(.caption)
                    .foregroundStyle(isSelected ? .primary : .secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(minHeight: 30, alignment: .top)
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(theme.displayName)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private var swatchCornerRadius: CGFloat {
        #if os(macOS)
        8
        #else
        14
        #endif
    }

    @ViewBuilder
    private var swatch: some View {
        if theme.isMultiColor {
            // Gradient capsule for multi-color themes
            LinearGradient(
                colors: theme.previewColors,
                startPoint: .leading,
                endPoint: .trailing
            )
        } else {
            // Solid circle for single-color themes
            theme.previewColors.first.map { color in
                color
            }
        }
    }
}
