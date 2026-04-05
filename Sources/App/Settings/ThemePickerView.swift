import SwiftUI

/// Grid-based color theme selection view.
/// Works on both iOS and macOS (pure SwiftUI, no UIKit dependency).
struct ThemePickerView: View {
    @Environment(AppConfiguration.self) private var config
    #if os(macOS)
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 20), count: 4)
    #else
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 20), count: 3)
    #endif

    var body: some View {
        @Bindable var config = config

        ScrollView {
            LazyVGrid(columns: columns, spacing: 20) {
                ForEach(ColorTheme.allCases) { theme in
                    ThemeCell(
                        theme: theme,
                        isSelected: config.colorTheme == theme
                    ) {
                        config.colorTheme = theme
                    }
                }
            }
            .padding()
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
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
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
                    .lineLimit(1)
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(theme.displayName)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
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
