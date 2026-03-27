import SwiftUI

/// Color theme presets for app-wide accent customization.
/// Themes affect decorative/accent colors only — semantic status colors
/// (red=error, green=success, orange=warning) are never changed.
enum ColorTheme: String, CaseIterable, Identifiable, Codable {
    // System default (no tint override — uses Color.accentColor)
    case systemDefault

    // Single-color
    case defaultBlue
    case indigo
    case purple
    case teal
    case mint
    case pink
    case orange
    case red
    case graphite

    // Multi-color
    case prideRainbow
    case transPride
    case bisexualPride
    case nonBinary

    var id: String { rawValue }

    // MARK: - Display

    var displayName: String {
        switch self {
        case .systemDefault:
            String(localized: "theme.systemDefault", defaultValue: "Default")
        case .defaultBlue:
            String(localized: "theme.defaultBlue", defaultValue: "Blue")
        case .indigo:
            String(localized: "theme.indigo", defaultValue: "Indigo")
        case .purple:
            String(localized: "theme.purple", defaultValue: "Purple")
        case .teal:
            String(localized: "theme.teal", defaultValue: "Teal")
        case .mint:
            String(localized: "theme.mint", defaultValue: "Mint")
        case .pink:
            String(localized: "theme.pink", defaultValue: "Pink")
        case .orange:
            String(localized: "theme.orange", defaultValue: "Orange")
        case .red:
            String(localized: "theme.red", defaultValue: "Red")
        case .graphite:
            String(localized: "theme.graphite", defaultValue: "Graphite")
        case .prideRainbow:
            String(localized: "theme.prideRainbow", defaultValue: "Pride")
        case .transPride:
            String(localized: "theme.transPride", defaultValue: "Trans")
        case .bisexualPride:
            String(localized: "theme.bisexualPride", defaultValue: "Bisexual")
        case .nonBinary:
            String(localized: "theme.nonBinary", defaultValue: "Non-Binary")
        }
    }

    var isMultiColor: Bool {
        switch self {
        case .prideRainbow, .transPride, .bisexualPride, .nonBinary:
            true
        default:
            false
        }
    }

    // MARK: - Global Accent Color

    /// The primary tint color applied at the app root level.
    /// Returns `nil` for system default (no tint override — SwiftUI uses `Color.accentColor`).
    /// Affects navigation bars, toggles, pickers, `.borderedProminent` buttons.
    var accentColor: Color? {
        switch self {
        case .systemDefault: nil
        case .defaultBlue: .blue
        case .indigo: .indigo
        case .purple: .purple
        case .teal: .teal
        case .mint: .mint
        case .pink: .pink
        case .orange: .orange
        case .red: .red
        case .graphite: Color(hue: 0, saturation: 0.02, brightness: 0.55)
        case .prideRainbow: .red
        case .transPride: Color(hue: 0.56, saturation: 0.65, brightness: 0.85)  // light blue
        case .bisexualPride: Color(hue: 0.93, saturation: 0.55, brightness: 0.85)  // pink
        case .nonBinary: Color(hue: 0.15, saturation: 0.75, brightness: 0.90)  // yellow
        }
    }

    // MARK: - Action Button Colors

    /// Colors for the 4 HomeView action buttons (Encrypt, Decrypt, Sign, Verify).
    /// Each button's `.tint()` overrides the global tint, providing per-button distinction.
    var actionColors: ActionColors {
        switch self {
        // System default and blue both use the original hardcoded colors
        case .systemDefault, .defaultBlue:
            ActionColors(encrypt: .blue, decrypt: .green, sign: .orange, verify: .purple)

        // Single-color themes: 4 hue-shifted variants within the palette
        case .indigo:
            ActionColors(
                encrypt: .indigo,
                decrypt: Color(hue: 0.60, saturation: 0.50, brightness: 0.80),
                sign: Color(hue: 0.72, saturation: 0.45, brightness: 0.75),
                verify: Color(hue: 0.65, saturation: 0.55, brightness: 0.85)
            )
        case .purple:
            ActionColors(
                encrypt: .purple,
                decrypt: Color(hue: 0.75, saturation: 0.50, brightness: 0.85),
                sign: Color(hue: 0.80, saturation: 0.55, brightness: 0.80),
                verify: .indigo
            )
        case .teal:
            ActionColors(
                encrypt: .teal,
                decrypt: Color(hue: 0.48, saturation: 0.55, brightness: 0.75),
                sign: Color(hue: 0.42, saturation: 0.50, brightness: 0.80),
                verify: .cyan
            )
        case .mint:
            ActionColors(
                encrypt: .mint,
                decrypt: Color(hue: 0.42, saturation: 0.40, brightness: 0.80),
                sign: Color(hue: 0.38, saturation: 0.45, brightness: 0.75),
                verify: .teal
            )
        case .pink:
            ActionColors(
                encrypt: .pink,
                decrypt: Color(hue: 0.93, saturation: 0.45, brightness: 0.85),
                sign: Color(hue: 0.88, saturation: 0.50, brightness: 0.80),
                verify: Color(hue: 0.96, saturation: 0.40, brightness: 0.90)
            )
        case .orange:
            ActionColors(
                encrypt: .orange,
                decrypt: Color(hue: 0.08, saturation: 0.60, brightness: 0.90),
                sign: Color(hue: 0.05, saturation: 0.55, brightness: 0.85),
                verify: Color(hue: 0.12, saturation: 0.50, brightness: 0.85)
            )
        case .red:
            ActionColors(
                encrypt: .red,
                decrypt: Color(hue: 0.98, saturation: 0.55, brightness: 0.85),
                sign: Color(hue: 0.02, saturation: 0.60, brightness: 0.80),
                verify: Color(hue: 0.95, saturation: 0.50, brightness: 0.90)
            )
        case .graphite:
            ActionColors(
                encrypt: Color(hue: 0, saturation: 0.02, brightness: 0.55),
                decrypt: Color(hue: 0, saturation: 0.02, brightness: 0.45),
                sign: Color(hue: 0, saturation: 0.02, brightness: 0.65),
                verify: Color(hue: 0, saturation: 0.02, brightness: 0.50)
            )

        // Multi-color themes: colors from the flag palette
        case .prideRainbow:
            ActionColors(
                encrypt: Color(hue: 0.0, saturation: 0.75, brightness: 0.90),    // red
                decrypt: Color(hue: 0.08, saturation: 0.75, brightness: 0.95),   // orange
                sign: Color(hue: 0.33, saturation: 0.70, brightness: 0.75),      // green
                verify: Color(hue: 0.58, saturation: 0.65, brightness: 0.80)     // blue
            )
        case .transPride:
            ActionColors(
                encrypt: Color(hue: 0.56, saturation: 0.65, brightness: 0.85),   // light blue
                decrypt: Color(hue: 0.93, saturation: 0.45, brightness: 0.90),   // pink
                sign: Color(hue: 0.56, saturation: 0.55, brightness: 0.75),      // deeper blue
                verify: Color(hue: 0.95, saturation: 0.50, brightness: 0.85)     // deeper pink
            )
        case .bisexualPride:
            ActionColors(
                encrypt: Color(hue: 0.93, saturation: 0.55, brightness: 0.85),   // pink
                decrypt: Color(hue: 0.78, saturation: 0.50, brightness: 0.65),   // purple
                sign: Color(hue: 0.62, saturation: 0.60, brightness: 0.75),      // blue
                verify: Color(hue: 0.80, saturation: 0.45, brightness: 0.75)     // lavender
            )
        case .nonBinary:
            ActionColors(
                encrypt: Color(hue: 0.15, saturation: 0.75, brightness: 0.90),   // yellow
                decrypt: Color(hue: 0.78, saturation: 0.55, brightness: 0.65),   // purple
                sign: Color(hue: 0.80, saturation: 0.50, brightness: 0.75),      // lighter purple
                verify: Color(hue: 0.15, saturation: 0.65, brightness: 0.80)     // softer yellow
            )
        }
    }

    // MARK: - Preview Colors (for theme picker swatch)

    /// Colors shown in the theme picker as a preview swatch.
    var previewColors: [Color] {
        switch self {
        case .systemDefault: [Color.accentColor]
        case .defaultBlue: [.blue]
        case .indigo: [.indigo]
        case .purple: [.purple]
        case .teal: [.teal]
        case .mint: [.mint]
        case .pink: [.pink]
        case .orange: [.orange]
        case .red: [.red]
        case .graphite: [Color(hue: 0, saturation: 0.02, brightness: 0.55)]
        case .prideRainbow: [
            Color(hue: 0.0, saturation: 0.75, brightness: 0.90),
            Color(hue: 0.08, saturation: 0.75, brightness: 0.95),
            Color(hue: 0.15, saturation: 0.80, brightness: 0.95),
            Color(hue: 0.33, saturation: 0.70, brightness: 0.75),
            Color(hue: 0.58, saturation: 0.65, brightness: 0.80),
            Color(hue: 0.78, saturation: 0.60, brightness: 0.70)
        ]
        case .transPride: [
            Color(hue: 0.56, saturation: 0.65, brightness: 0.85),
            Color(hue: 0.93, saturation: 0.45, brightness: 0.90),
            Self.adaptiveWhite
        ]
        case .bisexualPride: [
            Color(hue: 0.93, saturation: 0.55, brightness: 0.85),
            Color(hue: 0.78, saturation: 0.50, brightness: 0.65),
            Color(hue: 0.62, saturation: 0.60, brightness: 0.75)
        ]
        case .nonBinary: [
            Color(hue: 0.15, saturation: 0.75, brightness: 0.90),
            Self.adaptiveWhite,
            Color(hue: 0.78, saturation: 0.55, brightness: 0.65),
            Self.adaptiveBlack
        ]
        }
    }

    // MARK: - Adaptive Colors for Light/Dark Mode

    /// White that remains visible in both light and dark mode.
    private static var adaptiveWhite: Color {
        #if canImport(UIKit)
        Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(white: 0.85, alpha: 1.0)
                : UIColor(white: 0.95, alpha: 1.0)
        })
        #else
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(white: 0.85, alpha: 1.0)
                : NSColor(white: 0.95, alpha: 1.0)
        })
        #endif
    }

    /// Black that remains visible in both light and dark mode.
    private static var adaptiveBlack: Color {
        #if canImport(UIKit)
        Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(white: 0.35, alpha: 1.0)
                : UIColor(white: 0.15, alpha: 1.0)
        })
        #else
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(white: 0.35, alpha: 1.0)
                : NSColor(white: 0.15, alpha: 1.0)
        })
        #endif
    }
}

// MARK: - Action Colors

/// Named colors for the 4 HomeView action buttons.
/// Using a struct with named properties avoids fragile array indexing.
struct ActionColors {
    let encrypt: Color
    let decrypt: Color
    let sign: Color
    let verify: Color
}
