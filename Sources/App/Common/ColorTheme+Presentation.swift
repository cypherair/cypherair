import SwiftUI

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

extension ColorTheme {
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
        case .systemDefault, .defaultBlue, .indigo, .purple, .teal,
             .mint, .pink, .orange, .red, .graphite:
            false
        }
    }

    /// The primary tint color applied at the app root level.
    /// Returns `nil` for system default so SwiftUI uses `Color.accentColor`.
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
        case .transPride: Color(hue: 0.56, saturation: 0.65, brightness: 0.85)
        case .bisexualPride: Color(hue: 0.93, saturation: 0.55, brightness: 0.85)
        case .nonBinary: Color(hue: 0.15, saturation: 0.75, brightness: 0.90)
        }
    }

    /// Colors for the 4 HomeView action buttons.
    var actionColors: ActionColors {
        switch self {
        case .systemDefault, .defaultBlue:
            ActionColors(encrypt: .blue, decrypt: .green, sign: .orange, verify: .purple)
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
        case .prideRainbow:
            ActionColors(
                encrypt: Color(hue: 0.0, saturation: 0.75, brightness: 0.90),
                decrypt: Color(hue: 0.08, saturation: 0.75, brightness: 0.95),
                sign: Color(hue: 0.33, saturation: 0.70, brightness: 0.75),
                verify: Color(hue: 0.58, saturation: 0.65, brightness: 0.80)
            )
        case .transPride:
            ActionColors(
                encrypt: Color(hue: 0.56, saturation: 0.65, brightness: 0.85),
                decrypt: Color(hue: 0.93, saturation: 0.45, brightness: 0.90),
                sign: Color(hue: 0.56, saturation: 0.55, brightness: 0.75),
                verify: Color(hue: 0.95, saturation: 0.50, brightness: 0.85)
            )
        case .bisexualPride:
            ActionColors(
                encrypt: Color(hue: 0.93, saturation: 0.55, brightness: 0.85),
                decrypt: Color(hue: 0.78, saturation: 0.50, brightness: 0.65),
                sign: Color(hue: 0.62, saturation: 0.60, brightness: 0.75),
                verify: Color(hue: 0.80, saturation: 0.45, brightness: 0.75)
            )
        case .nonBinary:
            ActionColors(
                encrypt: Color(hue: 0.15, saturation: 0.75, brightness: 0.90),
                decrypt: Color(hue: 0.78, saturation: 0.55, brightness: 0.65),
                sign: Color(hue: 0.80, saturation: 0.50, brightness: 0.75),
                verify: Color(hue: 0.15, saturation: 0.65, brightness: 0.80)
            )
        }
    }

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

    private static var adaptiveWhite: Color {
        #if canImport(UIKit)
        Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(white: 0.85, alpha: 1.0)
                : UIColor(white: 0.95, alpha: 1.0)
        })
        #elseif canImport(AppKit)
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(white: 0.85, alpha: 1.0)
                : NSColor(white: 0.95, alpha: 1.0)
        })
        #endif
    }

    private static var adaptiveBlack: Color {
        #if canImport(UIKit)
        Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(white: 0.35, alpha: 1.0)
                : UIColor(white: 0.15, alpha: 1.0)
        })
        #elseif canImport(AppKit)
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                ? NSColor(white: 0.35, alpha: 1.0)
                : NSColor(white: 0.15, alpha: 1.0)
        })
        #endif
    }
}

/// Named colors for the 4 HomeView action buttons.
struct ActionColors {
    let encrypt: Color
    let decrypt: Color
    let sign: Color
    let verify: Color
}
