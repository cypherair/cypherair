import SwiftUI

/// Shared spacing scale for screen layouts.
///
/// The design system is deliberately small: spacing, radii, and one surface
/// modifier (`cypherSurface(_:)`). Standard SwiftUI components (Form, List,
/// section headers, ContentUnavailableView) already carry the platform design
/// language; do not add new primitives here without a repeated cross-screen need.
enum CypherSpacing {
    /// Tight intra-row spacing (icon-to-text pairs, dot indicators).
    static let compact: CGFloat = 8
    /// Spacing between related elements inside a card or row.
    static let tight: CGFloat = 12
    /// Default spacing between sibling controls and grid items.
    static let standard: CGFloat = 16
    /// Spacing between sections of a screen.
    static let section: CGFloat = 20
    /// Breathing room around hero content.
    static let loose: CGFloat = 24
}

/// Shared corner-radius scale. macOS uses tighter radii to match native
/// window chrome; the other platforms use softer Liquid Glass-era values.
enum CypherRadius {
    /// Small controls: badges, inline text blocks, editor chrome.
    static var control: CGFloat { platformValue(mac: 8, other: 10) }
    /// Cards and content surfaces.
    static var card: CGFloat { platformValue(mac: 8, other: 14) }
    /// Hero and large presentation surfaces.
    static var hero: CGFloat { platformValue(mac: 10, other: 22) }

    private static func platformValue(mac: CGFloat, other: CGFloat) -> CGFloat {
        #if os(macOS)
        mac
        #else
        other
        #endif
    }
}
