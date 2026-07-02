import SwiftUI

/// Style of a shared content surface.
enum CypherSurfaceStyle {
    /// Content card sitting on a screen background.
    case card
    /// Elevated surface for prominent presentation moments.
    case hero
}

extension View {
    /// Applies the shared surface treatment with platform-appropriate fill and
    /// corner radius. For grouped content cards only — content views keep their
    /// system backgrounds, and glass is never applied here (docs/CONVENTIONS.md,
    /// Liquid Glass).
    @ViewBuilder
    func cypherSurface(_ style: CypherSurfaceStyle = .card) -> some View {
        switch style {
        case .card:
            background(
                cypherCardFill,
                in: RoundedRectangle(cornerRadius: CypherRadius.card, style: .continuous)
            )
        case .hero:
            background(
                .regularMaterial,
                in: RoundedRectangle(cornerRadius: CypherRadius.hero, style: .continuous)
            )
        }
    }

    private var cypherCardFill: AnyShapeStyle {
        #if os(macOS)
        AnyShapeStyle(.background.secondary)
        #else
        AnyShapeStyle(.fill.tertiary)
        #endif
    }
}
