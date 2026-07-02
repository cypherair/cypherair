import SwiftUI

enum TutorialCardChrome {
    case hero
    case standard
    case overlay
}

private struct TutorialCardChromeModifier: ViewModifier {
    let chrome: TutorialCardChrome

    func body(content: Content) -> some View {
        switch chrome {
        case .hero:
            content.cypherSurface(.hero)
        case .standard:
            content.cypherSurface(.card)
        case .overlay:
            // Floats over spotlighted live UI, so it keeps its own material
            // treatment instead of the shared card surface.
            content.background(.regularMaterial, in: RoundedRectangle(cornerRadius: overlayCornerRadius, style: .continuous))
        }
    }

    private var overlayCornerRadius: CGFloat {
        #if os(macOS)
        CypherRadius.control
        #else
        18
        #endif
    }
}

private struct TutorialBannerChromeModifier: ViewModifier {
    func body(content: Content) -> some View {
        content.background(.regularMaterial)
    }
}

extension View {
    func tutorialCardChrome(_ chrome: TutorialCardChrome) -> some View {
        modifier(TutorialCardChromeModifier(chrome: chrome))
    }

    func tutorialBannerChrome() -> some View {
        modifier(TutorialBannerChromeModifier())
    }
}
