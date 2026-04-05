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
            content.background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        case .standard:
            #if canImport(UIKit)
            content.background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            #else
            content.background(.background.secondary, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            #endif
        case .overlay:
            content.background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
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
