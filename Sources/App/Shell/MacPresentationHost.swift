import SwiftUI

private struct MacPresentationHostModifier: ViewModifier {
    @Binding var activePresentation: MacPresentation?

    @Environment(AppSettingsCoordinator.self) private var appSettings
    @Environment(TutorialSessionStore.self) private var tutorialStore

    func body(content: Content) -> some View {
        ZStack {
            content
                .environment(\.macPresentationController, macPresentationControllerValue)

            if let workspacePresentation {
                workspaceOverlay(for: workspacePresentation)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(.background)
                    .transition(.opacity)
                    .zIndex(1)
            }
        }
        .sheet(item: modalPresentationBinding) { presentation in
            switch presentation {
            case .modifyExpiry(let request):
                NavigationStack {
                    ModifyExpirySheetView(request: request)
                }
                .presentationSizing(.form)
            case .onboarding, .tutorial:
                EmptyView()
            }
        }
    }

    private var workspacePresentation: MacPresentation? {
        guard let activePresentation else { return nil }
        switch activePresentation {
        case .onboarding, .tutorial:
            return activePresentation
        case .modifyExpiry:
            return nil
        }
    }

    private var modalPresentationBinding: Binding<MacPresentation?> {
        Binding(
            get: {
                guard let activePresentation else { return nil }
                switch activePresentation {
                case .modifyExpiry:
                    return activePresentation
                case .onboarding, .tutorial:
                    return nil
                }
            },
            set: { newValue in
                if let newValue {
                    activePresentation = newValue
                } else {
                    activePresentation = nil
                }
            }
        )
    }

    @ViewBuilder
    private func workspaceOverlay(for presentation: MacPresentation) -> some View {
        switch presentation {
        case .onboarding(let initialPage):
            OnboardingView(initialPage: initialPage)
                .environment(appSettings)
                .environment(tutorialStore)
                .environment(\.macPresentationController, macPresentationControllerValue)
        case .tutorial(let presentationContext):
            TutorialView(
                presentationContext: presentationContext,
                onTutorialFinished: {
                    activePresentation = nil
                }
            )
            .environment(appSettings)
            .environment(tutorialStore)
            .environment(\.macPresentationController, macPresentationControllerValue)
        case .modifyExpiry:
            EmptyView()
        }
    }

    private var macPresentationControllerValue: MacPresentationController {
        MacPresentationController.mainWindow(activePresentation: $activePresentation)
    }

}

extension View {
    func macPresentationHost(
        _ activePresentation: Binding<MacPresentation?>
    ) -> some View {
        modifier(
            MacPresentationHostModifier(
                activePresentation: activePresentation
            )
        )
    }
}
