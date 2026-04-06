import SwiftUI

private struct MacPresentationHostModifier: ViewModifier {
    @Binding var activePresentation: MacPresentation?

    @Environment(AppConfiguration.self) private var config
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(TutorialPresentationCoordinator.self) private var tutorialPresentationCoordinator

    func body(content: Content) -> some View {
        content
            .sheet(item: $activePresentation) { presentation in
                switch presentation {
                case .importConfirmation(let request):
                    ImportConfirmView(
                        keyInfo: request.keyInfo,
                        detectedProfile: request.profile,
                        onImportVerified: {
                            activePresentation = nil
                            request.onImportVerified()
                        },
                        onImportUnverified: request.allowsUnverifiedImport ? {
                            activePresentation = nil
                            request.onImportUnverified()
                        } : nil,
                        onCancel: {
                            activePresentation = nil
                            request.onCancel()
                        }
                    )
                    .presentationSizing(.form)
                case .authModeConfirmation(let request):
                    NavigationStack {
                        SettingsAuthModeConfirmationSheetView(request: request)
                    }
                    .presentationSizing(.form)
                case .modifyExpiry(let request):
                    NavigationStack {
                        ModifyExpirySheetView(request: request)
                    }
                    .presentationSizing(.form)
                case .onboarding(let initialPage):
                    OnboardingView(initialPage: initialPage)
                        .environment(config)
                        .environment(tutorialStore)
                        .interactiveDismissDisabled(!config.hasCompletedOnboarding)
                        .presentationSizing(.page)
                case .tutorial(let presentationContext):
                    Color.clear
                        .task {
                            tutorialPresentationCoordinator.presentMacTutorial(
                                origin: presentationContext == .onboardingFirstRun ? .onboardingFirstRun : .inApp
                            )
                            activePresentation = nil
                        }
                }
            }
    }
}

extension View {
    func macPresentationHost(_ activePresentation: Binding<MacPresentation?>) -> some View {
        modifier(MacPresentationHostModifier(activePresentation: activePresentation))
    }
}
