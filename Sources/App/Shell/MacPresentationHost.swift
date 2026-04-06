import SwiftUI

private struct MacPresentationHostModifier: ViewModifier {
    @Binding var activePresentation: MacPresentation?

    @Environment(AppConfiguration.self) private var config
    @Environment(TutorialSessionStore.self) private var tutorialStore

    func body(content: Content) -> some View {
        ZStack {
            content

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
            case .importConfirmation(let request):
                let onImportUnverified: (() -> Void)? = request.allowsUnverifiedImport ? {
                    activePresentation = nil
                    request.onImportUnverified()
                } : nil

                ImportConfirmView(
                    keyInfo: request.keyInfo,
                    detectedProfile: request.profile,
                    onImportVerified: {
                        activePresentation = nil
                        request.onImportVerified()
                    },
                    onImportUnverified: onImportUnverified,
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
        case .importConfirmation, .authModeConfirmation, .modifyExpiry:
            return nil
        }
    }

    private var modalPresentationBinding: Binding<MacPresentation?> {
        Binding(
            get: {
                guard let activePresentation else { return nil }
                switch activePresentation {
                case .importConfirmation, .authModeConfirmation, .modifyExpiry:
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
                .environment(config)
                .environment(tutorialStore)
                .environment(\.macPresentationController, macPresentationControllerValue)
        case .tutorial(let presentationContext):
            TutorialView(
                presentationContext: presentationContext,
                onTutorialFinished: {
                    activePresentation = nil
                }
            )
            .environment(config)
            .environment(tutorialStore)
            .environment(\.macPresentationController, macPresentationControllerValue)
        case .importConfirmation, .authModeConfirmation, .modifyExpiry:
            EmptyView()
        }
    }

    private var macPresentationControllerValue: MacPresentationController {
        MacPresentationController(
            present: { presentation in
                activePresentation = presentation
            },
            dismiss: {
                activePresentation = nil
            }
        )
    }
}

extension View {
    func macPresentationHost(_ activePresentation: Binding<MacPresentation?>) -> some View {
        modifier(MacPresentationHostModifier(activePresentation: activePresentation))
    }
}
