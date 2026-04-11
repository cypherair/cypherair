import SwiftUI

let macMainWindowID = "cypherair-main-window"

@MainActor
enum MacPresentation: Identifiable {
    case importConfirmation(ImportConfirmationRequest)
    case authModeConfirmation(AuthModeChangeConfirmationRequest)
    case modifyExpiry(ModifyExpiryRequest)
    case onboarding(initialPage: Int)
    case tutorial(presentationContext: TutorialPresentationContext)

    var id: String {
        switch self {
        case .importConfirmation(let request):
            "import-\(request.id.uuidString)"
        case .authModeConfirmation(let request):
            "auth-\(request.id.uuidString)"
        case .modifyExpiry(let request):
            "expiry-\(request.id.uuidString)"
        case .onboarding(let initialPage):
            "onboarding-\(initialPage)"
        case .tutorial(let presentationContext):
            switch presentationContext {
            case .onboardingFirstRun:
                "tutorial-onboarding"
            case .inApp:
                "tutorial-in-app"
            }
        }
    }
}

struct MacPresentationController {
    let present: @MainActor (MacPresentation) -> Void
    let dismiss: @MainActor () -> Void
}

enum MacPresentationHostMode {
    case mainWindow
    case settingsScene
}

@MainActor
struct MacTutorialLaunchRequest: Identifiable {
    let id = UUID()
    let presentationContext: TutorialPresentationContext
}

@MainActor
@Observable
final class MacTutorialLaunchRelay {
    private(set) var pendingRequest: MacTutorialLaunchRequest?

    var pendingRequestID: UUID? {
        pendingRequest?.id
    }

    func submit(_ presentationContext: TutorialPresentationContext) {
        pendingRequest = MacTutorialLaunchRequest(presentationContext: presentationContext)
    }

    func pendingPresentation(currentPresentation: MacPresentation?) -> MacPresentation? {
        guard let pendingRequest else { return nil }
        guard currentPresentation?.blocksTutorialRelayConsumption != true else {
            return nil
        }

        return .tutorial(presentationContext: pendingRequest.presentationContext)
    }

    func clearIfMatches(_ requestID: UUID) {
        guard pendingRequest?.id == requestID else { return }
        pendingRequest = nil
    }
}

private extension MacPresentation {
    var blocksTutorialRelayConsumption: Bool {
        switch self {
        case .importConfirmation, .authModeConfirmation, .modifyExpiry:
            true
        case .onboarding, .tutorial:
            false
        }
    }
}

extension MacPresentationController {
    @MainActor
    static func mainWindow(
        activePresentation: Binding<MacPresentation?>
    ) -> MacPresentationController {
        MacPresentationController(
            present: { presentation in
                activePresentation.wrappedValue = presentation
            },
            dismiss: {
                activePresentation.wrappedValue = nil
            }
        )
    }

    @MainActor
    static func settingsScene(
        activePresentation: Binding<MacPresentation?>,
        tutorialLaunchRelay: MacTutorialLaunchRelay,
        openMainWindow: @escaping @MainActor () -> Void
    ) -> MacPresentationController {
        MacPresentationController(
            present: { presentation in
                switch presentation {
                case .tutorial(let presentationContext):
                    activePresentation.wrappedValue = nil
                    openMainWindow()
                    tutorialLaunchRelay.submit(presentationContext)
                case .importConfirmation, .authModeConfirmation, .modifyExpiry, .onboarding:
                    activePresentation.wrappedValue = presentation
                }
            },
            dismiss: {
                activePresentation.wrappedValue = nil
            }
        )
    }
}

private struct MacPresentationControllerKey: EnvironmentKey {
    static let defaultValue: MacPresentationController? = nil
}

extension EnvironmentValues {
    var macPresentationController: MacPresentationController? {
        get { self[MacPresentationControllerKey.self] }
        set { self[MacPresentationControllerKey.self] = newValue }
    }
}
