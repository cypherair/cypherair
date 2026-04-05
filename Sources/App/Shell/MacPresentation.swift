import SwiftUI

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
