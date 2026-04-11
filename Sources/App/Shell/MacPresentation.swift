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
enum MacTutorialHostBlocker: String, CaseIterable {
    case importConfirmationSheet
    case importErrorAlert
    case keyUpdateAlert
    case tutorialImportBlockedAlert
    case loadWarningAlert
    case hostImportConfirmation
    case hostAuthModeConfirmation
    case hostModifyExpiry
    case hostOnboarding
}

@MainActor
@Observable
final class MacTutorialHostAvailability {
    private(set) var appLevelBlockers: Set<MacTutorialHostBlocker> = []
    private(set) var hostBlocker: MacTutorialHostBlocker?

    var canPresentTutorialInMainWindow: Bool {
        appLevelBlockers.isEmpty && hostBlocker == nil
    }

    func setAppLevelBlocker(_ blocker: MacTutorialHostBlocker, isActive: Bool) {
        if isActive {
            appLevelBlockers.insert(blocker)
        } else {
            appLevelBlockers.remove(blocker)
        }
    }

    func updateHostPresentation(_ presentation: MacPresentation?) {
        hostBlocker = presentation?.tutorialHostBlocker
    }
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

    func clearIfMatches(_ requestID: UUID) {
        guard pendingRequest?.id == requestID else { return }
        pendingRequest = nil
    }
}

private extension MacPresentation {
    var tutorialHostBlocker: MacTutorialHostBlocker? {
        switch self {
        case .importConfirmation:
            .hostImportConfirmation
        case .authModeConfirmation:
            .hostAuthModeConfirmation
        case .modifyExpiry:
            .hostModifyExpiry
        case .onboarding:
            .hostOnboarding
        case .tutorial:
            nil
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
        tutorialHostAvailability: MacTutorialHostAvailability,
        onTutorialLaunchBlocked: @escaping @MainActor () -> Void,
        openMainWindow: @escaping @MainActor () -> Void
    ) -> MacPresentationController {
        MacPresentationController(
            present: { presentation in
                switch presentation {
                case .tutorial(let presentationContext):
                    guard tutorialHostAvailability.canPresentTutorialInMainWindow else {
                        onTutorialLaunchBlocked()
                        return
                    }

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
