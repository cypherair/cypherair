import SwiftUI

enum OnboardingPresentationContext {
    case firstRun
    case inApp
}

@MainActor
enum IOSPresentation: Identifiable {
    case onboarding(initialPage: Int, context: OnboardingPresentationContext)
    case tutorial(presentationContext: TutorialPresentationContext)

    var id: String {
        switch self {
        case .onboarding(let initialPage, let context):
            switch context {
            case .firstRun:
                "onboarding-firstRun-\(initialPage)"
            case .inApp:
                "onboarding-inApp-\(initialPage)"
            }
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

struct IOSPresentationController {
    let present: @MainActor (IOSPresentation) -> Void
    let dismiss: @MainActor () -> Void
    let handoffToTutorialAfterOnboardingDismiss: @MainActor (TutorialPresentationContext) -> Void
}

struct TutorialOnboardingHandoffState {
    var activePresentation: IOSPresentation?
    var pendingTutorialLaunchAfterOnboardingDismissal: TutorialPresentationContext?

    mutating func requestTutorialLaunchFromOnboarding(_ presentationContext: TutorialPresentationContext) {
        pendingTutorialLaunchAfterOnboardingDismissal = presentationContext

        if case .onboarding? = activePresentation {
            activePresentation = nil
        } else {
            activePresentation = .tutorial(presentationContext: presentationContext)
            pendingTutorialLaunchAfterOnboardingDismissal = nil
        }
    }

    mutating func completePendingTutorialLaunchIfNeeded() {
        guard activePresentation == nil,
              let pendingTutorialLaunchAfterOnboardingDismissal else {
            return
        }

        activePresentation = .tutorial(presentationContext: pendingTutorialLaunchAfterOnboardingDismissal)
        self.pendingTutorialLaunchAfterOnboardingDismissal = nil
    }
}

private struct IOSPresentationControllerKey: EnvironmentKey {
    static let defaultValue: IOSPresentationController? = nil
}

extension EnvironmentValues {
    var iosPresentationController: IOSPresentationController? {
        get { self[IOSPresentationControllerKey.self] }
        set { self[IOSPresentationControllerKey.self] = newValue }
    }
}
