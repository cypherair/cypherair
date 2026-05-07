import SwiftUI

/// Three-page onboarding flow shown on first launch.
/// Can be re-viewed from Settings.
struct OnboardingView: View {
    let presentationContext: OnboardingPresentationContext
    @State private var currentPage: Int

    init(
        initialPage: Int = 0,
        presentationContext: OnboardingPresentationContext = .firstRun
    ) {
        self.presentationContext = presentationContext
        _currentPage = State(initialValue: min(max(initialPage, 0), 2))
    }

    var body: some View {
        #if canImport(UIKit)
        TabView(selection: $currentPage) {
            OnboardingPageOne()
                .tag(0)

            OnboardingPageTwo()
                .tag(1)

            OnboardingPageThree(presentationContext: presentationContext)
                .tag(2)
        }
        .tabViewStyle(.page(indexDisplayMode: .always))
        .indexViewStyle(.page(backgroundDisplayMode: .always))
        #else
        VStack {
            Group {
                switch currentPage {
                case 0: OnboardingPageOne()
                case 1: OnboardingPageTwo()
                case 2: OnboardingPageThree(presentationContext: presentationContext)
                default: OnboardingPageOne()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                Button(String(localized: "onboarding.back", defaultValue: "Back")) {
                    withAnimation { currentPage -= 1 }
                }
                .disabled(currentPage == 0)

                Spacer()

                HStack(spacing: 8) {
                    ForEach(0..<3, id: \.self) { index in
                        Circle()
                            .fill(index == currentPage ? Color.primary : Color.secondary.opacity(0.3))
                            .frame(width: 8, height: 8)
                    }
                }

                Spacer()

                Button(String(localized: "onboarding.next", defaultValue: "Next")) {
                    withAnimation { currentPage += 1 }
                }
                .disabled(currentPage >= 2)
            }
            .padding()
        }
        #endif
    }
}

/// Page 1: Offline Security
struct OnboardingPageOne: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "wifi.slash")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.blue)
                .accessibilityHidden(true)

            Text(String(localized: "onboarding.p1.title", defaultValue: "Completely Offline"))
                .font(.title.bold())

            Text(String(localized: "onboarding.p1.body", defaultValue: "CypherAir never connects to the internet. Your messages and keys stay on your device."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
        .cypherMacReadableContent(
            maxWidth: MacPresentationWidth.onboarding,
            alignment: .center,
            outerAlignment: .center
        )
    }
}

/// Page 2: PGP Introduction
struct OnboardingPageTwo: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.shield")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.green)
                .accessibilityHidden(true)

            Text(String(localized: "onboarding.p2.title", defaultValue: "OpenPGP Standard"))
                .font(.title.bold())

            Text(String(localized: "onboarding.p2.body", defaultValue: "Compatible with GnuPG and other PGP tools. Your contacts can verify your messages with any standards-compliant software."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Spacer()
            Spacer()
        }
        .cypherMacReadableContent(
            maxWidth: MacPresentationWidth.onboarding,
            alignment: .center,
            outerAlignment: .center
        )
    }
}

/// Page 3: Generate Key CTA
struct OnboardingPageThree: View {
    @Environment(ProtectedOrdinarySettingsCoordinator.self) private var protectedOrdinarySettings
    @Environment(\.dismiss) private var dismiss
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(\.macPresentationController) private var macPresentationController

    let presentationContext: OnboardingPresentationContext

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "testtube.2")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)

            Text(String(localized: "onboarding.p3.title", defaultValue: "Start with a Guided Tutorial"))
                .font(.title.bold())

            Text(String(localized: "onboarding.p3.body", defaultValue: "Learn CypherAir in an isolated sandbox first, or skip the tutorial and enter the real app right away. Tutorial actions never touch your real keys, contacts, settings, files, exports, or private-key security assets."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Button {
                presentTutorial()
            } label: {
                Text(String(localized: "guidedTutorial.onboarding.enterTutorial", defaultValue: "Close Onboarding and Enter Tutorial"))
                    .cypherPrimaryActionLabelFrame(minWidth: 280)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 40)
            .accessibilityIdentifier(TutorialAutomationContract.onboardingStartIdentifier)

            Button {
                skipTutorial()
            } label: {
                Text(String(localized: "onboarding.skip.enterApp", defaultValue: "Skip Tutorial and Enter App"))
                    .cypherPrimaryActionLabelFrame(minWidth: 280)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .padding(.horizontal, 40)
            .accessibilityIdentifier(TutorialAutomationContract.onboardingSkipIdentifier)

            Spacer()
        }
        .cypherMacReadableContent(
            maxWidth: MacPresentationWidth.onboarding,
            alignment: .center,
            outerAlignment: .center
        )
        .screenReady(TutorialAutomationContract.onboardingDecisionReadyMarker)
    }

    private func presentTutorial() {
        protectedOrdinarySettings.setHasCompletedOnboarding(true)
        #if os(iOS)
        if let iosPresentationController {
            iosPresentationController.handoffToTutorialAfterOnboardingDismiss(.onboardingFirstRun)
        }
        #else
        if let macPresentationController {
            macPresentationController.present(.tutorial(presentationContext: .onboardingFirstRun))
        } else if let iosPresentationController {
            iosPresentationController.handoffToTutorialAfterOnboardingDismiss(.onboardingFirstRun)
        } else {
            dismiss()
        }
        #endif
    }

    private func skipTutorial() {
        protectedOrdinarySettings.setHasCompletedOnboarding(true)
        if let macPresentationController {
            macPresentationController.dismiss()
        } else if let iosPresentationController {
            iosPresentationController.dismiss()
        } else {
            dismiss()
        }
    }
}

private extension View {
    @ViewBuilder
    func `if`<Content: View>(
        _ condition: Bool,
        transform: (Self) -> Content
    ) -> some View {
        if condition {
            transform(self)
        } else {
            self
        }
    }
}
