import SwiftUI

/// Three-page onboarding flow shown on first launch.
/// Can be re-viewed from Settings.
struct OnboardingView: View {
    @Environment(AppConfiguration.self) private var config

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
        .accessibilityIdentifier("onboarding.page1")
        .screenReady(TutorialAutomationContract.Ready.onboardingPageOne)
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
        .accessibilityIdentifier("onboarding.page2")
        .screenReady(TutorialAutomationContract.Ready.onboardingPageTwo)
    }
}

/// Page 3: Generate Key CTA
struct OnboardingPageThree: View {
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss
    @Environment(\.iosPresentationController) private var iosPresentationController
    #if os(macOS)
    @Environment(TutorialPresentationCoordinator.self) private var tutorialPresentationCoordinator
    #endif

    let presentationContext: OnboardingPresentationContext

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "testtube.2")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)

            Text(String(localized: "onboarding.p3.title", defaultValue: "Choose How You Want to Start"))
                .font(.title.bold())

            Text(String(localized: "onboarding.p3.body", defaultValue: "Take the guided tutorial to learn CypherAir in a safe demo workspace first, or skip it and go straight into the real app."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Button {
                presentTutorial()
            } label: {
                Text(String(localized: "tutorial.onboarding.start", defaultValue: "Start Guided Tutorial"))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 40)
            .accessibilityIdentifier(TutorialAutomationContract.Identifier.onboardingStartTutorial)

            Button {
                config.hasCompletedOnboarding = true
                dismiss()
            } label: {
                Text(String(localized: "tutorial.onboarding.skip", defaultValue: "Skip Tutorial and Enter App"))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .padding(.horizontal, 40)
            .accessibilityIdentifier(TutorialAutomationContract.Identifier.onboardingSkipTutorial)

            Spacer()
        }
        .accessibilityIdentifier("onboarding.page3")
        .screenReady(TutorialAutomationContract.Ready.onboardingPageThree)
    }

    private func presentTutorial() {
        #if os(iOS)
        iosPresentationController?.dismiss()
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(150))
            iosPresentationController?.present(.tutorial(presentationContext: .onboardingFirstRun))
        }
        #else
        dismiss()
        tutorialPresentationCoordinator.presentMacTutorial(origin: .onboardingFirstRun)
        #endif
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
