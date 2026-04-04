import SwiftUI

/// Three-page onboarding flow shown on first launch.
/// Can be re-viewed from Settings.
struct OnboardingView: View {
    @Environment(AppConfiguration.self) private var config

    @State private var currentPage: Int

    init(initialPage: Int = 0) {
        _currentPage = State(initialValue: min(max(initialPage, 0), 2))
    }

    var body: some View {
        #if canImport(UIKit)
        TabView(selection: $currentPage) {
            OnboardingPageOne()
                .tag(0)

            OnboardingPageTwo()
                .tag(1)

            OnboardingPageThree()
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
                case 2: OnboardingPageThree()
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
    }
}

/// Page 3: Generate Key CTA
struct OnboardingPageThree: View {
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss
    #if canImport(UIKit)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    @State private var showTutorial = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "key.fill")
                .font(.system(size: 72, weight: .light))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)

            Text(String(localized: "onboarding.p3.title", defaultValue: "Generate Your Key"))
                .font(.title.bold())

            Text(String(localized: "onboarding.p3.body", defaultValue: "Create your encryption key to start securing your messages. You can choose between Universal (GnuPG compatible) and Advanced (stronger security) profiles."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Button {
                showTutorial = true
            } label: {
                Text(guidedTutorialEntryTitle)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 40)

            Button {
                config.hasCompletedOnboarding = true
                dismiss()
            } label: {
                Text(String(localized: "onboarding.getStarted", defaultValue: "Get Started"))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .padding(.horizontal, 40)

            Spacer()
        }
        #if canImport(UIKit)
        .if(sizeClass == .compact) { view in
            view.fullScreenCover(isPresented: $showTutorial) {
                TutorialView(presentationContext: .onboardingFirstRun) {
                    showTutorial = false
                    dismiss()
                }
            }
        }
        .if(sizeClass != .compact) { view in
            view.sheet(isPresented: $showTutorial) {
                TutorialView(presentationContext: .onboardingFirstRun) {
                    showTutorial = false
                    dismiss()
                }
            }
        }
        #else
        .sheet(isPresented: $showTutorial) {
            TutorialView(presentationContext: .onboardingFirstRun) {
                showTutorial = false
                dismiss()
            }
        }
        #endif
    }

    private var guidedTutorialEntryTitle: String {
        switch config.guidedTutorialCompletionState {
        case .neverCompleted:
            String(localized: "guidedTutorial.onboarding.entry", defaultValue: "Open Guided Tutorial")
        case .completedCurrentVersion:
            String(localized: "guidedTutorial.replay", defaultValue: "Replay Guided Tutorial")
        case .completedPreviousVersion:
            String(localized: "guidedTutorial.updated.entry", defaultValue: "Updated Guided Tutorial Available")
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
