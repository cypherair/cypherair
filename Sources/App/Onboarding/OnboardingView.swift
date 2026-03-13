import SwiftUI

/// Three-page onboarding flow shown on first launch.
/// Can be re-viewed from Settings.
struct OnboardingView: View {
    @Environment(AppConfiguration.self) private var config

    @State private var currentPage = 0

    var body: some View {
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
    }
}

/// Page 1: Offline Security
struct OnboardingPageOne: View {
    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "wifi.slash")
                .font(.system(size: 72))
                .foregroundStyle(.blue)

            Text(String(localized: "onboarding.p1.title", defaultValue: "Completely Offline"))
                .font(.title.bold())

            Text(String(localized: "onboarding.p1.body", defaultValue: "Cypher Air never connects to the internet. Your messages and keys stay on your device."))
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
                .font(.system(size: 72))
                .foregroundStyle(.green)

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

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "key.fill")
                .font(.system(size: 72))
                .foregroundStyle(.orange)

            Text(String(localized: "onboarding.p3.title", defaultValue: "Generate Your Key"))
                .font(.title.bold())

            Text(String(localized: "onboarding.p3.body", defaultValue: "Create your encryption key to start securing your messages. You can choose between Universal (GnuPG compatible) and Advanced (stronger security) profiles."))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            Button {
                config.hasCompletedOnboarding = true
                dismiss()
            } label: {
                Text(String(localized: "onboarding.getStarted", defaultValue: "Get Started"))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 40)

            Spacer()
        }
    }
}
