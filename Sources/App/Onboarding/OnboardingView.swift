import SwiftUI

/// Four-page onboarding flow shown on first launch.
/// Can be re-viewed from Settings.
struct OnboardingView: View {
    let presentationContext: OnboardingPresentationContext
    @State private var currentPage: Int
    @State private var fold: CGRect?

    init(
        initialPage: Int = 0,
        presentationContext: OnboardingPresentationContext = .firstRun
    ) {
        self.presentationContext = presentationContext
        _currentPage = State(initialValue: min(max(initialPage, 0), 3))
    }

    var body: some View {
        #if canImport(UIKit)
        TabView(selection: $currentPage) {
            OnboardingOfflinePage(fold: fold)
                .tag(0)

            OnboardingStandardPage(fold: fold)
                .tag(1)

            OnboardingKeyFamiliesPage(fold: fold)
                .tag(2)

            OnboardingTutorialPage(fold: fold)
                .tag(3)
        }
        .tabViewStyle(.page(indexDisplayMode: .always))
        .indexViewStyle(.page(backgroundDisplayMode: .always))
        .onGeometryChange(for: CGRect?.self) { proxy in
            proxy.activeFold
        } action: { newFold in
            fold = newFold
        }
        #else
        VStack {
            Group {
                switch currentPage {
                case 0: OnboardingOfflinePage(fold: nil)
                case 1: OnboardingStandardPage(fold: nil)
                case 2: OnboardingKeyFamiliesPage(fold: nil)
                case 3: OnboardingTutorialPage(fold: nil)
                default: OnboardingOfflinePage(fold: nil)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                Button(String(localized: "onboarding.back", defaultValue: "Back")) {
                    withAnimation { currentPage -= 1 }
                }
                .disabled(currentPage == 0)

                Spacer()

                HStack(spacing: CypherSpacing.compact) {
                    ForEach(0..<4, id: \.self) { index in
                        Circle()
                            .fill(index == currentPage ? Color.primary : Color.secondary.opacity(0.3))
                            .frame(width: 8, height: 8)
                    }
                }

                Spacer()

                Button(String(localized: "onboarding.next", defaultValue: "Next")) {
                    withAnimation { currentPage += 1 }
                }
                .disabled(currentPage >= 3)
            }
            .padding()
        }
        #endif
    }
}

/// One onboarding page: its header (symbol, title, explanation) and what
/// follows it (a note, or the way out). Together they are centred and scroll
/// when the page is too short for them; while a fold crosses the page the
/// header sits before the fold and the rest after it. The pager scrolls, so
/// no arrangement view can sit inside a page: the page places its two parts
/// around the fold frame the pager reads, in the pager's coordinates, which
/// every page shares.
private struct OnboardingPageLayout<Footer: View>: View {
    let fold: CGRect?
    let systemImage: String
    let tint: Color
    let title: String
    let message: String
    @ViewBuilder let footer: () -> Footer

    @Environment(\.verticalSizeClass) private var verticalSizeClass

    /// Room for the pager's page dots, which float over the bottom of every
    /// page; the macOS pager puts its controls below the page instead.
    private var pageIndicatorClearance: CGFloat {
        #if canImport(UIKit)
        52
        #else
        0
        #endif
    }

    private var spacing: CGFloat {
        verticalSizeClass == .compact ? CypherSpacing.standard : 24
    }

    var body: some View {
        Group {
            if let fold, fold.width > fold.height {
                VStack(spacing: 0) {
                    part { header }
                        .frame(height: max(fold.minY, 0))
                    Color.clear
                        .frame(height: fold.height)
                    part { footer() }
                        .padding(.bottom, pageIndicatorClearance)
                }
            } else if let fold {
                HStack(spacing: 0) {
                    part { header }
                        .frame(width: max(fold.minX, 0))
                    Color.clear
                        .frame(width: fold.width)
                    part { footer() }
                }
                .padding(.bottom, pageIndicatorClearance)
            } else {
                part {
                    header
                    footer()
                }
                .padding(.bottom, pageIndicatorClearance)
            }
        }
        .cypherMacReadableContent(
            maxWidth: MacPresentationWidth.onboarding,
            alignment: .center,
            outerAlignment: .center
        )
    }

    @ViewBuilder
    private var header: some View {
        Image(systemName: systemImage)
            .font(.system(size: verticalSizeClass == .compact ? 48 : 72, weight: .light))
            .foregroundStyle(tint)
            .accessibilityHidden(true)

        Text(title)
            .font(.title.bold())
            .multilineTextAlignment(.center)

        Text(message)
            .font(.body)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 40)
    }

    private func part(@ViewBuilder _ content: () -> some View) -> some View {
        ScrollView {
            VStack(spacing: spacing) {
                content()
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, spacing)
        }
        .defaultScrollAnchor(.center, for: .alignment)
        .scrollBounceBehavior(.basedOnSize)
    }
}

/// Page 0: the offline promise and its device-only consequence — backups do
/// not restore keys, so the user must keep their own export.
struct OnboardingOfflinePage: View {
    let fold: CGRect?

    var body: some View {
        OnboardingPageLayout(
            fold: fold,
            systemImage: "wifi.slash",
            tint: .blue,
            title: String(localized: "onboarding.p1.title", defaultValue: "Completely Offline"),
            message: String(localized: "onboarding.p1.body", defaultValue: "CypherAir X never connects to the internet. Your messages and keys stay on your device.")
        ) {
            VStack(alignment: .leading, spacing: CypherSpacing.compact) {
                Label(
                    String(localized: "onboarding.p1.deviceOnly.title", defaultValue: "Only on This Device"),
                    systemImage: "externaldrive.badge.xmark"
                )
                .font(.subheadline.weight(.semibold))

                Text(String(localized: "onboarding.p1.deviceOnly.body", defaultValue: "Your keys and contacts exist only on this device. Restoring an iCloud or computer backup does not bring them back or make your data usable again. To keep a copy of a key, export it as a passphrase-protected .asc file — the guided tutorial shows how."))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(CypherSpacing.standard)
            .frame(maxWidth: .infinity, alignment: .leading)
            .cypherSurface(.card)
            .padding(.horizontal, 40)
        }
    }
}

/// Page 1: OpenPGP standard compatibility.
struct OnboardingStandardPage: View {
    let fold: CGRect?

    var body: some View {
        OnboardingPageLayout(
            fold: fold,
            systemImage: "lock.shield",
            tint: .green,
            title: String(localized: "onboarding.p2.title", defaultValue: "OpenPGP Standard"),
            message: String(localized: "onboarding.p2.body", defaultValue: "Compatible with GnuPG and other PGP tools. Your contacts can verify your messages with any standards-compliant software.")
        ) {
            EmptyView()
        }
    }
}

/// Page 2: key families — Secure Enclave custody and post-quantum options.
struct OnboardingKeyFamiliesPage: View {
    let fold: CGRect?

    var body: some View {
        OnboardingPageLayout(
            fold: fold,
            systemImage: "cpu",
            tint: .purple,
            title: String(localized: "onboarding.keyFamilies.title", defaultValue: "Secure Enclave & Post-Quantum"),
            message: String(localized: "onboarding.keyFamilies.body", defaultValue: "Nine key families to choose from. Device-Bound keys keep private keys inside this device’s Secure Enclave — they can never leave. Post-Quantum keys are designed to resist future quantum computers. Classical portable keys remain for full GnuPG compatibility.")
        ) {
            EmptyView()
        }
    }
}

/// Page 3: exit — enter the guided tutorial sandbox or skip into the app.
struct OnboardingTutorialPage: View {
    let fold: CGRect?

    @Environment(AppSettingsCoordinator.self) private var appSettings
    @Environment(\.dismiss) private var dismiss
    @Environment(\.iosPresentationController) private var iosPresentationController
    @Environment(\.macPresentationController) private var macPresentationController

    var body: some View {
        OnboardingPageLayout(
            fold: fold,
            systemImage: "testtube.2",
            tint: .orange,
            title: String(localized: "onboarding.p3.title", defaultValue: "Start with a Guided Tutorial"),
            message: String(localized: "onboarding.p3.body", defaultValue: "Learn CypherAir X in an isolated sandbox first, or skip the tutorial and enter the real app right away. Tutorial actions never touch your real keys, contacts, settings, files, exports, or private-key security assets.")
        ) {
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
        }
        .screenReady(TutorialAutomationContract.onboardingDecisionReadyMarker)
    }

    private func presentTutorial() {
        appSettings.setHasCompletedOnboarding(true)
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
        appSettings.setHasCompletedOnboarding(true)
        if let macPresentationController {
            macPresentationController.dismiss()
        } else if let iosPresentationController {
            iosPresentationController.dismiss()
        } else {
            dismiss()
        }
    }
}
