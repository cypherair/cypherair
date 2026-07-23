import SwiftUI

/// The opaque lock surface shown while `AppLockController` is locked. It
/// auto-invokes authentication on appear and hosts the retry / biometrics-locked-out
/// messaging, driven solely by the explicit `AppLockController.lockState`.
///
/// The surface is deliberately OPAQUE — an app-identified screen, not a
/// material over content: locked content must never show through. The header
/// is text-only (app name + locked-state caption) by maintainer decision —
/// no decorative lock imagery. The cosmetic privacy cover
/// (`CosmeticPrivacyCover`) is a separate, unrelated layer with its own
/// role. Native platform chrome only; no `.glassEffect()` on a security
/// surface (PRD §4.9).
struct AppLockSurfaceView: View {
    let appLockController: AppLockController

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
                .ignoresSafeArea()

            // At accessibility Dynamic Type sizes the locked-out card can
            // outgrow a small screen; fall back to scrolling only then, so the
            // retry button is always reachable.
            ViewThatFits(in: .vertical) {
                lockContent
                ScrollView {
                    lockContent
                }
            }
        }
        .task {
            await appLockController.handleForegroundActive(source: "lockSurface.appear")
        }
        .accessibilityIdentifier("appLock.surface")
        // The surface is hosted in the shield window
        // (`AppLockShieldWindow.swift`), layered above all app content and
        // presentations. Mark it modal so VoiceOver confines navigation to the
        // lock surface and never reaches the locked content beneath; the
        // opaque fill already blocks pointer hit-testing within the shield.
        .accessibilityAddTraits(.isModal)
    }

    private var lockContent: some View {
        VStack(spacing: 28) {
            lockHeader
            stateContent
        }
        .padding(24)
    }

    private var lockHeader: some View {
        VStack(spacing: 8) {
            Text(AppProductIdentity.localizedDisplayName)
                .font(.title2.weight(.semibold))

            Text(String(localized: "privacy.locked.title", defaultValue: "Locked"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var stateContent: some View {
        switch appLockController.lockState {
        case .authenticating:
            ProgressView()
        case .authenticationFailed(.biometricsLockedOut):
            biometricsLockedOutCard
        case .authenticationFailed(.authenticationFailed), .locked:
            retryAuthenticationButton(
                title: String(localized: "privacy.tapToAuth", defaultValue: "Tap to Authenticate"),
                accessibilityLabel: String(
                    localized: "privacy.tapToAuth.a11y",
                    defaultValue: "Authenticate to unlock the app"
                )
            )
        case .unlocked:
            EmptyView()
        }
    }

    private var biometricIconName: String {
        #if os(macOS)
        "touchid"
        #elseif os(visionOS)
        "opticid"
        #else
        "faceid"
        #endif
    }

    private var biometricsLockedOutCard: some View {
        VStack(spacing: 14) {
            Image(systemName: biometricIconName)
                .font(.system(size: 32, weight: .semibold))
                .foregroundStyle(.secondary)

            VStack(spacing: 8) {
                Text(biometricsLockedOutTitle)
                    .font(.headline)
                    .multilineTextAlignment(.center)

                Text(biometricsLockedOutMessage)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)

                Text(biometricsLockedOutRecoveryMessage)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            retryAuthenticationButton(
                title: biometricsLockedOutRetryTitle,
                accessibilityLabel: biometricsLockedOutRetryAccessibilityLabel
            )
        }
        .padding(22)
        .frame(maxWidth: 440)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    private func retryAuthenticationButton(title: String, accessibilityLabel: String) -> some View {
        Button {
            Task { await appLockController.retryUnlock(source: "retryButton") }
        } label: {
            Label(title, systemImage: biometricIconName)
                .font(.headline)
        }
        .buttonStyle(.borderedProminent)
        .accessibilityLabel(accessibilityLabel)
    }

    private var biometricsLockedOutTitle: String {
        #if os(macOS)
        String(localized: "privacy.biometricsLockedOut.title.macOS", defaultValue: "Touch ID is locked by macOS")
        #elseif os(visionOS)
        String(localized: "privacy.biometricsLockedOut.title.visionOS", defaultValue: "Optic ID is locked by visionOS")
        #else
        String(localized: "privacy.biometricsLockedOut.title.iOS", defaultValue: "Biometric authentication is locked by iOS")
        #endif
    }

    private var biometricsLockedOutMessage: String {
        #if os(macOS)
        String(
            localized: "privacy.biometricsLockedOut.message.macOS",
            defaultValue: "CypherAir X is set to Biometrics Only, so it will not use your Mac password as a fallback."
        )
        #else
        String(
            localized: "privacy.biometricsLockedOut.message.device",
            defaultValue: "CypherAir X is set to Biometrics Only, so it will not use your device passcode as a fallback."
        )
        #endif
    }

    private var biometricsLockedOutRecoveryMessage: String {
        #if os(macOS)
        String(
            localized: "privacy.biometricsLockedOut.recovery.macOS",
            defaultValue: "Unlock your Mac with your password to re-enable Touch ID, then retry."
        )
        #else
        String(
            localized: "privacy.biometricsLockedOut.recovery.device",
            defaultValue: "Use the system passcode flow to re-enable biometric authentication, then retry."
        )
        #endif
    }

    private var biometricsLockedOutRetryTitle: String {
        #if os(macOS)
        String(localized: "privacy.biometricsLockedOut.retry.touchID", defaultValue: "Retry Touch ID")
        #elseif os(visionOS)
        String(localized: "privacy.biometricsLockedOut.retry.opticID", defaultValue: "Retry Optic ID")
        #else
        String(localized: "privacy.biometricsLockedOut.retry.faceID", defaultValue: "Retry Face ID")
        #endif
    }

    private var biometricsLockedOutRetryAccessibilityLabel: String {
        #if os(macOS)
        String(
            localized: "privacy.biometricsLockedOut.retry.a11y.macOS",
            defaultValue: "Retry Touch ID after re-enabling it with your Mac password"
        )
        #else
        String(
            localized: "privacy.biometricsLockedOut.retry.a11y.device",
            defaultValue: "Retry biometric authentication after re-enabling it with the system passcode"
        )
        #endif
    }
}
