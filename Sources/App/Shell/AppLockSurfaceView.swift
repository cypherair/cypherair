import SwiftUI
#if os(macOS)
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
#endif

/// The opaque lock surface shown while `AppLockController` is locked. It
/// auto-invokes authentication on appear and hosts the retry / biometrics-locked-out
/// messaging, driven solely by the explicit `AppLockController.lockState`.
///
/// On macOS the surface additionally HOSTS the app-session authentication
/// itself (issue #724): while an embedded attempt is presenting, the
/// `LAAuthenticationView` bound to `AppSessionUnlockPresenter`'s published
/// context renders the Touch ID prompt in-window (no app resign), with the
/// Standard-mode "Use Password…" action beside it; the composition for the
/// settled states follows the presenter's method matrix (password-primary
/// when biometrics cannot evaluate in Standard mode, the existing
/// failure/retry surfaces in High Security). Other platforms keep the
/// system-sheet presentation unchanged.
///
/// The surface is deliberately OPAQUE — an app-identified screen, not a
/// material over content: locked content must never show through. The header
/// is text-only (app name + locked-state caption) by maintainer decision —
/// no decorative lock imagery. The cosmetic privacy cover is the same shield
/// window's OTHER rendering mode (`AppPrivacySurfaceView` below; issue #723)
/// — same visual family, no authentication role. Native platform chrome
/// only; no `.glassEffect()` on a security surface (PRD §4.9).
struct AppLockSurfaceView: View {
    let appLockController: AppLockController
    #if os(macOS)
    /// The macOS in-window unlock owner (issue #724). Optional structurally
    /// (a nil presenter composes exactly the pre-#724 retry surface), but
    /// every macOS app container wires one.
    var unlockPresenter: AppSessionUnlockPresenter?
    #endif

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
        // The surface marker lives on the always-present header, NOT the
        // surface root: a container-level `accessibilityIdentifier` replaces
        // the identifiers of every contained element (verified against the
        // AX hierarchy), which would mask the state content's own
        // identifiers (`appLock.passwordUnlock`, `appLock.embeddedAuth`).
        .accessibilityIdentifier("appLock.surface")
    }

    @ViewBuilder
    private var stateContent: some View {
        switch appLockController.lockState {
        case .authenticating:
            #if os(macOS)
            macAuthenticatingContent
            #else
            ProgressView()
            #endif
        case .authenticationFailed(.biometricsLockedOut):
            #if os(macOS)
            macBiometricsLockedOutContent
            #else
            biometricsLockedOutCard
            #endif
        case .authenticationFailed(.authenticationFailed), .locked:
            #if os(macOS)
            macIdleUnlockContent
            #else
            standardRetryAuthenticationButton
            #endif
        case .unlocked:
            EmptyView()
        }
    }

    private var standardRetryAuthenticationButton: some View {
        retryAuthenticationButton(
            title: String(localized: "privacy.tapToAuth", defaultValue: "Tap to Authenticate"),
            accessibilityLabel: String(
                localized: "privacy.tapToAuth.a11y",
                defaultValue: "Authenticate to unlock the app"
            )
        )
    }

    #if os(macOS)

    // MARK: - macOS in-window unlock composition (issue #724)

    /// `.authenticating` face: the embedded biometric prompt while an
    /// embedded attempt is presenting (with the Standard-mode password
    /// action), otherwise the indeterminate spinner — the detached
    /// system-sheet password evaluation and the post-auth fan-out both show
    /// the system UI or finish quickly, exactly as before.
    @ViewBuilder
    private var macAuthenticatingContent: some View {
        if let unlockPresenter, let context = unlockPresenter.presentedEmbeddedContext {
            VStack(spacing: 14) {
                // The identifier sits on the leaf host, not this container: a
                // container-level identifier would replace its children's own
                // (see the `appLock.surface` placement note).
                MacEmbeddedAuthenticationViewHost(context: context) {
                    unlockPresenter.embeddedAuthenticationViewDidMount(for: context)
                }
                .frame(width: 120, height: 120)
                .id(ObjectIdentifier(context))
                .accessibilityIdentifier("appLock.embeddedAuth")

                // The embedded view is deliberately non-textual (its reason
                // must be apparent from the surrounding UI), so the surface
                // carries the same reason string the evaluation uses.
                Text(String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume"))
                    .font(.callout)
                    .foregroundStyle(.secondary)

                if unlockPresenter.offersPasswordUnlock {
                    passwordUnlockButton(prominent: false)
                }
            }
        } else {
            ProgressView()
        }
    }

    /// `.locked` / `.authenticationFailed(.authenticationFailed)` face:
    /// password-primary when Standard mode cannot evaluate biometrics,
    /// otherwise the existing retry affordance plus the Standard-mode
    /// password action.
    @ViewBuilder
    private var macIdleUnlockContent: some View {
        if let unlockPresenter, unlockPresenter.composesPasswordPrimary {
            passwordUnlockButton(prominent: true)
        } else {
            VStack(spacing: 14) {
                standardRetryAuthenticationButton
                if unlockPresenter?.offersPasswordUnlock == true {
                    passwordUnlockButton(prominent: false)
                }
            }
        }
    }

    /// `.authenticationFailed(.biometricsLockedOut)` face: in Standard mode
    /// the system password sheet is both the unlock and the lockout recovery,
    /// so compose it primary under the existing lockout title; High Security
    /// keeps the existing biometrics-only locked-out card verbatim.
    @ViewBuilder
    private var macBiometricsLockedOutContent: some View {
        if let unlockPresenter, unlockPresenter.offersPasswordUnlock {
            VStack(spacing: 14) {
                Text(biometricsLockedOutTitle)
                    .font(.headline)
                    .multilineTextAlignment(.center)
                passwordUnlockButton(prominent: true)
            }
        } else {
            biometricsLockedOutCard
        }
    }

    /// The explicit "Use Password…" action (Standard mode only): a detached
    /// system-sheet evaluation via the presenter's one-shot request. During
    /// an embedded attempt the request cancels the pending evaluation and the
    /// in-flight attempt continues on the sheet (`retryUnlock` no-ops on
    /// `.authenticating`); from a settled state it starts a fresh attempt
    /// that consumes the request. The `isLocked` re-check closes the race
    /// where the click lands in the same instant an attempt unlocks.
    @ViewBuilder
    private func passwordUnlockButton(prominent: Bool) -> some View {
        let button = Button {
            unlockPresenter?.requestPasswordUnlock()
            Task {
                if appLockController.isLocked {
                    await appLockController.retryUnlock(source: "usePassword")
                }
            }
        } label: {
            Text(String(localized: "privacy.usePassword", defaultValue: "Use Password…"))
                .font(prominent ? .headline : .callout)
        }
        .accessibilityLabel(String(
            localized: "privacy.usePassword.a11y",
            defaultValue: "Unlock with your Mac password"
        ))
        .accessibilityIdentifier("appLock.passwordUnlock")

        if prominent {
            button.buttonStyle(.borderedProminent)
        } else {
            button.buttonStyle(.borderless)
        }
    }

    #endif

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

#if os(macOS)
/// Hosts the AppKit `LAAuthenticationView` (LocalAuthenticationEmbeddedUI)
/// bound to the presenter's published context inside the SwiftUI lock
/// surface (issue #724). The AppKit view was chosen over the SwiftUI
/// `LocalAuthenticationView(_:context:)` sibling on evidence: both are
/// probe-proven on this OS build (PR #496 probes D and G/H), but only the
/// AppKit route gives a deterministic post-attach hook for the load-bearing
/// evaluate-after-mount ordering — `makeNSView` pairs the context eagerly
/// and the main-queue hop lands after the hosting transaction commits (the
/// #469 PoC's on-device-validated mechanic), whereas the SwiftUI wrapper
/// hides both the pairing moment and the attachment moment.
///
/// The view is created once per context; the caller re-keys identity by the
/// context object (`.id(ObjectIdentifier(context))`), so a fresh attempt can
/// never inherit a view paired to a previous context
/// (`LAAuthenticationView.context` is read-only).
private struct MacEmbeddedAuthenticationViewHost: NSViewRepresentable {
    let context: LAContext
    let onMount: () -> Void

    func makeNSView(context _: Context) -> LAAuthenticationView {
        let view = LAAuthenticationView(context: self.context)
        DispatchQueue.main.async { onMount() }
        return view
    }

    func updateNSView(_: LAAuthenticationView, context _: Context) {}
}
#endif

/// The shield window's privacy face (issue #723): shown while the app is
/// cosmetically covered but not locked (multitasking snapshot,
/// shoulder-surfing). Same visual family as the lock surface minus the
/// authentication affordance and lock texts — an opaque, app-identified
/// screen carrying only the existing localized display name, so it adds no
/// String Catalog entries. Purely visual: the per-mode input discipline (no
/// key status, no text-editing interruption) lives in the shield coordinator
/// (`AppLockShieldWindow.swift`), not here.
struct AppPrivacySurfaceView: View {
    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
                .ignoresSafeArea()

            Text(AppProductIdentity.localizedDisplayName)
                .font(.title2.weight(.semibold))
        }
        .accessibilityIdentifier("appLock.privacySurface")
    }
}
