import Foundation
import LocalAuthentication

// MARK: - macOS in-window app-session unlock (issue #724, stage 2)
//
// On macOS the app-session unlock authenticates INSIDE the shield window's
// lock surface: an `LAAuthenticationView` bound to an explicit `LAContext`
// renders the Touch ID prompt in-window, so unlocking no longer resigns the
// app (probe-verified for #724: `resignDelta 0`; the detached system sheet
// resigns the app on both present and dismiss). This type owns the unlock
// METHOD for that platform — which authentication mechanism an attempt uses
// and the presentation state the lock surface renders — while the flow
// itself stays exactly where it was:
//
// - `AppLockController.runUnlockFlow` still drives every attempt and spans
//   `.authenticating` across evaluation + post-auth fan-out; this type is
//   called through the controller's injected `evaluateAppSessionAuthentication`
//   closure and never calls the controller.
// - On success the produced context flows through the EXISTING custody path
//   unchanged: `recordSuccessfulAppSessionAuthentication(context:)` →
//   `AppSessionOrchestrator` handoff → Protected App-Data opening. The
//   embedded context is an app-session context and is NEVER routed into a
//   private-key operation (standing doctrine; see `AppSessionOrchestrator`).
// - Every evaluation failure normalizes into the EXISTING
//   `AppSessionAuthenticationFailureReason` states via the manager's app-
//   session error normalization — no new fallback machinery, no
//   error-specific branches (a hypothetical embedded-UI denial such as the
//   past macOS 27 beta -1007 return lands in the same retry/password branch).
//
// Method matrix (decided for #724; `AppSessionAuthenticationPolicy` is the
// App Access Protection policy — `.userPresence` = Standard,
// `.biometricsOnly` = High Security):
//
// - Biometrics can evaluate → the attempt runs the embedded BIOMETRIC
//   evaluation (`.deviceOwnerAuthenticationWithBiometrics` on the context the
//   embedded view displays). Standard mode additionally offers an explicit
//   secondary "Use Password…" action.
// - "Use Password…" (Standard only) runs a DETACHED `.deviceOwnerAuthentication`
//   system-sheet evaluation — exactly today's machinery (maintainer decision
//   in #724: no app-defined password, the system sheet stays the password
//   path). Requested mid-embedded-attempt it cancels the embedded evaluation
//   and continues the SAME attempt on the sheet; requested from a settled
//   state the surface starts a fresh attempt.
// - Biometrics cannot evaluate (no hardware / not enrolled / lockout) → the
//   attempt fails fast into the normalized failure states WITHOUT presenting
//   any system UI; the Standard-mode lock surface then composes the password
//   action as primary, High Security keeps the existing failure/retry
//   surface. The detached sheet is therefore presented ONLY on an explicit
//   user action — the auto-invoked attempt never pops a system modal.
//
// Auto-invoke decision (recorded for #724): the lock surface's existing
// auto-auth-on-appear (`handleForegroundActive`) DOES start the embedded
// evaluation — an attempt still starts automatically per lock/foreground
// return, preserving the shipped semantics; only the presentation moved
// in-window, where a pending prompt cannot steal focus or resign the app.
//
// Evaluation lifecycle (empirically load-bearing, from the #469 PoC and the
// #496 probe suite): the paired view must be mounted in a window BEFORE the
// context evaluates, so `evaluateAppSessionUnlock` publishes the context,
// awaits the lock surface's mount signal (`embeddedAuthenticationViewDidMount`),
// and only then evaluates. A pending mount wait is resolved by cancellation
// too, so an attempt can never hang un-cancellable.
//
// Cancellation: `cancelEmbeddedEvaluationIfInFlight()` invalidates the
// published context, failing a pending (or about-to-start) evaluation
// immediately. `AppLockController` calls it when a macOS app-resign arrives
// during an embedded attempt — the embedded prompt causes no resign, so that
// resign is a REAL app switch and processes as a genuine away — and on
// `lockNow` (screen lock / "Lock Now"), where the bumped away generation
// discards the attempt's result ("real background wins").
//
// The type compiles on every platform (it is a pure, closure-injected state
// machine) but is constructed on macOS only; UIKit-family containers leave
// their slot nil and keep the system-sheet presentation.
@Observable
@MainActor
final class AppSessionUnlockPresenter {
    /// Whether the embedded biometric method can currently evaluate, probed
    /// via `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`.
    enum EmbeddedBiometricsAvailability: Equatable {
        case available
        /// The probe failed with `.biometryLockout`.
        case lockedOut
        /// No usable biometrics (no hardware, not enrolled, or any other
        /// probe failure).
        case unavailable
    }

    // MARK: - Injected dependencies

    private let appSessionPolicy: @MainActor () -> AppSessionAuthenticationPolicy
    private let probeEmbeddedBiometricsAvailability: @MainActor () -> EmbeddedBiometricsAvailability
    private let makeEmbeddedContext: @MainActor () -> LAContext
    /// The embedded biometric app-session evaluation on a caller-supplied
    /// context (`AuthenticationManager.evaluateAppSessionWithEmbeddedBiometrics`).
    private let evaluateEmbeddedBiometrics: @MainActor (LAContext, String) async throws -> AppSessionAuthenticationResult
    /// The detached system-sheet password evaluation — today's
    /// `AuthenticationManager.evaluateAppSession(policy: .userPresence, …)`
    /// machinery, invoked only in Standard mode.
    private let evaluatePasswordWithSystemSheet: @MainActor (String) async throws -> AppSessionAuthenticationResult

    // MARK: - Presentation state (read by the lock surface)

    /// The context the lock surface's embedded biometric view displays for
    /// the in-flight attempt; nil while no embedded evaluation is presenting.
    /// This context IS the context evaluated — one context, existing custody.
    private(set) var presentedEmbeddedContext: LAContext?

    /// Availability snapshot for surface composition, refreshed at attempt
    /// start and end (a stale value self-corrects on the next attempt: the
    /// doomed retry fails fast and recomposes).
    private(set) var embeddedBiometricsAvailability: EmbeddedBiometricsAvailability

    /// Standard mode offers the explicit "Use Password…" action; High
    /// Security is biometric-only with no password affordance.
    var offersPasswordUnlock: Bool {
        appSessionPolicy() == .userPresence
    }

    /// When biometrics cannot evaluate, the Standard-mode lock surface
    /// composes the password action as PRIMARY (the biometric retry would
    /// fail fast and guide nowhere).
    var composesPasswordPrimary: Bool {
        offersPasswordUnlock && embeddedBiometricsAvailability != .available
    }

    // MARK: - Attempt-scoped state

    /// One-shot "Use Password…" request. Consumed by the attempt that honors
    /// it; cleared unconsumed at every attempt end so a click racing an
    /// attempt's completion can never leak into an unrelated later attempt.
    private var passwordUnlockRequested = false
    /// Mount handshake for the load-bearing evaluate-after-mount ordering.
    private var isEmbeddedViewMounted = false
    private var embeddedViewMountContinuation: CheckedContinuation<Void, Never>?

    init(
        appSessionPolicy: @escaping @MainActor () -> AppSessionAuthenticationPolicy,
        probeEmbeddedBiometricsAvailability: @escaping @MainActor () -> EmbeddedBiometricsAvailability,
        makeEmbeddedContext: @escaping @MainActor () -> LAContext = { LAContext() },
        evaluateEmbeddedBiometrics: @escaping @MainActor (LAContext, String) async throws -> AppSessionAuthenticationResult,
        evaluatePasswordWithSystemSheet: @escaping @MainActor (String) async throws -> AppSessionAuthenticationResult
    ) {
        self.appSessionPolicy = appSessionPolicy
        self.probeEmbeddedBiometricsAvailability = probeEmbeddedBiometricsAvailability
        self.makeEmbeddedContext = makeEmbeddedContext
        self.evaluateEmbeddedBiometrics = evaluateEmbeddedBiometrics
        self.evaluatePasswordWithSystemSheet = evaluatePasswordWithSystemSheet
        self.embeddedBiometricsAvailability = probeEmbeddedBiometricsAvailability()
    }

    // MARK: - The attempt driver (the controller's evaluate closure)

    /// Evaluate one app-session unlock attempt using the method matrix above.
    /// Called exclusively through `AppLockController`'s injected
    /// `evaluateAppSessionAuthentication` closure, which guarantees a single
    /// attempt in flight (`.authenticating` guards re-entry).
    func evaluateAppSessionUnlock(reason: String) async throws -> AppSessionAuthenticationResult {
        defer { finishAttempt() }
        embeddedBiometricsAvailability = probeEmbeddedBiometricsAvailability()

        // An explicit password request from a settled state (the surface
        // started this attempt for it) goes straight to the sheet.
        if consumePasswordUnlockRequest() {
            return try await evaluatePasswordWithSystemSheet(reason)
        }

        if embeddedBiometricsAvailability == .available {
            do {
                return try await runEmbeddedBiometricAttempt(reason: reason)
            } catch {
                // "Use Password…" pressed during the embedded prompt: the
                // cancellation above surfaced as this error; the SAME attempt
                // continues on the detached sheet. Any other failure (and a
                // password request outside Standard mode, which the surface
                // never offers) rethrows into the normal normalization.
                guard consumePasswordUnlockRequest(), offersPasswordUnlock else {
                    throw error
                }
                return try await evaluatePasswordWithSystemSheet(reason)
            }
        }

        // Biometrics cannot evaluate: fail fast with the EXISTING normalized
        // reasons and present no system UI — the surface composes
        // password-primary (Standard) or the failure/retry surface (High
        // Security); the detached sheet appears only on the explicit action.
        throw embeddedBiometricsAvailability == .lockedOut
            ? AuthenticationError.appAccessBiometricsLockedOut
            : AuthenticationError.appAccessBiometricsUnavailable
    }

    // MARK: - Surface actions

    /// The explicit "Use Password…" action (Standard mode only). During an
    /// embedded attempt this cancels the pending evaluation and the in-flight
    /// attempt continues on the detached sheet; from a settled state the
    /// surface follows up with `AppLockController.retryUnlock`, whose attempt
    /// consumes the request.
    func requestPasswordUnlock() {
        guard offersPasswordUnlock else {
            return
        }
        passwordUnlockRequested = true
        cancelEmbeddedEvaluationIfInFlight()
    }

    /// Invalidate the in-flight embedded evaluation, if any. Returns whether
    /// one was in flight — `AppLockController`'s macOS away rule keys on the
    /// result: an app-resign during an EMBEDDED attempt is a real app switch
    /// (the in-window prompt resigns nothing), so the controller cancels here
    /// and processes the away as genuine; a resign with no embedded attempt
    /// in flight keeps today's system-sheet swallow.
    @discardableResult
    func cancelEmbeddedEvaluationIfInFlight() -> Bool {
        guard let context = presentedEmbeddedContext else {
            return false
        }
        // Release a pending mount wait first so the attempt task reaches the
        // evaluation, which then fails immediately on the invalidated context.
        resumeEmbeddedViewMountWait()
        context.invalidate()
        return true
    }

    /// Mount signal from the lock surface's embedded view host: the paired
    /// view for `context` is in a window, so evaluation may begin.
    func embeddedAuthenticationViewDidMount(for context: LAContext) {
        guard context === presentedEmbeddedContext else {
            return
        }
        isEmbeddedViewMounted = true
        resumeEmbeddedViewMountWait()
    }

    // MARK: - Embedded attempt internals

    private func runEmbeddedBiometricAttempt(reason: String) async throws -> AppSessionAuthenticationResult {
        let context = makeEmbeddedContext()
        isEmbeddedViewMounted = false
        presentedEmbeddedContext = context
        defer { endEmbeddedPresentation() }
        await waitForEmbeddedViewMount()
        return try await evaluateEmbeddedBiometrics(context, reason)
    }

    private func waitForEmbeddedViewMount() async {
        if isEmbeddedViewMounted {
            return
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            embeddedViewMountContinuation = continuation
        }
    }

    private func resumeEmbeddedViewMountWait() {
        embeddedViewMountContinuation?.resume()
        embeddedViewMountContinuation = nil
    }

    private func endEmbeddedPresentation() {
        resumeEmbeddedViewMountWait()
        presentedEmbeddedContext = nil
        isEmbeddedViewMounted = false
    }

    private func consumePasswordUnlockRequest() -> Bool {
        defer { passwordUnlockRequested = false }
        return passwordUnlockRequested
    }

    private func finishAttempt() {
        passwordUnlockRequested = false
        embeddedBiometricsAvailability = probeEmbeddedBiometricsAvailability()
    }
}
