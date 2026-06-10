#if os(macOS)
import Foundation
import LocalAuthentication

/// macOS implementation of the in-window authentication seam (P3 of the
/// auth-lifecycle redesign; TARGET §4, validated by the P0 PoC `AuthPoCPresenter`).
///
/// It publishes the `LAContext` that should currently be rendered in-window;
/// the SwiftUI host (`authenticationPresentationHost`) observes `activePresentation`
/// and mounts an `LAAuthenticationView` paired with that context. The evaluation
/// runs only after the host signals the view's `NSView` is in the hierarchy
/// (`viewDidMount(_:)`) — `LAAuthenticationView` requires its paired view to exist
/// *before* the context evaluates, or the prompt never renders.
///
/// Because the prompt renders in-window, authentication does **not** post
/// `NSApplication.didResignActiveNotification`, which is what makes the macOS lock
/// model sound (TARGET §3).
///
/// Presentations are serialized first-in-first-out: at most one
/// `LAAuthenticationView` is mounted at a time; overlapping requests queue.
@MainActor
@Observable
final class MacAuthenticationPresenter {
    /// The presentation the host should currently render, or `nil` when idle.
    struct ActivePresentation: Identifiable {
        let id: Int
        let context: LAContext
        let request: AuthenticationPresentationRequest
    }

    private(set) var activePresentation: ActivePresentation?

    @ObservationIgnored private var isPresenting = false
    @ObservationIgnored private var waiters: [CheckedContinuation<Void, Never>] = []
    @ObservationIgnored private var readyContinuation: CheckedContinuation<Void, any Error>?
    @ObservationIgnored private var presentationCounter = 0

    init() {}

    // MARK: - Presentation core

    /// Mount an in-window authentication view for `context` for the duration of
    /// `body`, returning its result. Serializes so only one presentation is active
    /// at a time, and waits for the view-mount handshake before running `body`.
    ///
    /// Biometric reuse is disabled on the presented context: every presentation is
    /// exactly one fresh authentication (per-operation posture, TARGET §6).
    func present<T>(
        context: LAContext,
        request: AuthenticationPresentationRequest,
        perform body: () async throws -> T
    ) async throws -> T {
        await acquire()
        defer { release() }
        try Task.checkCancellation()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        presentationCounter += 1
        activePresentation = ActivePresentation(
            id: presentationCounter,
            context: context,
            request: request
        )
        defer {
            activePresentation = nil
            readyContinuation = nil
        }
        try await waitForViewMount()
        return try await body()
    }

    /// Called by the hosted `LAAuthenticationView` once its `NSView` is in the
    /// hierarchy. Guarded by id so a stale (unmounting) host cannot release the
    /// handshake for a newer presentation.
    func viewDidMount(_ id: Int) {
        guard activePresentation?.id == id else { return }
        readyContinuation?.resume()
        readyContinuation = nil
    }

    /// Cancel the active presentation (the card's Cancel button / Esc).
    /// Invalidating the context makes the in-flight `evaluatePolicy` /
    /// `evaluateAccessControl` fail with `LAError.appCancel`, which unwinds the
    /// caller's evaluation and tears the presentation down through `present`'s
    /// `defer`.
    func cancelActivePresentation() {
        activePresentation?.context.invalidate()
    }

    private func waitForViewMount() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                readyContinuation = continuation
            }
        } onCancel: {
            Task { @MainActor in
                self.readyContinuation?.resume(throwing: CancellationError())
                self.readyContinuation = nil
            }
        }
    }

    /// Hand-off mutex: `release()` passes ownership directly to the next waiter
    /// without clearing `isPresenting`, so a newly arriving caller cannot slip
    /// ahead of the queue. Queue waits are not cancellation points — ownership
    /// always arrives because every `present` releases in `defer`; a cancelled
    /// waiter then exits via the `checkCancellation` before mounting anything.
    private func acquire() async {
        if !isPresenting {
            isPresenting = true
            return
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
        }
    }

    private func release() {
        if waiters.isEmpty {
            isPresenting = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

// MARK: - AuthenticationPresenting

extension MacAuthenticationPresenter: AuthenticationPresenting {
    /// `nonisolated` so non-main callers (e.g. the per-operation private-key path)
    /// can reach the seam; the body hops to the main actor to drive the UI.
    /// `LAContext` is intentionally non-Sendable — the rebind below moves it across
    /// the hop without copying; the caller retains ownership after return (the same
    /// pattern `AuthenticationManager` uses for its `LAContext` reply callbacks).
    nonisolated func presentingEvaluation<T: Sendable>(
        context: LAContext,
        request: AuthenticationPresentationRequest,
        _ evaluation: @Sendable @escaping (LAContext) async throws -> T
    ) async throws -> T {
        nonisolated(unsafe) let context = context
        return try await present(context: context, request: request) {
            try await evaluation(context)
        }
    }
}
#endif
