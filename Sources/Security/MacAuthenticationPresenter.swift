#if os(macOS)
import Foundation
import LocalAuthentication

/// macOS implementation of the in-window authentication seam (P3 of the auth-lifecycle
/// redesign; see AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md §4 and the validated PoC
/// `AuthPoCPresenter`). It publishes the `LAContext` that should currently be rendered
/// in-window; a SwiftUI host (`authenticationPresentationHost`) observes
/// `activePresentation` and mounts an `LAAuthenticationView` for it. The evaluation runs
/// only after the view's `NSView` is in the hierarchy (`viewDidMount()`), because
/// `LAAuthenticationView` requires its paired view to exist before the context evaluates.
///
/// Because the prompt renders in-window, authentication does **not** post
/// `NSApplication.didResignActiveNotification` — which is what makes the macOS lock
/// model sound (TARGET §3).
///
/// Presentations are serialized: at most one `LAAuthenticationView` is mounted at a time;
/// overlapping requests queue first-in-first-out.
///
/// PR-1 introduces this **dormant**: no production caller routes through it yet (the
/// per-surface wiring lands in later P3 PRs). The `present(context:request:perform:)`
/// core is exercised by unit tests; the `nonisolated` seam entry points drive real
/// LocalAuthentication and are validated on device.
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
    @ObservationIgnored private var readyContinuation: CheckedContinuation<Void, Never>?
    @ObservationIgnored private var presentationCounter = 0

    init() {}

    // MARK: - Presentation core (testable; no LocalAuthentication side effects)

    /// Mount an in-window auth view for `context` for the duration of `body`, returning
    /// its result. Serializes so only one presentation is active at a time, and waits for
    /// the view-mount handshake (`viewDidMount()`) before running `body`.
    func present<T>(
        context: LAContext,
        request: AuthenticationPresentationRequest,
        perform body: () async throws -> T
    ) async rethrows -> T {
        await acquire()
        presentationCounter += 1
        activePresentation = ActivePresentation(id: presentationCounter, context: context, request: request)
        defer {
            activePresentation = nil
            readyContinuation = nil
            release()
        }
        await waitForViewMount()
        return try await body()
    }

    /// Called by the hosted `LAAuthenticationView` once its `NSView` is in the hierarchy
    /// (or by tests to drive the handshake).
    func viewDidMount() {
        readyContinuation?.resume()
        readyContinuation = nil
    }

    private func waitForViewMount() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            readyContinuation = continuation
        }
    }

    /// Hand-off mutex: `release()` passes ownership directly to the next waiter without
    /// clearing `isPresenting`, so a newly arriving caller cannot slip ahead of the queue.
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
    nonisolated func evaluatePolicyInWindow(
        _ context: LAContext,
        policy: LAPolicy,
        localizedReason: String,
        reply: @escaping @Sendable (Bool, Error?) -> Void
    ) {
        nonisolated(unsafe) let context = context
        Task { @MainActor in
            await self.present(
                context: context,
                request: AuthenticationPresentationRequest(
                    localizedReason: localizedReason,
                    purpose: .appSessionUnlock,
                    source: "appSessionUnlock"
                )
            ) {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    context.evaluatePolicy(policy, localizedReason: localizedReason) { success, error in
                        reply(success, error)
                        continuation.resume()
                    }
                }
            }
        }
    }

    nonisolated func authorizeAccessControlInWindow(
        _ context: LAContext,
        accessControl: SecAccessControl,
        operation: LAAccessControlOperation,
        localizedReason: String,
        purpose: AuthenticationPresentationPurpose,
        reply: @escaping @Sendable (Bool, Error?) -> Void
    ) {
        nonisolated(unsafe) let context = context
        nonisolated(unsafe) let accessControl = accessControl
        Task { @MainActor in
            do {
                try await self.present(
                    context: context,
                    request: AuthenticationPresentationRequest(
                        localizedReason: localizedReason,
                        purpose: purpose,
                        source: "perOperation"
                    )
                ) {
                    _ = try await context.evaluateAccessControl(
                        accessControl,
                        operation: operation,
                        localizedReason: localizedReason
                    )
                }
                reply(true, nil)
            } catch {
                reply(false, error)
            }
        }
    }
}
#endif
