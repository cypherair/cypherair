import Foundation
import LocalAuthentication

/// Owns Secure Enclave reconstruction and secret-certificate-material unwrap for callers.
final class PrivateKeyAccessService {
    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let authenticationPresenter: (any AuthenticationPresenting)?
    private let privateKeyControlStore: (any PrivateKeyControlStoreProtocol)?
    private let traceStore: AuthLifecycleTraceStore?

    /// `authenticationPresenter` + `privateKeyControlStore` enable the macOS
    /// in-window per-operation authentication route (P3). When either is absent
    /// (iOS/visionOS code path, UI-test container, direct test construction), the
    /// Secure Enclave authenticates implicitly via the system prompt as before.
    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        authenticationPresenter: (any AuthenticationPresenting)? = nil,
        privateKeyControlStore: (any PrivateKeyControlStoreProtocol)? = nil,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
        self.authenticationPresenter = authenticationPresenter
        self.privateKeyControlStore = privateKeyControlStore
        self.traceStore = traceStore
    }

    /// Triggers device authentication and returns the unwrapped secret certificate material.
    /// Callers must zeroize the returned data after use.
    func unwrapPrivateKey(fingerprint: String) async throws -> Data {
        traceStore?.record(category: .operation, name: "privateKey.unwrap.start")
        do {
            let unwrapped = try await authenticationPromptCoordinator.withOperationPrompt(source: "privateKey.unwrap") {
                traceStore?.record(category: .operation, name: "privateKey.unwrap.bundle.load.start")
                let bundle: WrappedKeyBundle
                do {
                    bundle = try bundleStore.loadBundle(fingerprint: fingerprint)
                    traceStore?.record(
                        category: .operation,
                        name: "privateKey.unwrap.bundle.load.finish",
                        metadata: ["result": "success"]
                    )
                } catch {
                    traceStore?.record(
                        category: .operation,
                        name: "privateKey.unwrap.bundle.load.finish",
                        metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failure"])
                    )
                    throw error
                }

                #if os(macOS)
                // P3: authenticate the operation in-window FIRST, then thread the
                // authenticated context into the Secure Enclave reconstruction so it
                // consumes the session with no second prompt (PoC findings Item 2).
                let presentedContext = try await presentInWindowOperationAuthenticationIfWired()
                #else
                // iOS / iPadOS / visionOS: nil context — the Secure Enclave
                // reconstruction triggers the system prompt exactly as today.
                let presentedContext: LAContext? = nil
                #endif
                defer { presentedContext?.invalidate() }

                // Reconstruct + unwrap run OFF the main actor. `reconstructKey` is a
                // SYNCHRONOUS, blocking Secure Enclave biometric; if it ran on the main
                // actor it would block the main thread, so the `.inactive`/`.active`
                // scene transitions the biometric sheet causes would only be delivered
                // AFTER `endOperationPrompt` reset the operation-prompt depth to 0. The
                // app-session lifecycle gate would then never observe the operation
                // in-progress and would mistake the transient blip for a real app
                // backgrounding — under grace period "Immediately" (0) that clears
                // content and shows a spurious second prompt. Running it off-main frees
                // the main actor so `.inactive` is observed while the operation-prompt
                // depth is still > 0, letting the existing gate suppression engage.
                // (On macOS the in-window prompt has already completed by this point;
                // staying off-main keeps the main actor free during the SE call.)
                // `loadBundle` above stays on-main: it is a plain Keychain read with no
                // biometric, so it does not block.
                let unwrapped = try await Self.reconstructAndUnwrapOffMainActor(
                    secureEnclave: secureEnclave,
                    bundle: bundle,
                    fingerprint: fingerprint,
                    authenticationContext: AuthenticationContextCarrier(context: presentedContext),
                    traceStore: traceStore
                )
                traceStore?.record(
                    category: .operation,
                    name: "privateKey.unwrap.closure.return",
                    metadata: ["result": "success"]
                )
                return unwrapped
            }
            traceStore?.record(category: .operation, name: "privateKey.unwrap.finish", metadata: ["result": "success"])
            return unwrapped
        } catch {
            traceStore?.record(
                category: .operation,
                name: "privateKey.unwrap.finish",
                metadata: ["result": "failure", "errorType": String(describing: type(of: error))]
            )
            throw error
        }
    }

    #if os(macOS)
    /// Present the per-operation in-window authentication (P3) and return the
    /// authenticated context, or `nil` when the route is not wired (UI-test
    /// container, direct test construction) — in which case the Secure Enclave
    /// authenticates implicitly as before.
    ///
    /// The evaluation is `evaluateAccessControl(.useKeyKeyExchange)` against the
    /// **persisted-mode** access control: the biometric-gated SE operation is the
    /// wrapping key's self-ECDH regardless of the OpenPGP operation, and a
    /// biometric evaluation satisfies both the Standard OR-gate and the
    /// High Security flag set (PoC findings Item 2; plan O3/O4).
    private func presentInWindowOperationAuthenticationIfWired() async throws -> LAContext? {
        guard let authenticationPresenter, let privateKeyControlStore else {
            return nil
        }
        traceStore?.record(category: .operation, name: "privateKey.unwrap.inWindowAuth.start")
        do {
            let mode = try privateKeyControlStore.requireUnlockedAuthMode()
            let accessControl = try mode.createAccessControl()
            let reason = String(
                localized: "auth.privateKey.operation.reason",
                defaultValue: "Authenticate with Touch ID to use your private key."
            )
            let context = LAContext()
            // SecAccessControl is not Sendable; the rebind moves it into the
            // evaluation closure without copying (single read, no shared mutation).
            nonisolated(unsafe) let evaluatedAccessControl = accessControl
            let success = try await authenticationPresenter.presentingEvaluation(
                context: context,
                request: AuthenticationPresentationRequest(
                    localizedReason: reason,
                    purpose: .perOperation,
                    source: "privateKey.unwrap"
                )
            ) { context in
                try await context.evaluateAccessControl(
                    evaluatedAccessControl,
                    operation: .useKeyKeyExchange,
                    localizedReason: reason
                )
            }
            guard success else {
                throw AuthenticationError.failed
            }
            traceStore?.record(
                category: .operation,
                name: "privateKey.unwrap.inWindowAuth.finish",
                metadata: ["result": "success"]
            )
            return context
        } catch {
            traceStore?.record(
                category: .operation,
                name: "privateKey.unwrap.inWindowAuth.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failure"])
            )
            throw error
        }
    }
    #endif

    /// Moves an optional presenter-authenticated `LAContext` into the off-main
    /// Secure Enclave reconstruction. `LAContext` is intentionally non-Sendable;
    /// this carrier crosses the actor boundary without copying, the context is
    /// consumed by exactly one SE operation, and the caller invalidates it after
    /// the operation returns (the same pattern `AuthenticationManager` uses for
    /// its `LAContext` reply callbacks).
    private struct AuthenticationContextCarrier: @unchecked Sendable {
        let context: LAContext?
    }

    /// Performs the Secure Enclave reconstruct + unwrap off the main actor.
    ///
    /// `@concurrent` hops this work to the cooperative pool so the synchronous,
    /// blocking biometric inside `reconstructKey` does not stall the main actor — see
    /// the rationale in `unwrapPrivateKey`. The `SEKeyHandle` is created and consumed
    /// here so it never crosses the actor boundary; only `Sendable` `Data` crosses.
    /// The returned bytes are secret-certificate material and must be zeroized by the
    /// caller (unchanged from the in-line implementation).
    @concurrent
    private static func reconstructAndUnwrapOffMainActor(
        secureEnclave: any SecureEnclaveManageable,
        bundle: WrappedKeyBundle,
        fingerprint: String,
        authenticationContext: AuthenticationContextCarrier,
        traceStore: AuthLifecycleTraceStore?
    ) async throws -> Data {
        traceStore?.record(category: .operation, name: "privateKey.unwrap.reconstruct.start")
        let handle: any SEKeyHandle
        do {
            handle = try secureEnclave.reconstructKey(
                from: bundle.seKeyData,
                authenticationContext: authenticationContext.context
            )
            traceStore?.record(
                category: .operation,
                name: "privateKey.unwrap.reconstruct.finish",
                metadata: ["result": "success"]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "privateKey.unwrap.reconstruct.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failure"])
            )
            throw error
        }

        traceStore?.record(category: .operation, name: "privateKey.unwrap.seUnwrap.call.start")
        do {
            let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
            traceStore?.record(
                category: .operation,
                name: "privateKey.unwrap.seUnwrap.call.finish",
                metadata: ["result": "success"]
            )
            return unwrapped
        } catch {
            traceStore?.record(
                category: .operation,
                name: "privateKey.unwrap.seUnwrap.call.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failure"])
            )
            throw error
        }
    }
}
