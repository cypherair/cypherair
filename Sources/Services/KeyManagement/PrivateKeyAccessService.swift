import Foundation

/// Owns Secure Enclave reconstruction and secret-certificate-material unwrap for callers.
final class PrivateKeyAccessService {
    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator
    private let traceStore: AuthLifecycleTraceStore?

    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
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
                // `loadBundle` above stays on-main: it is a plain Keychain read with no
                // biometric, so it does not block.
                let unwrapped = try await Self.reconstructAndUnwrapOffMainActor(
                    secureEnclave: secureEnclave,
                    bundle: bundle,
                    fingerprint: fingerprint,
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
        traceStore: AuthLifecycleTraceStore?
    ) async throws -> Data {
        traceStore?.record(category: .operation, name: "privateKey.unwrap.reconstruct.start")
        let handle: any SEKeyHandle
        do {
            handle = try secureEnclave.reconstructKey(from: bundle.seKeyData)
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
