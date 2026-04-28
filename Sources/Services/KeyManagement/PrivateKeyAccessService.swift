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
                let unwrapped: Data
                do {
                    unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
                    traceStore?.record(
                        category: .operation,
                        name: "privateKey.unwrap.seUnwrap.call.finish",
                        metadata: ["result": "success"]
                    )
                } catch {
                    traceStore?.record(
                        category: .operation,
                        name: "privateKey.unwrap.seUnwrap.call.finish",
                        metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failure"])
                    )
                    throw error
                }

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
}
