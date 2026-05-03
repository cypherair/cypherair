import Foundation
import LocalAuthentication

final class PrivateKeyRewrapWorkflow {
    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore
    private let traceStore: AuthLifecycleTraceStore?

    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
        self.traceStore = traceStore
    }

    func run(
        targetMode: AuthenticationMode,
        fingerprints: [String],
        authenticator: any AuthenticationEvaluable,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) throws {
        // Step 1: Write protected rewrap journal before any Keychain modifications.
        try privateKeyControlStore.beginRewrap(targetMode: targetMode)

        try runPhaseA(
            targetMode: targetMode,
            fingerprints: fingerprints,
            authenticator: authenticator,
            privateKeyControlStore: privateKeyControlStore
        )
        try runPhaseB(
            targetMode: targetMode,
            fingerprints: fingerprints,
            privateKeyControlStore: privateKeyControlStore
        )
    }

    private func runPhaseA(
        targetMode: AuthenticationMode,
        fingerprints: [String],
        authenticator: any AuthenticationEvaluable,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) throws {
        // Phase A: Create all pending items. If anything fails here, old items
        // are intact, so pending artifacts can be cleaned up.
        do {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseA.start",
                metadata: ["keyCount": String(fingerprints.count), "targetMode": targetMode.rawValue]
            )
            let newAccessControl = try targetMode.createAccessControl()

            for (index, fingerprint) in fingerprints.enumerated() {
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseA.key.start",
                    metadata: ["index": String(index), "keyCount": String(fingerprints.count)]
                )
                let existingBundle = try bundleStore.loadBundle(fingerprint: fingerprint)
                let existingHandle = try secureEnclave.reconstructKey(
                    from: existingBundle.seKeyData,
                    authenticationContext: authenticator.lastEvaluatedContext
                )

                var rawKeyBytes = try secureEnclave.unwrap(
                    bundle: existingBundle,
                    using: existingHandle,
                    fingerprint: fingerprint
                )

                defer {
                    rawKeyBytes.resetBytes(in: rawKeyBytes.startIndex..<rawKeyBytes.endIndex)
                }

                let newHandle = try secureEnclave.generateWrappingKey(
                    accessControl: newAccessControl,
                    authenticationContext: authenticator.lastEvaluatedContext
                )
                let newBundle = try secureEnclave.wrap(
                    privateKey: rawKeyBytes,
                    using: newHandle,
                    fingerprint: fingerprint
                )

                try bundleStore.saveBundle(
                    newBundle,
                    fingerprint: fingerprint,
                    namespace: .pending
                )
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseA.key.finish",
                    metadata: ["index": String(index), "result": "success"]
                )
            }

            for fingerprint in fingerprints {
                _ = try bundleStore.loadBundle(
                    fingerprint: fingerprint,
                    namespace: .pending
                )
            }

            // From this point forward Phase B may delete permanent items, so the
            // target mode must survive even if the final protected write fails.
            try privateKeyControlStore.markRewrapCommitRequired()
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseA.finish",
                metadata: ["result": "success", "keyCount": String(fingerprints.count)]
            )
        } catch {
            fingerprints.forEach { bundleStore.cleanupPendingBundle(fingerprint: $0) }
            try? privateKeyControlStore.clearRewrapJournal()
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseA.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed"])
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "phaseAFailed"])
            )
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }
    }

    private func runPhaseB(
        targetMode: AuthenticationMode,
        fingerprints: [String],
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) throws {
        // Phase B may delete permanent items. If it fails, pending items must be
        // preserved so interrupted-rewrap recovery can finish or fail closed.
        do {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseB.start",
                metadata: ["keyCount": String(fingerprints.count), "targetMode": targetMode.rawValue]
            )
            for (index, fingerprint) in fingerprints.enumerated() {
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseB.delete.start",
                    metadata: ["index": String(index)]
                )
                try bundleStore.deleteBundle(fingerprint: fingerprint)
            }

            for (index, fingerprint) in fingerprints.enumerated() {
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseB.promote.start",
                    metadata: ["index": String(index)]
                )
                try bundleStore.promotePendingToPermanent(
                    fingerprint: fingerprint,
                    seKeyAccessControl: nil
                )
                traceStore?.record(
                    category: .operation,
                    name: "privateKeyProtection.switch.phaseB.promote.finish",
                    metadata: ["index": String(index), "result": "success"]
                )
            }

            try privateKeyControlStore.completeRewrap(targetMode: targetMode)
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseB.finish",
                metadata: ["result": "success", "keyCount": String(fingerprints.count)]
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: ["result": "success", "targetMode": targetMode.rawValue]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.phaseB.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "failed"])
            )
            traceStore?.record(
                category: .operation,
                name: "privateKeyProtection.switch.finish",
                metadata: traceErrorMetadata(error, extra: ["result": "phaseBFailed"])
            )
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }
    }

    private func traceErrorMetadata(
        _ error: Error,
        extra: [String: String] = [:]
    ) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
    }
}
