import Foundation
import LocalAuthentication
import Security

final class PrivateKeyRewrapWorkflow {
    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator

    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
    }

    /// Re-wrap every listed key into the target mode, journal first.
    ///
    /// - Parameter authenticationContext: The caller's authenticated context,
    ///   reused across every key so one authentication covers the whole switch.
    ///   `nil` leaves each Secure Enclave operation to authenticate implicitly.
    ///   Ownership stays with the caller, which invalidates it when the switch
    ///   ends — this workflow never retains it.
    func run(
        targetMode: AuthenticationMode,
        fingerprints: [String],
        authenticationContext: LAContext?,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) async throws {
        // Step 1: Write protected rewrap journal before any Keychain modifications.
        try privateKeyControlStore.beginRewrap(targetMode: targetMode)

        try await runPhaseA(
            targetMode: targetMode,
            fingerprints: fingerprints,
            authenticationContext: authenticationContext,
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
        authenticationContext: LAContext?,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) async throws {
        // Phase A: Create all pending items. If anything fails here, old items
        // are intact, so pending artifacts can be cleaned up.
        do {
            let newAccessControl = try targetMode.createAccessControl()

            for fingerprint in fingerprints {
                let existingBundle = try bundleStore.loadBundle(fingerprint: fingerprint)
                let newBundle = try await rewrapBundleForModeSwitch(
                    existingBundle: existingBundle,
                    fingerprint: fingerprint,
                    newAccessControl: newAccessControl,
                    authenticationContext: authenticationContext
                )

                try bundleStore.saveBundle(
                    newBundle,
                    fingerprint: fingerprint,
                    namespace: .pending
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
        } catch {
            fingerprints.forEach { bundleStore.cleanupPendingBundle(fingerprint: $0) }
            try? privateKeyControlStore.clearRewrapJournal()
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }
    }

    /// SECURITY-CRITICAL: every envelope this workflow opens and re-seals is
    /// pinned to `.softwareSecretCertificate`. Device-bound custody state is
    /// exempt from mode switching (docs/CUSTODY.md §2) and the exemption does
    /// not rest on the caller's fingerprint filter alone: a split-custody
    /// classical component is sealed as a different payload kind, so it is
    /// rejected by contract validation here — before any Secure Enclave call —
    /// and would fail the AEAD even if that check were bypassed.
    private func rewrapBundleForModeSwitch(
        existingBundle: WrappedKeyBundle,
        fingerprint: String,
        newAccessControl: SecAccessControl,
        authenticationContext: LAContext?
    ) async throws -> WrappedKeyBundle {
        try await authenticationPromptCoordinator.withOperationPrompt {
            let existingSeKeyData = try PrivateKeyEnvelopeCodec.seKeyData(
                from: existingBundle.envelope,
                expectedFingerprint: fingerprint,
                expectedPayloadKind: .softwareSecretCertificate
            )
            let existingHandle = try secureEnclave.reconstructKey(
                from: existingSeKeyData,
                authenticationContext: authenticationContext
            )

            let rawKeyBytes = try secureEnclave.unwrap(
                bundle: existingBundle,
                using: existingHandle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            )

            let newHandle = try secureEnclave.generateWrappingKey(
                accessControl: newAccessControl,
                authenticationContext: authenticationContext
            )
            return try secureEnclave.wrap(
                privateKey: rawKeyBytes,
                using: newHandle,
                fingerprint: fingerprint,
                payloadKind: .softwareSecretCertificate
            )
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
            for fingerprint in fingerprints {
                try bundleStore.deleteBundle(fingerprint: fingerprint)
            }

            for fingerprint in fingerprints {
                try bundleStore.promotePendingToPermanent(fingerprint: fingerprint)
            }

            try privateKeyControlStore.completeRewrap(targetMode: targetMode)
        } catch {
            throw AuthenticationError.modeSwitchFailed(underlying: error)
        }
    }
}
