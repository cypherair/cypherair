import Foundation
import LocalAuthentication

/// Pair-level lifecycle for Secure Enclave composite (post-quantum) handles,
/// mirroring `SecureEnclaveCustodyHandleStore` for the split-custody family:
/// create-with-rollback, authenticated load, non-prompting locate by the
/// certificate's component public keys, deletion, and local-data-reset cleanup.
struct SecureEnclaveCompositeHandleStore {
    private let keyStore: any SecureEnclaveCompositeKeyStoring
    private let handleSetIdentifierGenerator: () throws -> String

    init(
        keyStore: any SecureEnclaveCompositeKeyStoring,
        handleSetIdentifierGenerator: @escaping () throws -> String = {
            try SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier()
        }
    ) {
        self.keyStore = keyStore
        self.handleSetIdentifierGenerator = handleSetIdentifierGenerator
    }

    /// Create both Secure Enclave composite keys under the fixed device-bound
    /// access policy. Device-Bound Post-Quantum handles — like every
    /// device-bound handle — use `privateKeyUsageBiometryAny` regardless of the
    /// app authentication mode, so they are exempt from mode-switch re-wrap.
    func createLoadedHandlePair(
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandlePair {
        let handleSetIdentifier = try handleSetIdentifierGenerator()
        let signingReference = try SecureEnclaveCompositeHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing
        )
        let keyAgreementReference = try SecureEnclaveCompositeHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement
        )
        let policy = SecureEnclaveCustodyAccessControlPolicy.privateKeyUsageBiometryAny

        let signing = try keyStore.createKey(
            reference: signingReference,
            accessPolicy: policy,
            authenticationContext: authenticationContext
        )
        do {
            let keyAgreement = try keyStore.createKey(
                reference: keyAgreementReference,
                accessPolicy: policy,
                authenticationContext: authenticationContext
            )
            return try SecureEnclaveCompositeLoadedHandlePair(
                signing: signing,
                keyAgreement: keyAgreement
            )
        } catch {
            do {
                try deleteReferences([signingReference, keyAgreementReference])
            } catch {
                throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
            }
            throw error
        }
    }

    func loadHandle(
        reference: SecureEnclaveCompositeHandleReference,
        expectedPublicKeyRaw: Data,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandle {
        guard SecureEnclaveCompositeHandlePublicBinding.hasExpectedPublicKeyShape(
            expectedPublicKeyRaw,
            role: reference.role
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(reference.role)
        }

        guard let handle = try keyStore.loadKey(
            reference: reference,
            authenticationContext: authenticationContext
        ) else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
        }
        guard handle.binding.publicKeyRaw == expectedPublicKeyRaw else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(reference.role)
        }
        return handle
    }

    /// Locate the unique handle pair whose stored public bindings match the
    /// certificate's component public keys. Non-prompting: matches on the
    /// stored binding attributes only. A set matching one role but not the
    /// other fails closed as a binding mismatch, mirroring the P-256 store.
    func locateHandlePair(
        signingPublicKeyRaw: Data,
        keyAgreementPublicKeyRaw: Data
    ) throws -> SecureEnclaveCompositeHandlePair {
        guard SecureEnclaveCompositeHandlePublicBinding.hasExpectedPublicKeyShape(
            signingPublicKeyRaw,
            role: .signing
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(.signing)
        }
        guard SecureEnclaveCompositeHandlePublicBinding.hasExpectedPublicKeyShape(
            keyAgreementPublicKeyRaw,
            role: .keyAgreement
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(.keyAgreement)
        }

        let bindings = try keyStore.inventoryBindings()
        var grouped: [String: [SecureEnclaveCompositeHandlePublicBinding]] = [:]
        for binding in bindings {
            grouped[binding.reference.handleSetIdentifier, default: []].append(binding)
        }

        var matches: [SecureEnclaveCompositeHandlePair] = []
        for group in grouped.values {
            let signingBindings = group.filter { $0.reference.role == .signing }
            let keyAgreementBindings = group.filter { $0.reference.role == .keyAgreement }
            guard signingBindings.count <= 1 else {
                throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.signing)
            }
            guard keyAgreementBindings.count <= 1 else {
                throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.keyAgreement)
            }

            let signingMatches = signingBindings.first?.publicKeyRaw == signingPublicKeyRaw
            let keyAgreementMatches = keyAgreementBindings.first?.publicKeyRaw == keyAgreementPublicKeyRaw
            switch (signingMatches, keyAgreementMatches) {
            case (true, true):
                guard let signing = signingBindings.first,
                      let keyAgreement = keyAgreementBindings.first else {
                    throw SecureEnclaveCustodyHandleError.partialHandlePair
                }
                matches.append(try SecureEnclaveCompositeHandlePair(
                    signing: signing,
                    keyAgreement: keyAgreement
                ))
            case (true, false):
                throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
            case (false, true):
                throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.signing)
            case (false, false):
                continue
            }
        }

        guard !matches.isEmpty else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(.signing)
        }
        guard matches.count == 1 else {
            throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.signing)
        }
        return matches[0]
    }

    func deleteHandlePair(_ pair: SecureEnclaveCompositeHandlePair) throws {
        try deleteReferences(pair.references)
    }

    /// Delete whatever composite handles match the certificate's component
    /// public keys, tolerating already-missing and partial sets — the
    /// identity-deletion path must converge even after interrupted rollbacks.
    func deleteHandles(
        signingPublicKeyRaw: Data,
        keyAgreementPublicKeyRaw: Data
    ) throws {
        let bindings = try keyStore.inventoryBindings()
        let references = bindings
            .filter { binding in
                switch binding.reference.role {
                case .signing:
                    return binding.publicKeyRaw == signingPublicKeyRaw
                case .keyAgreement:
                    return binding.publicKeyRaw == keyAgreementPublicKeyRaw
                }
            }
            .map(\.reference)
        try deleteReferences(references)
    }

    func inventoryHandleCount() throws -> Int {
        try keyStore.inventoryBindings().count
    }

    func cleanupAllHandlesForLocalDataReset() -> SecureEnclaveCustodyHandleCleanupResult {
        let bindings: [SecureEnclaveCompositeHandlePublicBinding]
        do {
            bindings = try keyStore.inventoryBindings()
        } catch {
            return SecureEnclaveCustodyHandleCleanupResult(
                inspectedHandleCount: 0,
                deletedHandleCount: 0,
                failureCategory: .cleanupOrRollbackFailure
            )
        }

        var deletedCount = 0
        var cleanupFailed = false
        for binding in bindings {
            do {
                try keyStore.deleteKey(reference: binding.reference)
                deletedCount += 1
            } catch let error as SecureEnclaveCustodyHandleError where error.isMissing {
                continue
            } catch {
                cleanupFailed = true
            }
        }

        return SecureEnclaveCustodyHandleCleanupResult(
            inspectedHandleCount: bindings.count,
            deletedHandleCount: deletedCount,
            failureCategory: cleanupFailed ? .cleanupOrRollbackFailure : nil
        )
    }

    private func deleteReferences(_ references: [SecureEnclaveCompositeHandleReference]) throws {
        var cleanupFailed = false
        for reference in references {
            do {
                try keyStore.deleteKey(reference: reference)
            } catch let error as SecureEnclaveCustodyHandleError where error.isMissing {
                continue
            } catch {
                cleanupFailed = true
            }
        }
        if cleanupFailed {
            throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
        }
    }
}
