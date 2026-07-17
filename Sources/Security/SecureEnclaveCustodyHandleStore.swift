import Foundation
import LocalAuthentication

/// Pair-level lifecycle for Secure Enclave custody handles, scoped to one tier:
/// create-with-rollback, authenticated load, non-prompting locate and inspect by
/// the certificate's public keys, and converging deletion. The maintenance
/// surface (inventory summary, local-data-reset cleanup) is deliberately
/// tier-independent: it sweeps every device-bound custody row so reset and
/// recovery never depend on which tier instance performs them.
///
/// `loadHandle` reconstructs the private blob and belongs inside an authorized
/// operation window; every other member works on stored bindings only and
/// never prompts.
struct SecureEnclaveCustodyHandleStore {
    private let keyStore: any SecureEnclaveCustodyKeyStoring
    private let tier: SecureEnclaveCustodyTier
    private let handleSetIdentifierGenerator: () throws -> String

    init(
        keyStore: any SecureEnclaveCustodyKeyStoring,
        tier: SecureEnclaveCustodyTier,
        handleSetIdentifierGenerator: @escaping () throws -> String = {
            try SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier()
        }
    ) {
        self.keyStore = keyStore
        self.tier = tier
        self.handleSetIdentifierGenerator = handleSetIdentifierGenerator
    }

    /// Create both Secure Enclave keys under the fixed device-bound access
    /// policy. Device-bound handles use `privateKeyUsageBiometryAny` regardless
    /// of the app authentication mode, so they are exempt from mode-switch
    /// re-wrap.
    func createLoadedHandlePair(
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandlePair {
        let handleSetIdentifier = try handleSetIdentifierGenerator()
        let signingReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing,
            tier: tier
        )
        let keyAgreementReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement,
            tier: tier
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
            return try SecureEnclaveCustodyLoadedHandlePair(
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
        reference: SecureEnclaveCustodyHandleReference,
        expectedPublicKeyRaw: Data,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        guard SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            expectedPublicKeyRaw,
            role: reference.role,
            tier: reference.tier
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
    /// certificate's public keys. Non-prompting: matches on the stored binding
    /// attributes only. A set matching one role but not the other fails closed
    /// as a binding mismatch; a partial set matching its present role surfaces
    /// as `partialHandlePair` so recovery can classify interrupted generation.
    func locateHandlePair(
        signingPublicKeyRaw: Data,
        keyAgreementPublicKeyRaw: Data
    ) throws -> SecureEnclaveCustodyHandlePair {
        guard SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            signingPublicKeyRaw,
            role: .signing,
            tier: tier
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(.signing)
        }
        guard SecureEnclaveCustodyHandlePublicBinding.hasExpectedPublicKeyShape(
            keyAgreementPublicKeyRaw,
            role: .keyAgreement,
            tier: tier
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(.keyAgreement)
        }

        var matches: [SecureEnclaveCustodyHandlePair] = []
        for group in try tierGroups().values {
            let signingBinding = group.first { $0.role == .signing }
            let keyAgreementBinding = group.first { $0.role == .keyAgreement }

            switch (signingBinding, keyAgreementBinding) {
            case (.some(let signing), .some(let keyAgreement)):
                let signingMatches = signing.publicKeyRaw == signingPublicKeyRaw
                let keyAgreementMatches = keyAgreement.publicKeyRaw == keyAgreementPublicKeyRaw
                switch (signingMatches, keyAgreementMatches) {
                case (true, true):
                    matches.append(try SecureEnclaveCustodyHandlePair(
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
            case (.some(let signing), nil):
                if signing.publicKeyRaw == signingPublicKeyRaw {
                    throw SecureEnclaveCustodyHandleError.partialHandlePair
                }
            case (nil, .some(let keyAgreement)):
                if keyAgreement.publicKeyRaw == keyAgreementPublicKeyRaw {
                    throw SecureEnclaveCustodyHandleError.partialHandlePair
                }
            case (nil, nil):
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

    func deleteHandlePair(_ pair: SecureEnclaveCustodyHandlePair) throws {
        try deleteReferences(pair.references)
    }

    /// Delete whatever handles match the certificate's public keys, tolerating
    /// already-missing and partial sets — the identity-deletion path must
    /// converge even after interrupted rollbacks. Tier-independent: matches raw
    /// public-key bytes across the full inventory (tier key shapes are
    /// disjoint), so one store instance converges deletion for any tier.
    func deleteHandles(
        signingPublicKeyRaw: Data,
        keyAgreementPublicKeyRaw: Data
    ) throws {
        let references = try keyStore.inventory().bindings
            .filter { binding in
                switch binding.role {
                case .signing:
                    return binding.publicKeyRaw == signingPublicKeyRaw
                case .keyAgreement:
                    return binding.publicKeyRaw == keyAgreementPublicKeyRaw
                }
            }
            .map(\.reference)
        try deleteReferences(references)
    }

    /// Cross-tier: counts every stored custody handle row for the local
    /// recovery report, so handle-only orphans (from interrupted or partial
    /// generation) surface regardless of tier.
    func inventorySummaryForLocalRecovery() throws -> SecureEnclaveCustodyHandleInventorySummary {
        let inventory = try keyStore.inventory()
        guard inventory.totalRowCount > 0 else {
            return .empty
        }

        var grouped: [String: [SecureEnclaveCustodyHandlePublicBinding]] = [:]
        for binding in inventory.bindings {
            grouped["\(binding.reference.tier.rawValue).\(binding.reference.handleSetIdentifier)", default: []]
                .append(binding)
        }

        var completeCount = 0
        var partialCount = 0
        for group in grouped.values {
            let hasSigning = group.contains { $0.role == .signing }
            let hasKeyAgreement = group.contains { $0.role == .keyAgreement }
            if hasSigning && hasKeyAgreement {
                completeCount += 1
            } else {
                partialCount += 1
            }
        }

        return SecureEnclaveCustodyHandleInventorySummary(
            totalHandleCount: inventory.totalRowCount,
            completeSetCount: completeCount,
            partialSetCount: partialCount,
            malformedHandleCount: inventory.malformedRowCount
        )
    }

    /// Cross-tier: removes every device-bound custody row, including rows whose
    /// attributes no longer decode, via per-namespace sweeps.
    func cleanupAllHandlesForLocalDataReset() -> SecureEnclaveCustodyHandleCleanupResult {
        let inspectedCount: Int
        do {
            inspectedCount = try keyStore.inventory().totalRowCount
        } catch {
            return SecureEnclaveCustodyHandleCleanupResult(
                inspectedHandleCount: 0,
                deletedHandleCount: 0,
                failureCategory: .cleanupOrRollbackFailure
            )
        }

        var cleanupFailed = false
        for tier in SecureEnclaveCustodyTier.allCases {
            for role in [PGPPrivateOperationRole.signing, .keyAgreement] {
                do {
                    try keyStore.deleteAllKeys(tier: tier, role: role)
                } catch {
                    cleanupFailed = true
                }
            }
        }

        // The deleted count is inferred from a verification re-read; if that
        // read fails, no deletions are verifiable, so report zero and a
        // failure instead of inferring success from an unreadable store.
        let remainingCount: Int
        do {
            remainingCount = try keyStore.inventory().totalRowCount
        } catch {
            return SecureEnclaveCustodyHandleCleanupResult(
                inspectedHandleCount: inspectedCount,
                deletedHandleCount: 0,
                failureCategory: .cleanupOrRollbackFailure
            )
        }
        return SecureEnclaveCustodyHandleCleanupResult(
            inspectedHandleCount: inspectedCount,
            deletedHandleCount: max(0, inspectedCount - remainingCount),
            failureCategory: cleanupFailed ? .cleanupOrRollbackFailure : nil
        )
    }

    /// Cross-tier: rows still present after a reset cleanup, for verification.
    func remainingHandleCountForLocalDataReset() throws -> Int {
        try keyStore.inventory().totalRowCount
    }

    private func tierBindings() throws -> [SecureEnclaveCustodyHandlePublicBinding] {
        try keyStore.inventory().bindings.filter { $0.reference.tier == tier }
    }

    private func tierGroups() throws -> [String: [SecureEnclaveCustodyHandlePublicBinding]] {
        var grouped: [String: [SecureEnclaveCustodyHandlePublicBinding]] = [:]
        for binding in try tierBindings() {
            grouped[binding.reference.handleSetIdentifier, default: []].append(binding)
        }
        return grouped
    }

    private func deleteReferences(_ references: [SecureEnclaveCustodyHandleReference]) throws {
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
