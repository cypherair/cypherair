import Foundation
import LocalAuthentication

struct SecureEnclaveCustodyHandleStore {
    private let keyStore: any SecureEnclaveCustodyKeyStoring
    private let handleSetIdentifierGenerator: () throws -> String

    init(
        keyStore: any SecureEnclaveCustodyKeyStoring,
        handleSetIdentifierGenerator: @escaping () throws -> String = {
            try SecureEnclaveCustodyHandleReference.generateHandleSetIdentifier()
        }
    ) {
        self.keyStore = keyStore
        self.handleSetIdentifierGenerator = handleSetIdentifierGenerator
    }

    func createHandlePair() throws -> SecureEnclaveCustodyHandlePair {
        let handleSetIdentifier = try handleSetIdentifierGenerator()
        let signingReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .signing
        )
        let keyAgreementReference = try SecureEnclaveCustodyHandleReference(
            handleSetIdentifier: handleSetIdentifier,
            role: .keyAgreement
        )
        let policy = SecureEnclaveCustodyAccessControlPolicy.privateKeyUsageBiometryAny

        let signing = try keyStore.createKey(
            reference: signingReference,
            accessPolicy: policy
        )
        do {
            let keyAgreement = try keyStore.createKey(
                reference: keyAgreementReference,
                accessPolicy: policy
            )
            return try SecureEnclaveCustodyHandlePair(
                signing: signing.binding,
                keyAgreement: keyAgreement.binding
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

    func loadHandlePair(
        expected pair: SecureEnclaveCustodyHandlePair,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandlePair {
        let signing = try loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyX963: pair.signing.publicKeyX963,
            authenticationContext: authenticationContext
        )
        let keyAgreement = try loadHandle(
            reference: pair.keyAgreement.reference,
            expectedPublicKeyX963: pair.keyAgreement.publicKeyX963,
            authenticationContext: authenticationContext
        )
        return try SecureEnclaveCustodyLoadedHandlePair(
            signing: signing,
            keyAgreement: keyAgreement
        )
    }

    func loadHandle(
        reference: SecureEnclaveCustodyHandleReference,
        expectedPublicKeyX963: Data,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        guard SecureEnclaveCustodyHandlePublicBinding.hasUncompressedP256X963PublicKeyShape(expectedPublicKeyX963) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(reference.role)
        }

        let candidates = try keyStore.loadKeys(
            reference: reference,
            authenticationContext: authenticationContext
        )
        guard !candidates.isEmpty else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
        }
        guard candidates.count == 1 else {
            throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(reference.role)
        }

        let candidate = candidates[0]
        guard candidate.reference == reference else {
            if candidate.role != reference.role {
                throw SecureEnclaveCustodyHandleError.privateOperationRoleMismatch(
                    expected: reference.role,
                    actual: candidate.role
                )
            }
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
        }
        guard candidate.binding.publicKeyX963 == expectedPublicKeyX963 else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(reference.role)
        }

        return candidate
    }

    func inspectHandlePair(handleSetIdentifier: String) -> SecureEnclaveCustodyHandleState {
        let signingReference: SecureEnclaveCustodyHandleReference
        let keyAgreementReference: SecureEnclaveCustodyHandleReference
        do {
            signingReference = try SecureEnclaveCustodyHandleReference(
                handleSetIdentifier: handleSetIdentifier,
                role: .signing
            )
            keyAgreementReference = try SecureEnclaveCustodyHandleReference(
                handleSetIdentifier: handleSetIdentifier,
                role: .keyAgreement
            )
        } catch let error as SecureEnclaveCustodyHandleError {
            return .invalid(error)
        } catch {
            return .invalid(.privateHandleInaccessible(.signing))
        }

        do {
            let signingCandidates = try keyStore.loadKeys(
                reference: signingReference,
                authenticationContext: nil
            )
            let keyAgreementCandidates = try keyStore.loadKeys(
                reference: keyAgreementReference,
                authenticationContext: nil
            )
            if signingCandidates.count > 1 {
                return .invalid(.ambiguousPrivateHandle(.signing))
            }
            if keyAgreementCandidates.count > 1 {
                return .invalid(.ambiguousPrivateHandle(.keyAgreement))
            }

            let signing = signingCandidates.first
            let keyAgreement = keyAgreementCandidates.first
            switch (signing, keyAgreement) {
            case (nil, nil):
                return .missing
            case (.some, nil):
                return .partial(presentRoles: [.signing])
            case (nil, .some):
                return .partial(presentRoles: [.keyAgreement])
            case (.some(let signing), .some(let keyAgreement)):
                do {
                    let pair = try SecureEnclaveCustodyHandlePair(
                        signing: signing.binding,
                        keyAgreement: keyAgreement.binding
                    )
                    return .complete(pair)
                } catch let error as SecureEnclaveCustodyHandleError {
                    return .invalid(error)
                } catch {
                    return .invalid(.privateHandleInaccessible(.signing))
                }
            }
        } catch let error as SecureEnclaveCustodyHandleError {
            return .invalid(error)
        } catch {
            return .invalid(.privateHandleInaccessible(.signing))
        }
    }

    func classifyHandleAvailability(
        expected pair: SecureEnclaveCustodyHandlePair
    ) -> SecureEnclaveCustodyHandleAvailability {
        switch inspectHandlePair(handleSetIdentifier: pair.handleSetIdentifier) {
        case .missing:
            return .unavailable(.privateHandleMissing)
        case .partial:
            return .unavailable(.migrationOrRecoveryRequired)
        case .invalid(let error):
            return .unavailable(error.failureCategory)
        case .complete:
            do {
                _ = try loadHandlePair(expected: pair, authenticationContext: nil)
                return .available
            } catch let error as SecureEnclaveCustodyHandleError {
                return .unavailable(error.failureCategory)
            } catch {
                return .unavailable(.privateHandleInaccessible)
            }
        }
    }

    func locateHandlePair(
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data
    ) throws -> SecureEnclaveCustodyHandlePair {
        guard SecureEnclaveCustodyHandlePublicBinding.hasUncompressedP256X963PublicKeyShape(
            signingPublicKeyX963
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(.signing)
        }
        guard SecureEnclaveCustodyHandlePublicBinding.hasUncompressedP256X963PublicKeyShape(
            keyAgreementPublicKeyX963
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(.keyAgreement)
        }

        let items = try keyStore.inventoryKeys()
        var grouped: [String: [SecureEnclaveCustodyHandleInventoryItem]] = [:]
        for item in items {
            guard let reference = item.reference else {
                continue
            }
            grouped[reference.handleSetIdentifier, default: []].append(item)
        }

        var matches: [SecureEnclaveCustodyHandlePair] = []
        for (handleSetIdentifier, group) in grouped {
            let signingCount = group.filter { $0.role == .signing }.count
            let keyAgreementCount = group.filter { $0.role == .keyAgreement }.count
            if signingCount > 1 {
                throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.signing)
            }
            if keyAgreementCount > 1 {
                throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.keyAgreement)
            }

            switch inspectHandlePair(handleSetIdentifier: handleSetIdentifier) {
            case .missing:
                continue
            case .invalid(let error):
                throw error
            case .partial(let presentRoles):
                try failIfPartialSetMatchesExpectedPublicKey(
                    handleSetIdentifier: handleSetIdentifier,
                    presentRoles: presentRoles,
                    signingPublicKeyX963: signingPublicKeyX963,
                    keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
                )
            case .complete(let pair):
                let signingMatches = pair.signing.publicKeyX963 == signingPublicKeyX963
                let keyAgreementMatches = pair.keyAgreement.publicKeyX963 == keyAgreementPublicKeyX963
                if signingMatches, keyAgreementMatches {
                    matches.append(pair)
                } else if signingMatches {
                    throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.keyAgreement)
                } else if keyAgreementMatches {
                    throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(.signing)
                }
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

    func loadSigningHandle(
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        try loadHandle(
            forRole: .signing,
            signingPublicKeyX963: signingPublicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementPublicKeyX963,
            authenticationContext: authenticationContext
        )
    }

    func loadKeyAgreementHandle(
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        try loadHandle(
            forRole: .keyAgreement,
            signingPublicKeyX963: signingPublicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementPublicKeyX963,
            authenticationContext: authenticationContext
        )
    }

    private func loadHandle(
        forRole role: PGPPrivateOperationRole,
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        let pair = try locateHandlePair(
            signingPublicKeyX963: signingPublicKeyX963,
            keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
        )
        let binding = role == .signing ? pair.signing : pair.keyAgreement
        return try loadHandle(
            reference: binding.reference,
            expectedPublicKeyX963: binding.publicKeyX963,
            authenticationContext: authenticationContext
        )
    }

    func inventorySummaryForLocalRecovery() throws -> SecureEnclaveCustodyHandleInventorySummary {
        let items = try keyStore.inventoryKeys()
        guard !items.isEmpty else {
            return .empty
        }

        var malformedCount = 0
        var grouped: [String: [SecureEnclaveCustodyHandleInventoryItem]] = [:]
        for item in items {
            guard let reference = item.reference else {
                malformedCount += 1
                continue
            }
            grouped[reference.handleSetIdentifier, default: []].append(item)
        }

        var completeCount = 0
        var partialCount = 0
        var ambiguousCount = 0
        for group in grouped.values {
            let signingCount = group.filter { $0.role == .signing }.count
            let keyAgreementCount = group.filter { $0.role == .keyAgreement }.count
            if signingCount > 1 || keyAgreementCount > 1 {
                ambiguousCount += 1
            } else if signingCount == 1 && keyAgreementCount == 1 {
                completeCount += 1
            } else {
                partialCount += 1
            }
        }

        return SecureEnclaveCustodyHandleInventorySummary(
            totalHandleCount: items.count,
            completeSetCount: completeCount,
            partialSetCount: partialCount,
            ambiguousSetCount: ambiguousCount,
            malformedHandleCount: malformedCount
        )
    }

    func cleanupAllHandlesForLocalDataReset() -> SecureEnclaveCustodyHandleCleanupResult {
        let items: [SecureEnclaveCustodyHandleInventoryItem]
        do {
            items = try keyStore.inventoryKeys()
        } catch {
            return SecureEnclaveCustodyHandleCleanupResult(
                inspectedHandleCount: 0,
                deletedHandleCount: 0,
                failureCategory: .cleanupOrRollbackFailure
            )
        }

        let groupedByTag = Dictionary(grouping: items, by: \.applicationTagData)
        var deletedCount = 0
        var cleanupFailed = false
        for (applicationTagData, tagItems) in groupedByTag {
            do {
                try keyStore.deleteKey(
                    applicationTagData: applicationTagData,
                    roleHint: tagItems.compactMap(\.role).first
                )
                deletedCount += tagItems.count
            } catch let error as SecureEnclaveCustodyHandleError where error.isMissing {
                continue
            } catch {
                cleanupFailed = true
            }
        }

        return SecureEnclaveCustodyHandleCleanupResult(
            inspectedHandleCount: items.count,
            deletedHandleCount: deletedCount,
            failureCategory: cleanupFailed ? .cleanupOrRollbackFailure : nil
        )
    }

    func remainingHandleCountForLocalDataReset() throws -> Int {
        try keyStore.inventoryKeys().count
    }

    func deleteHandlePair(_ pair: SecureEnclaveCustodyHandlePair) throws {
        try deleteReferences(pair.references)
    }

    func deleteHandlePair(
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data
    ) throws {
        do {
            let pair = try locateHandlePair(
                signingPublicKeyX963: signingPublicKeyX963,
                keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
            )
            try deleteHandlePair(pair)
        } catch let error as SecureEnclaveCustodyHandleError where error == .partialHandlePair {
            let partialReferences = try locateMatchingPartialReferences(
                signingPublicKeyX963: signingPublicKeyX963,
                keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
            )
            try deleteReferences(partialReferences)
        } catch let error as SecureEnclaveCustodyHandleError where error.isMissing {
            return
        }
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

    private func locateMatchingPartialReferences(
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data
    ) throws -> [SecureEnclaveCustodyHandleReference] {
        let items = try keyStore.inventoryKeys()
        var grouped: [String: [SecureEnclaveCustodyHandleInventoryItem]] = [:]
        for item in items {
            guard let reference = item.reference else {
                continue
            }
            grouped[reference.handleSetIdentifier, default: []].append(item)
        }

        var matchingReferences: [SecureEnclaveCustodyHandleReference] = []
        var matchingHandleSetIdentifiers: Set<String> = []
        for (handleSetIdentifier, group) in grouped {
            let signingCount = group.filter { $0.role == .signing }.count
            let keyAgreementCount = group.filter { $0.role == .keyAgreement }.count
            if signingCount > 1 {
                throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.signing)
            }
            if keyAgreementCount > 1 {
                throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.keyAgreement)
            }

            switch inspectHandlePair(handleSetIdentifier: handleSetIdentifier) {
            case .missing, .complete:
                continue
            case .invalid(let error):
                throw error
            case .partial(let presentRoles):
                let references = try matchingPartialReferences(
                    handleSetIdentifier: handleSetIdentifier,
                    presentRoles: presentRoles,
                    signingPublicKeyX963: signingPublicKeyX963,
                    keyAgreementPublicKeyX963: keyAgreementPublicKeyX963
                )
                if !references.isEmpty {
                    matchingReferences.append(contentsOf: references)
                    matchingHandleSetIdentifiers.insert(handleSetIdentifier)
                }
            }
        }

        guard matchingHandleSetIdentifiers.count <= 1 else {
            throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(.signing)
        }
        return matchingReferences
    }

    private func matchingPartialReferences(
        handleSetIdentifier: String,
        presentRoles: Set<PGPPrivateOperationRole>,
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data
    ) throws -> [SecureEnclaveCustodyHandleReference] {
        var references: [SecureEnclaveCustodyHandleReference] = []
        for role in presentRoles {
            let reference = try SecureEnclaveCustodyHandleReference(
                handleSetIdentifier: handleSetIdentifier,
                role: role
            )
            let candidates = try keyStore.loadKeys(
                reference: reference,
                authenticationContext: nil
            )
            guard candidates.count <= 1 else {
                throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(role)
            }
            guard let candidate = candidates.first else {
                continue
            }

            let expectedPublicKey = role == .signing ? signingPublicKeyX963 : keyAgreementPublicKeyX963
            if candidate.binding.publicKeyX963 == expectedPublicKey {
                references.append(reference)
            }
        }
        return references
    }

    private func failIfPartialSetMatchesExpectedPublicKey(
        handleSetIdentifier: String,
        presentRoles: Set<PGPPrivateOperationRole>,
        signingPublicKeyX963: Data,
        keyAgreementPublicKeyX963: Data
    ) throws {
        for role in presentRoles {
            let reference = try SecureEnclaveCustodyHandleReference(
                handleSetIdentifier: handleSetIdentifier,
                role: role
            )
            let candidates = try keyStore.loadKeys(
                reference: reference,
                authenticationContext: nil
            )
            let expectedPublicKey = role == .signing ? signingPublicKeyX963 : keyAgreementPublicKeyX963
            if candidates.contains(where: { $0.binding.publicKeyX963 == expectedPublicKey }) {
                throw SecureEnclaveCustodyHandleError.partialHandlePair
            }
        }
    }
}
