import Foundation

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
                try keyStore.deleteKey(reference: signingReference)
            } catch {
                throw SecureEnclaveCustodyHandleError.cleanupOrRollbackFailed
            }
            throw error
        }
    }

    func loadHandlePair(expected pair: SecureEnclaveCustodyHandlePair) throws -> SecureEnclaveCustodyLoadedHandlePair {
        let signing = try loadHandle(
            reference: pair.signing.reference,
            expectedPublicKeyX963: pair.signing.publicKeyX963
        )
        let keyAgreement = try loadHandle(
            reference: pair.keyAgreement.reference,
            expectedPublicKeyX963: pair.keyAgreement.publicKeyX963
        )
        return try SecureEnclaveCustodyLoadedHandlePair(
            signing: signing,
            keyAgreement: keyAgreement
        )
    }

    func loadHandle(
        reference: SecureEnclaveCustodyHandleReference,
        expectedPublicKeyX963: Data
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        guard SecureEnclaveCustodyHandlePublicBinding.isValidP256X963PublicKey(expectedPublicKeyX963) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(reference.role)
        }

        let candidates = try keyStore.loadKeys(reference: reference)
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
            let signingCandidates = try keyStore.loadKeys(reference: signingReference)
            let keyAgreementCandidates = try keyStore.loadKeys(reference: keyAgreementReference)
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
                _ = try loadHandlePair(expected: pair)
                return .available
            } catch let error as SecureEnclaveCustodyHandleError {
                return .unavailable(error.failureCategory)
            } catch {
                return .unavailable(.privateHandleInaccessible)
            }
        }
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

        var deletedCount = 0
        var cleanupFailed = false
        var seenTags = Set<Data>()
        for item in items where seenTags.insert(item.applicationTagData).inserted {
            do {
                try keyStore.deleteKey(
                    applicationTagData: item.applicationTagData,
                    roleHint: item.role
                )
                deletedCount += 1
            } catch let error as SecureEnclaveCustodyHandleError where error.isMissing {
                continue
            } catch {
                cleanupFailed = true
            }
        }

        return SecureEnclaveCustodyHandleCleanupResult(
            inspectedHandleCount: seenTags.count,
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

    func deleteHandlePair(handleSetIdentifier: String) throws {
        let references = try [
            SecureEnclaveCustodyHandleReference(
                handleSetIdentifier: handleSetIdentifier,
                role: .signing
            ),
            SecureEnclaveCustodyHandleReference(
                handleSetIdentifier: handleSetIdentifier,
                role: .keyAgreement
            )
        ]
        try deleteReferences(references)
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
