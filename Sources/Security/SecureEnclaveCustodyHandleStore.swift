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
