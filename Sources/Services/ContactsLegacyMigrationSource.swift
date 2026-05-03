import Foundation

struct ContactsLegacyRuntimeValues {
    let contacts: [Contact]
    let verificationStates: [String: ContactVerificationState]
}

final class ContactsLegacyMigrationSource: @unchecked Sendable {
    private let engine: PgpEngine
    private let repository: ContactRepository
    private let domainRepository: ContactsDomainRepository

    init(
        engine: PgpEngine,
        repository: ContactRepository,
        domainRepository: ContactsDomainRepository = ContactsDomainRepository()
    ) {
        self.engine = engine
        self.repository = repository
        self.domainRepository = domainRepository
    }

    func makeInitialSnapshot() throws -> ContactsDomainSnapshot {
        guard repository.activeLegacySourceExists() else {
            return ContactsDomainSnapshot.empty()
        }
        let runtime = try loadRuntimeValues(repairMetadata: false)
        return try domainRepository.makeCompatibilitySnapshot(from: runtime.contacts)
    }

    func loadRuntimeValues(repairMetadata: Bool) throws -> ContactsLegacyRuntimeValues {
        let loadedVerificationStates = try repository.loadVerificationStatesIfDirectoryExists()
        var loadedContacts: [Contact] = []

        for storedContact in try repository.loadStoredContactsIfDirectoryExists() {
            let validation = try ContactImportPublicCertificateValidator.validate(
                storedContact.data,
                using: engine
            )
            let contact = makeContact(
                from: validation,
                verificationStates: loadedVerificationStates
            )
            loadedContacts.append(contact)
        }

        let loadedFingerprints = Set(loadedContacts.map(\.fingerprint))
        let filteredStates = loadedVerificationStates.filter { loadedFingerprints.contains($0.key) }
        if repairMetadata && filteredStates != loadedVerificationStates {
            try repository.saveVerificationStates(filteredStates)
        }

        return ContactsLegacyRuntimeValues(
            contacts: loadedContacts,
            verificationStates: filteredStates
        )
    }

    private func makeContact(
        from validation: PublicCertificateValidationResult,
        verificationStates: [String: ContactVerificationState]
    ) -> Contact {
        let resolvedVerificationState = verificationStates[validation.keyInfo.fingerprint] ?? .verified

        return Contact(
            fingerprint: validation.keyInfo.fingerprint,
            keyVersion: validation.keyInfo.keyVersion,
            profile: validation.profile,
            userId: validation.keyInfo.userId,
            isRevoked: validation.keyInfo.isRevoked,
            isExpired: validation.keyInfo.isExpired,
            hasEncryptionSubkey: validation.keyInfo.hasEncryptionSubkey,
            verificationState: resolvedVerificationState,
            publicKeyData: validation.publicCertData,
            primaryAlgo: validation.keyInfo.primaryAlgo,
            subkeyAlgo: validation.keyInfo.subkeyAlgo
        )
    }
}
