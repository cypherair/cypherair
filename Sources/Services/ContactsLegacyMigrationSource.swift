import Foundation

struct ContactsLegacyRuntimeValues {
    let contacts: [Contact]
    let verificationStates: [String: ContactVerificationState]
}

final class ContactsLegacyMigrationSource: @unchecked Sendable {
    private let contactImportAdapter: PGPContactImportAdapter
    private let repository: ContactRepository
    private let compatibilityMapper: ContactsCompatibilityMapper

    init(
        contactImportAdapter: PGPContactImportAdapter,
        repository: ContactRepository,
        compatibilityMapper: ContactsCompatibilityMapper = ContactsCompatibilityMapper()
    ) {
        self.contactImportAdapter = contactImportAdapter
        self.repository = repository
        self.compatibilityMapper = compatibilityMapper
    }

    func makeInitialSnapshot() throws -> ContactsDomainSnapshot {
        guard repository.activeLegacySourceExists() else {
            return ContactsDomainSnapshot.empty()
        }
        let runtime = try loadRuntimeValues(repairMetadata: false)
        return try compatibilityMapper.makeCompatibilitySnapshot(from: runtime.contacts)
    }

    func loadRuntimeValues(repairMetadata: Bool) throws -> ContactsLegacyRuntimeValues {
        let loadedVerificationStates = try repository.loadVerificationStatesIfDirectoryExists()
        var loadedContacts: [Contact] = []

        for storedContact in try repository.loadStoredContactsIfDirectoryExists() {
            let validation = try contactImportAdapter.validateImportablePublicCertificate(storedContact.data)
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
        from validation: PGPValidatedPublicCertificate,
        verificationStates: [String: ContactVerificationState]
    ) -> Contact {
        let metadata = validation.metadata
        let resolvedVerificationState = verificationStates[metadata.fingerprint] ?? .verified

        return Contact(
            fingerprint: metadata.fingerprint,
            keyVersion: metadata.keyVersion,
            profile: metadata.profile,
            userId: metadata.userId,
            isRevoked: metadata.isRevoked,
            isExpired: metadata.isExpired,
            hasEncryptionSubkey: metadata.hasEncryptionSubkey,
            verificationState: resolvedVerificationState,
            publicKeyData: validation.publicCertData,
            primaryAlgo: metadata.primaryAlgo,
            subkeyAlgo: metadata.subkeyAlgo
        )
    }
}
