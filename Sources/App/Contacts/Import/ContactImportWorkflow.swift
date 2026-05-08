import Foundation

@MainActor
struct PendingContactKeyUpdate: Identifiable {
    let id = UUID()
    let newContact: Contact
    let existingContact: Contact
    let keyData: Data
}

@MainActor
struct ContactKeyUpdateConfirmationRequest: Identifiable {
    let id = UUID()
    let pendingUpdate: PendingContactKeyUpdate
    let onConfirm: @MainActor () -> Void
    let onCancel: @MainActor () -> Void
}

@MainActor
struct ContactImportWorkflow {
    let contactService: ContactService

    func makeImportConfirmationRequest(
        inspection: PublicKeyImportInspection,
        allowsUnverifiedImport: Bool,
        onSuccess: @escaping @MainActor (Contact) -> Void,
        onReplaceRequested: @escaping @MainActor (ContactKeyUpdateConfirmationRequest) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void,
        onCancel: @escaping @MainActor () -> Void = {}
    ) -> ImportConfirmationRequest {
        ImportConfirmationRequest(
            keyData: inspection.keyData,
            keyInfo: inspection.keyInfo,
            profile: inspection.profile,
            allowsUnverifiedImport: allowsUnverifiedImport,
            onImportVerified: {
                importContact(
                    keyData: inspection.keyData,
                    verificationState: .verified,
                    onSuccess: onSuccess,
                    onReplaceRequested: onReplaceRequested,
                    onFailure: onFailure
                )
            },
            onImportUnverified: {
                importContact(
                    keyData: inspection.keyData,
                    verificationState: .unverified,
                    onSuccess: onSuccess,
                    onReplaceRequested: onReplaceRequested,
                    onFailure: onFailure
                )
            },
            onCancel: onCancel
        )
    }

    private func importContact(
        keyData: Data,
        verificationState: ContactVerificationState,
        onSuccess: @escaping @MainActor (Contact) -> Void,
        onReplaceRequested: @escaping @MainActor (ContactKeyUpdateConfirmationRequest) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void
    ) {
        do {
            let result = try contactService.addContact(
                publicKeyData: keyData,
                verificationState: verificationState
            )
            switch result {
            case .added(let contact), .addedWithCandidate(let contact, _),
                 .updated(let contact), .duplicate(let contact):
                onSuccess(contact)
            case .keyUpdateDetected(let newContact, let existingContact, let replacementKeyData):
                let pendingUpdate = PendingContactKeyUpdate(
                    newContact: newContact,
                    existingContact: existingContact,
                    keyData: replacementKeyData
                )
                onReplaceRequested(
                    makeKeyUpdateConfirmationRequest(
                        pendingUpdate: pendingUpdate,
                        onSuccess: onSuccess,
                        onFailure: onFailure
                    )
                )
            }
        } catch {
            onFailure(ContactImportPublicCertificateValidator.mapError(error))
        }
    }

    private func makeKeyUpdateConfirmationRequest(
        pendingUpdate: PendingContactKeyUpdate,
        onSuccess: @escaping @MainActor (Contact) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void
    ) -> ContactKeyUpdateConfirmationRequest {
        ContactKeyUpdateConfirmationRequest(
            pendingUpdate: pendingUpdate,
            onConfirm: {
                confirmReplacement(
                    pendingUpdate,
                    onSuccess: onSuccess,
                    onFailure: onFailure
                )
            },
            onCancel: {}
        )
    }

    private func confirmReplacement(
        _ pendingUpdate: PendingContactKeyUpdate,
        onSuccess: @escaping @MainActor (Contact) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void
    ) {
        do {
            let contact = try contactService.confirmKeyUpdate(
                existingFingerprint: pendingUpdate.existingContact.fingerprint,
                keyData: pendingUpdate.keyData
            )
            onSuccess(contact)
        } catch {
            onFailure(ContactImportPublicCertificateValidator.mapError(error))
        }
    }
}
