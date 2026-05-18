import Foundation

@MainActor
struct PendingContactKeyUpdate: Identifiable {
    let id = UUID()
    let request: ContactLegacyKeyReplacementRequest
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
        onSuccess: @escaping @MainActor (ContactIdentitySummary) -> Void,
        onReplaceRequested: @escaping @MainActor (ContactKeyUpdateConfirmationRequest) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void,
        onCancel: @escaping @MainActor () -> Void = {}
    ) -> ImportConfirmationRequest {
        ImportConfirmationRequest(
            keyData: inspection.keyData,
            metadata: inspection.metadata,
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
        onSuccess: @escaping @MainActor (ContactIdentitySummary) -> Void,
        onReplaceRequested: @escaping @MainActor (ContactKeyUpdateConfirmationRequest) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void
    ) {
        do {
            let result = try contactService.importContact(
                publicKeyData: keyData,
                verificationState: verificationState
            )
            switch result {
            case .added(let contact, _),
                 .addedWithCandidate(let contact, _, _),
                 .updated(let contact, _),
                 .duplicate(let contact, _):
                onSuccess(contact)
            case .legacyKeyReplacementDetected(let request):
                guard contactService.contactsAvailability != .availableProtectedDomain else {
                    onFailure(.contactKeyReplacementUnsupported)
                    return
                }
                onReplaceRequested(
                    makeKeyUpdateConfirmationRequest(
                        pendingUpdate: PendingContactKeyUpdate(request: request),
                        onSuccess: onSuccess,
                        onFailure: onFailure
                    )
                )
            }
        } catch {
            onFailure(Self.contactImportError(from: error))
        }
    }

    private func makeKeyUpdateConfirmationRequest(
        pendingUpdate: PendingContactKeyUpdate,
        onSuccess: @escaping @MainActor (ContactIdentitySummary) -> Void,
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
        onSuccess: @escaping @MainActor (ContactIdentitySummary) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void
    ) {
        do {
            let result = try contactService.confirmLegacyKeyReplacement(pendingUpdate.request)
            guard let contact = result.contact else {
                onFailure(.contactKeyReplacementUnsupported)
                return
            }
            onSuccess(contact)
        } catch {
            onFailure(Self.contactImportError(from: error))
        }
    }

    private static func contactImportError(from error: Error) -> CypherAirError {
        if let cypherAirError = error as? CypherAirError {
            return cypherAirError
        }
        return .invalidKeyData(reason: error.localizedDescription)
    }
}
