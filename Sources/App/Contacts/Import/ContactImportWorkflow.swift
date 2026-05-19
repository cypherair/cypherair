import Foundation

@MainActor
struct ContactImportWorkflow {
    let contactService: ContactService

    func makeImportConfirmationRequest(
        inspection: PublicKeyImportInspection,
        allowsUnverifiedImport: Bool,
        onSuccess: @escaping @MainActor (ContactIdentitySummary) -> Void,
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
                    onFailure: onFailure
                )
            },
            onImportUnverified: {
                importContact(
                    keyData: inspection.keyData,
                    verificationState: .unverified,
                    onSuccess: onSuccess,
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
            }
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
