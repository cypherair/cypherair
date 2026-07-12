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
    ) throws -> ImportConfirmationRequest {
        let candidateMatch = try contactService.previewImportCandidateMatch(
            publicKeyData: inspection.keyData
        )
        return ImportConfirmationRequest(
            metadata: inspection.metadata,
            candidateMatch: candidateMatch,
            allowsUnverifiedImport: allowsUnverifiedImport,
            onImportVerified: {
                importContact(
                    keyData: inspection.keyData,
                    verificationState: .verified,
                    displayedCandidateMatch: candidateMatch,
                    onSuccess: onSuccess,
                    onFailure: onFailure
                )
            },
            onImportUnverified: {
                importContact(
                    keyData: inspection.keyData,
                    verificationState: .unverified,
                    displayedCandidateMatch: candidateMatch,
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
        displayedCandidateMatch: ContactCandidateMatch?,
        onSuccess: @escaping @MainActor (ContactIdentitySummary) -> Void,
        onFailure: @escaping @MainActor (CypherAirError) -> Void
    ) {
        do {
            let result = try contactService.importContactAfterConfirmation(
                publicKeyData: keyData,
                verificationState: verificationState,
                displayedCandidateMatch: displayedCandidateMatch
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
