import Foundation

enum PGPMessageResultMapper {
    static func decryptDetailedResult(
        _ result: DecryptDetailedResult,
        context: PGPMessageVerificationContext
    ) -> (plaintext: Data, verification: DetailedSignatureVerification) {
        (
            plaintext: result.plaintext,
            verification: DetailedSignatureVerification.from(
                legacyStatus: result.legacyStatus,
                legacySignerFingerprint: result.legacySignerFingerprint,
                summaryState: result.summaryState,
                summaryEntryIndex: result.summaryEntryIndex,
                signatures: result.signatures,
                contacts: context.contacts,
                ownKeys: context.ownKeys,
                contactsAvailability: context.contactsAvailability
            )
        )
    }

    static func fileDecryptDetailedResult(
        _ result: FileDecryptDetailedResult,
        context: PGPMessageVerificationContext
    ) -> DetailedSignatureVerification {
        DetailedSignatureVerification.from(
            legacyStatus: result.legacyStatus,
            legacySignerFingerprint: result.legacySignerFingerprint,
            summaryState: result.summaryState,
            summaryEntryIndex: result.summaryEntryIndex,
            signatures: result.signatures,
            contacts: context.contacts,
            ownKeys: context.ownKeys,
            contactsAvailability: context.contactsAvailability
        )
    }

    static func passwordDecryptResult(
        _ result: PasswordDecryptResult,
        context: PGPMessageVerificationContext
    ) throws -> PasswordMessageDetailedDecryptOutcome {
        switch result.status {
        case .decrypted:
            guard let plaintext = result.plaintext else {
                throw CypherAirError.internalError(
                    reason: "Password decrypt returned decrypted status without plaintext."
                )
            }

            return .decrypted(
                plaintext: plaintext,
                verification: DetailedSignatureVerification.from(
                    legacyStatus: result.signatureStatus ?? .notSigned,
                    legacySignerFingerprint: result.signerFingerprint,
                    summaryState: result.summaryState,
                    summaryEntryIndex: result.summaryEntryIndex,
                    signatures: result.signatures,
                    contacts: context.contacts,
                    ownKeys: context.ownKeys,
                    contactsAvailability: context.contactsAvailability
                )
            )

        case .noSkesk:
            return .noSkesk

        case .passwordRejected:
            return .passwordRejected
        }
    }
}
