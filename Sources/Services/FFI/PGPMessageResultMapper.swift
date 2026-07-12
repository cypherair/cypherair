import Foundation

enum PGPMessageResultMapper {
    static func decryptDetailedResult(
        _ result: DecryptDetailedResult,
        context: PGPMessageVerificationContext
    ) -> (plaintext: Data, verification: DetailedSignatureVerification) {
        (
            plaintext: result.plaintext,
            verification: detailedVerification(
                summaryState: result.summaryState,
                summaryEntryIndex: result.summaryEntryIndex,
                signatures: result.signatures,
                contactKeys: context.contactKeys,
                ownKeys: context.ownKeys,
                contactsAvailability: context.contactsAvailability
            )
        )
    }

    static func fileDecryptDetailedResult(
        _ result: FileDecryptDetailedResult,
        context: PGPMessageVerificationContext
    ) -> DetailedSignatureVerification {
        detailedVerification(
            summaryState: result.summaryState,
            summaryEntryIndex: result.summaryEntryIndex,
            signatures: result.signatures,
            contactKeys: context.contactKeys,
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
                verification: detailedVerification(
                    summaryState: result.summaryState,
                    summaryEntryIndex: result.summaryEntryIndex,
                    signatures: result.signatures,
                    contactKeys: context.contactKeys,
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

    static func verifyDetailedResult(
        _ result: VerifyDetailedResult,
        context: PGPMessageVerificationContext
    ) -> (text: Data?, verification: DetailedSignatureVerification) {
        (
            text: result.content,
            verification: detailedVerification(
                summaryState: result.summaryState,
                summaryEntryIndex: result.summaryEntryIndex,
                signatures: result.signatures,
                contactKeys: context.contactKeys,
                ownKeys: context.ownKeys,
                contactsAvailability: context.contactsAvailability
            )
        )
    }

    static func fileVerifyDetailedResult(
        _ result: FileVerifyDetailedResult,
        context: PGPMessageVerificationContext
    ) -> DetailedSignatureVerification {
        detailedVerification(
            summaryState: result.summaryState,
            summaryEntryIndex: result.summaryEntryIndex,
            signatures: result.signatures,
            contactKeys: context.contactKeys,
            ownKeys: context.ownKeys,
            contactsAvailability: context.contactsAvailability
        )
    }

    private static func detailedVerification(
        summaryState: SignatureVerificationState,
        summaryEntryIndex: UInt64?,
        signatures: [DetailedSignatureEntry],
        contactKeys: [ContactKeyRecord],
        ownKeys: [PGPKeyIdentity],
        contactsAvailability: ContactsAvailability
    ) -> DetailedSignatureVerification {
        let contactKeysForVerification = contactsAvailability.allowsContactsVerification ? contactKeys : []
        let unavailableReason = contactsAvailability.allowsContactsVerification ? nil : contactsAvailability

        let mappedEntries = signatures.map { entry in
            let appState = SignatureVerification.VerificationState(
                ffiStatus: entry.status,
                contactsAvailability: contactsAvailability
            )
            return DetailedSignatureVerification.Entry(
                verificationState: appState,
                signerPrimaryFingerprint: entry.signerPrimaryFingerprint,
                contactsUnavailableReason: appState == .contactsContextUnavailable ? unavailableReason : nil,
                signerIdentity: SignatureVerification.SignerIdentity.resolve(
                    fingerprint: entry.signerPrimaryFingerprint,
                    contactKeys: contactKeysForVerification,
                    ownKeys: ownKeys
                )
            )
        }

        let appSummaryState = SignatureVerification.VerificationState(
            ffiState: summaryState,
            contactsAvailability: contactsAvailability
        )

        return DetailedSignatureVerification(
            summaryState: appSummaryState,
            summaryEntryIndex: summaryEntryIndex,
            contactsUnavailableReason: appSummaryState == .contactsContextUnavailable ? unavailableReason : nil,
            signatures: mappedEntries
        )
    }
}

private extension SignatureVerification.VerificationState {
    init(
        ffiState: SignatureVerificationState,
        contactsAvailability: ContactsAvailability
    ) {
        switch ffiState {
        case .notSigned:
            self = .notSigned
        case .verified:
            self = .verified
        case .invalid:
            self = .invalid
        case .expired:
            self = .expired
        case .signerCertificateUnavailable:
            if contactsAvailability.allowsContactsVerification {
                self = .signerCertificateUnavailable
            } else {
                self = .contactsContextUnavailable
            }
        }
    }

    init(
        ffiStatus: DetailedSignatureStatus,
        contactsAvailability: ContactsAvailability
    ) {
        switch ffiStatus {
        case .valid:
            self = .verified
        case .bad:
            self = .invalid
        case .expired:
            self = .expired
        case .unknownSigner:
            if contactsAvailability.allowsContactsVerification {
                self = .signerCertificateUnavailable
            } else {
                self = .contactsContextUnavailable
            }
        }
    }
}
