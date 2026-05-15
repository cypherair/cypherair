import Foundation

/// Additive message-signature verification result that preserves detailed per-signature outcomes
/// while retaining a legacy compatibility bridge for existing consumers.
struct DetailedSignatureVerification: Equatable {
    struct Entry: Equatable {
        enum Status: Equatable {
            case valid
            case unknownSigner
            case bad
            case expired
        }

        let status: Status
        let verificationState: SignatureVerification.VerificationState
        let signerPrimaryFingerprint: String?
        let verificationCertificateFingerprint: String?
        let contactsUnavailableReason: ContactsAvailability?
        let signerIdentity: SignatureVerification.SignerIdentity?

        init(
            status: Status,
            verificationState: SignatureVerification.VerificationState,
            signerPrimaryFingerprint: String?,
            verificationCertificateFingerprint: String?,
            contactsUnavailableReason: ContactsAvailability? = nil,
            signerIdentity: SignatureVerification.SignerIdentity?
        ) {
            self.status = status
            self.verificationState = verificationState
            self.signerPrimaryFingerprint = signerPrimaryFingerprint
            self.verificationCertificateFingerprint = verificationCertificateFingerprint
            self.contactsUnavailableReason = contactsUnavailableReason
            self.signerIdentity = signerIdentity
        }

        init(
            status: Status,
            signerPrimaryFingerprint: String?,
            signerIdentity: SignatureVerification.SignerIdentity?
        ) {
            self.init(
                status: status,
                verificationState: SignatureVerification.VerificationState(entryStatus: status),
                signerPrimaryFingerprint: signerPrimaryFingerprint,
                verificationCertificateFingerprint: signerPrimaryFingerprint,
                signerIdentity: signerIdentity
            )
        }
    }

    let legacyStatus: MessageSignatureStatus
    let legacySignerFingerprint: String?
    let legacySignerContact: Contact?
    let legacySignerIdentity: SignatureVerification.SignerIdentity?
    let summaryState: SignatureVerification.VerificationState
    let summaryEntryIndex: UInt64?
    let contactsUnavailableReason: ContactsAvailability?
    let signatures: [Entry]

    init(
        legacyStatus: MessageSignatureStatus,
        legacySignerFingerprint: String?,
        legacySignerContact: Contact?,
        legacySignerIdentity: SignatureVerification.SignerIdentity?,
        summaryState: SignatureVerification.VerificationState? = nil,
        summaryEntryIndex: UInt64? = nil,
        contactsUnavailableReason: ContactsAvailability? = nil,
        signatures: [Entry]
    ) {
        self.legacyStatus = legacyStatus
        self.legacySignerFingerprint = legacySignerFingerprint
        self.legacySignerContact = legacySignerContact
        self.legacySignerIdentity = legacySignerIdentity
        self.summaryState = summaryState ?? SignatureVerification.VerificationState(legacyStatus: legacyStatus)
        self.summaryEntryIndex = summaryEntryIndex
        self.contactsUnavailableReason = contactsUnavailableReason
        self.signatures = signatures
    }

    var legacyVerification: SignatureVerification {
        SignatureVerification(
            status: legacyStatus,
            signerFingerprint: legacySignerFingerprint,
            signerContact: legacySignerContact,
            signerIdentity: legacySignerIdentity,
            verificationState: summaryState,
            contactsUnavailableReason: contactsUnavailableReason
        )
    }

}

extension SignatureVerification.VerificationState {
    init(legacyStatus: MessageSignatureStatus) {
        switch legacyStatus {
        case .valid:
            self = .verified
        case .bad:
            self = .invalid
        case .unknownSigner:
            self = .signerCertificateUnavailable
        case .notSigned:
            self = .notSigned
        case .expired:
            self = .expired
        }
    }

    init(entryStatus: DetailedSignatureVerification.Entry.Status) {
        switch entryStatus {
        case .valid:
            self = .verified
        case .unknownSigner:
            self = .signerCertificateUnavailable
        case .bad:
            self = .invalid
        case .expired:
            self = .expired
        }
    }
}
