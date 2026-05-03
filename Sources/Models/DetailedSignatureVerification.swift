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

    let legacyStatus: SignatureStatus
    let legacySignerFingerprint: String?
    let legacySignerContact: Contact?
    let legacySignerIdentity: SignatureVerification.SignerIdentity?
    let summaryState: SignatureVerification.VerificationState
    let summaryEntryIndex: UInt64?
    let contactsUnavailableReason: ContactsAvailability?
    let signatures: [Entry]

    init(
        legacyStatus: SignatureStatus,
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

    static func from(
        legacyStatus: SignatureStatus,
        legacySignerFingerprint: String?,
        summaryState: SignatureVerificationState,
        summaryEntryIndex: UInt64?,
        signatures: [DetailedSignatureEntry],
        contacts: [Contact],
        ownKeys: [PGPKeyIdentity],
        contactsAvailability: ContactsAvailability = .availableLegacyCompatibility
    ) -> DetailedSignatureVerification {
        let contactsForVerification = contactsAvailability.allowsContactsVerification ? contacts : []
        let unavailableReason = contactsAvailability.allowsContactsVerification ? nil : contactsAvailability
        let legacySignerContact = legacySignerFingerprint.flatMap { fingerprint in
            contactsForVerification.first(where: { $0.fingerprint == fingerprint })
        }
        let legacySignerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: legacySignerFingerprint,
            contacts: contactsForVerification,
            ownKeys: ownKeys
        )

        let mappedEntries = signatures.map { entry in
            let appState = SignatureVerification.VerificationState(
                ffiState: entry.state,
                contactsAvailability: contactsAvailability
            )
            return Entry(
                status: Entry.Status(from: entry.status),
                verificationState: appState,
                signerPrimaryFingerprint: entry.signerPrimaryFingerprint,
                verificationCertificateFingerprint: entry.verificationCertificateFingerprint,
                contactsUnavailableReason: appState == .contactsContextUnavailable ? unavailableReason : nil,
                signerIdentity: SignatureVerification.SignerIdentity.resolve(
                    fingerprint: entry.verificationCertificateFingerprint,
                    contacts: contactsForVerification,
                    ownKeys: ownKeys
                )
            )
        }

        let appSummaryState = SignatureVerification.VerificationState(
            ffiState: summaryState,
            contactsAvailability: contactsAvailability
        )

        return DetailedSignatureVerification(
            legacyStatus: legacyStatus,
            legacySignerFingerprint: legacySignerFingerprint,
            legacySignerContact: legacySignerContact,
            legacySignerIdentity: legacySignerIdentity,
            summaryState: appSummaryState,
            summaryEntryIndex: summaryEntryIndex,
            contactsUnavailableReason: appSummaryState == .contactsContextUnavailable ? unavailableReason : nil,
            signatures: mappedEntries
        )
    }
}

extension ContactsAvailability {
    var allowsContactsVerification: Bool {
        switch self {
        case .availableLegacyCompatibility, .availableProtectedDomain:
            true
        case .opening, .locked, .recoveryNeeded, .frameworkUnavailable, .restartRequired:
            false
        }
    }
}

extension SignatureVerification.VerificationState {
    init(legacyStatus: SignatureStatus) {
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

private extension DetailedSignatureVerification.Entry.Status {
    init(from status: DetailedSignatureStatus) {
        switch status {
        case .valid:
            self = .valid
        case .unknownSigner:
            self = .unknownSigner
        case .bad:
            self = .bad
        case .expired:
            self = .expired
        }
    }
}
