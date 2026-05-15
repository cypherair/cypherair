import Foundation

/// App-level signature verification result for display in the UI.
struct SignatureVerification {
    enum VerificationState: Equatable {
        case notSigned
        case verified
        case invalid
        case expired
        case signerCertificateUnavailable
        case contactsContextUnavailable
    }

    enum SignerSource: Equatable {
        case contact
        case ownKey
        case unknown
    }

    struct SignerIdentity: Equatable {
        let source: SignerSource
        let displayName: String
        let secondaryText: String?
        let shortKeyId: String?
        let fingerprint: String
        let isVerifiedContact: Bool

        var formattedFingerprint: String {
            IdentityPresentation.formattedFingerprint(fingerprint)
        }

        static func resolve(
            fingerprint: String?,
            contacts: [Contact],
            ownKeys: [PGPKeyIdentity]
        ) -> SignerIdentity? {
            guard let fingerprint else { return nil }

            if let contact = contacts.first(where: { $0.fingerprint == fingerprint }) {
                return SignerIdentity(
                    source: .contact,
                    displayName: contact.displayName,
                    secondaryText: contact.email ?? contact.userId,
                    shortKeyId: contact.shortKeyId,
                    fingerprint: contact.fingerprint,
                    isVerifiedContact: contact.isVerified
                )
            }

            if let ownKey = ownKeys.first(where: { $0.fingerprint == fingerprint }) {
                return SignerIdentity(
                    source: .ownKey,
                    displayName: "",
                    secondaryText: ownKey.userId ?? ownKey.shortKeyId,
                    shortKeyId: ownKey.shortKeyId,
                    fingerprint: ownKey.fingerprint,
                    isVerifiedContact: true
                )
            }

            return SignerIdentity(
                source: .unknown,
                displayName: "",
                secondaryText: nil,
                shortKeyId: IdentityPresentation.shortKeyId(from: fingerprint),
                fingerprint: fingerprint,
                isVerifiedContact: false
            )
        }
    }

    /// The graded verification result.
    let status: MessageSignatureStatus

    /// App-level verification state that separates crypto verification from Contacts availability.
    let verificationState: VerificationState

    /// Fingerprint of the signer, if known.
    let signerFingerprint: String?

    /// The contact who signed (resolved from fingerprint), if available.
    let signerContact: Contact?

    let signerIdentity: SignerIdentity?

    let contactsUnavailableReason: ContactsAvailability?

    var requiresContactsContext: Bool {
        verificationState == .contactsContextUnavailable
    }

    init(
        status: MessageSignatureStatus,
        signerFingerprint: String?,
        signerContact: Contact?,
        signerIdentity: SignerIdentity? = nil,
        verificationState: VerificationState? = nil,
        contactsUnavailableReason: ContactsAvailability? = nil
    ) {
        self.status = status
        self.verificationState = verificationState ?? VerificationState(legacyStatus: status)
        self.signerFingerprint = signerFingerprint
        self.signerContact = signerContact
        self.contactsUnavailableReason = contactsUnavailableReason
        self.signerIdentity = signerIdentity ?? signerContact.map {
            SignerIdentity(
                source: .contact,
                displayName: $0.displayName,
                secondaryText: $0.email ?? $0.userId,
                shortKeyId: $0.shortKeyId,
                fingerprint: $0.fingerprint,
                isVerifiedContact: $0.isVerified
            )
        } ?? signerFingerprint.map {
            SignerIdentity(
                source: .unknown,
                displayName: "",
                secondaryText: nil,
                shortKeyId: IdentityPresentation.shortKeyId(from: $0),
                fingerprint: $0,
                isVerifiedContact: false
            )
        }
    }

    /// Whether this status represents a security concern.
    var isWarning: Bool {
        switch verificationState {
        case .invalid, .expired, .signerCertificateUnavailable,
             .contactsContextUnavailable:
            true
        case .verified, .notSigned:
            false
        }
    }

    var shouldShowSignerIdentity: Bool {
        verificationState != .notSigned && signerIdentity != nil
    }
}
