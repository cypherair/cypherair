import SwiftUI

/// App-level signature verification result for display in the UI.
/// Wraps the UniFFI `SignatureStatus` with user-facing information.
struct SignatureVerification {
    enum VerificationState: Equatable {
        case notSigned
        case verified
        case invalid
        case expired
        case signerCertificateUnavailable
        case contactsContextUnavailable
        case signerEvidenceUnavailable
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

        var sourceLabel: String {
            switch source {
            case .contact:
                return isVerifiedContact
                    ? String(localized: "signature.identity.contact", defaultValue: "Contact")
                    : String(localized: "signature.identity.contact.unverified", defaultValue: "Unverified Contact")
            case .ownKey:
                return String(localized: "signature.identity.ownKey", defaultValue: "Your Key")
            case .unknown:
                return String(localized: "signature.identity.unknown", defaultValue: "Unknown Signer")
            }
        }

        var verificationNote: String? {
            guard source == .contact, !isVerifiedContact else { return nil }
            return String(
                localized: "signature.identity.contact.unverified.note",
                defaultValue: "This signer matches a contact in your address book, but you have not verified that contact's fingerprint yet."
            )
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
                    displayName: String(localized: "signature.identity.ownKey", defaultValue: "Your Key"),
                    secondaryText: ownKey.userId ?? ownKey.shortKeyId,
                    shortKeyId: ownKey.shortKeyId,
                    fingerprint: ownKey.fingerprint,
                    isVerifiedContact: true
                )
            }

            return SignerIdentity(
                source: .unknown,
                displayName: String(localized: "signature.identity.unknown", defaultValue: "Unknown Signer"),
                secondaryText: nil,
                shortKeyId: IdentityPresentation.shortKeyId(from: fingerprint),
                fingerprint: fingerprint,
                isVerifiedContact: false
            )
        }
    }

    /// The graded verification result.
    let status: SignatureStatus

    /// App-level verification state that separates crypto verification from Contacts availability.
    let verificationState: VerificationState

    /// Fingerprint of the signer, if known.
    let signerFingerprint: String?

    /// The contact who signed (resolved from fingerprint), if available.
    let signerContact: Contact?

    let signerIdentity: SignerIdentity?

    let signerEvidence: SignerEvidence?

    let contactsUnavailableReason: ContactsAvailability?

    var requiresContactsContext: Bool {
        verificationState == .contactsContextUnavailable
    }

    init(
        status: SignatureStatus,
        signerFingerprint: String?,
        signerContact: Contact?,
        signerIdentity: SignerIdentity? = nil,
        verificationState: VerificationState? = nil,
        signerEvidence: SignerEvidence? = nil,
        contactsUnavailableReason: ContactsAvailability? = nil
    ) {
        self.status = status
        self.verificationState = verificationState ?? VerificationState(legacyStatus: status)
        self.signerFingerprint = signerFingerprint
        self.signerContact = signerContact
        self.signerEvidence = signerEvidence
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
                displayName: String(localized: "signature.identity.unknown", defaultValue: "Unknown Signer"),
                secondaryText: nil,
                shortKeyId: IdentityPresentation.shortKeyId(from: $0),
                fingerprint: $0,
                isVerifiedContact: false
            )
        }
    }

    /// SF Symbol name for the status indicator.
    var symbolName: String {
        switch verificationState {
        case .verified: "checkmark.seal.fill"
        case .invalid: "xmark.seal.fill"
        case .signerCertificateUnavailable: "person.crop.circle.badge.questionmark"
        case .contactsContextUnavailable: "lock.badge.clock"
        case .signerEvidenceUnavailable: "questionmark.circle.fill"
        case .notSigned: "minus.circle"
        case .expired: "clock.badge.exclamationmark"
        }
    }

    /// Color for the status indicator.
    var statusColor: Color {
        switch verificationState {
        case .verified: .green
        case .invalid: .red
        case .signerCertificateUnavailable: .orange
        case .contactsContextUnavailable: .orange
        case .signerEvidenceUnavailable: .orange
        case .notSigned: .secondary
        case .expired: .orange
        }
    }

    /// User-facing status description.
    var statusDescription: String {
        switch verificationState {
        case .verified:
            if let signerIdentity {
                String(localized: "signature.valid.known",
                       defaultValue: "Valid signature from \(signerIdentity.displayName)")
            } else if let fp = signerFingerprint {
                String(localized: "signature.valid.fingerprint",
                       defaultValue: "Valid signature from \(String(fp.suffix(16)))")
            } else {
                String(localized: "signature.valid", defaultValue: "Valid signature")
            }
        case .invalid:
            String(localized: "signature.bad", defaultValue: "Signature verification failed — content may have been modified")
        case .expired:
            String(localized: "signature.expired", defaultValue: "Signed by an expired key — ask the sender to update their key")
        case .signerCertificateUnavailable:
            String(
                localized: "signature.signerCertificateUnavailable",
                defaultValue: "Signer certificate unavailable — signature could not be verified"
            )
        case .contactsContextUnavailable:
            String(
                localized: "signature.contactsContextUnavailable",
                defaultValue: "Contacts verification context is unavailable — signer cannot be verified yet"
            )
        case .signerEvidenceUnavailable:
            String(
                localized: "signature.signerEvidenceUnavailable",
                defaultValue: "Signer evidence unavailable — signature could not be matched to a key"
            )
        case .notSigned:
            String(localized: "signature.none", defaultValue: "This message was not signed")
        }
    }

    /// Whether this status represents a security concern.
    var isWarning: Bool {
        switch verificationState {
        case .invalid, .expired, .signerCertificateUnavailable,
             .contactsContextUnavailable, .signerEvidenceUnavailable:
            true
        case .verified, .notSigned:
            false
        }
    }

    var shouldShowSignerIdentity: Bool {
        verificationState != .notSigned && signerIdentity != nil
    }
}
