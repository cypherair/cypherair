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

        static func resolve(
            fingerprint: String?,
            contactKeys: [ContactKeyRecord],
            ownKeys: [PGPKeyIdentity]
        ) -> SignerIdentity? {
            guard let fingerprint else { return nil }

            if let contactKey = contactKeys.first(where: { $0.fingerprint == fingerprint }) {
                return SignerIdentity(
                    source: .contact,
                    displayName: contactKey.displayName,
                    secondaryText: contactKey.email ?? contactKey.primaryUserId,
                    shortKeyId: IdentityPresentation.shortKeyId(from: contactKey.fingerprint),
                    fingerprint: contactKey.fingerprint,
                    isVerifiedContact: contactKey.manualVerificationState.isVerified
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

    /// App-level verification state that separates crypto verification from Contacts availability.
    let verificationState: VerificationState

    /// Fingerprint of the signer, if known.
    let signerFingerprint: String?

    let signerIdentity: SignerIdentity?

    let contactsUnavailableReason: ContactsAvailability?

    var requiresContactsContext: Bool {
        verificationState == .contactsContextUnavailable
    }

    init(
        signerFingerprint: String?,
        signerIdentity: SignerIdentity? = nil,
        verificationState: VerificationState,
        contactsUnavailableReason: ContactsAvailability? = nil
    ) {
        self.verificationState = verificationState
        self.signerFingerprint = signerFingerprint
        self.contactsUnavailableReason = contactsUnavailableReason
        self.signerIdentity = signerIdentity ?? signerFingerprint.map {
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
