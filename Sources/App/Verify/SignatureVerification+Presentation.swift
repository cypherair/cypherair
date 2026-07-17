import SwiftUI

extension SignatureVerification {
    /// SF Symbol name for the status indicator.
    var symbolName: String {
        switch verificationState {
        case .verified: "checkmark.seal.fill"
        case .invalid: "xmark.seal.fill"
        case .signerCertificateUnavailable: "person.crop.circle.badge.questionmark"
        case .contactsContextUnavailable: "lock.badge.clock"
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
        case .notSigned: .secondary
        case .expired: .orange
        }
    }

    /// User-facing status description.
    var statusDescription: String {
        switch verificationState {
        case .verified:
            if let signerIdentity {
                String(
                    localized: "signature.valid.known",
                    defaultValue: "Valid signature from \(signerIdentity.presentationDisplayName)"
                )
            } else if let fp = signerFingerprint {
                String(
                    localized: "signature.valid.fingerprint",
                    defaultValue: "Valid signature from \(String(fp.suffix(16)))"
                )
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
        case .notSigned:
            String(localized: "signature.none", defaultValue: "This message was not signed")
        }
    }
}

extension SignatureVerification.SignerIdentity {
    var sourceLabel: String {
        switch source {
        case .contact:
            isVerifiedContact
                ? String(localized: "signature.identity.contact", defaultValue: "Contact")
                : String(localized: "signature.identity.contact.unverified", defaultValue: "Unverified Contact")
        case .ownKey:
            String(localized: "signature.identity.ownKey", defaultValue: "Your Key")
        case .unknown:
            String(localized: "signature.identity.unknown", defaultValue: "Unknown Signer")
        }
    }

    var presentationDisplayName: String {
        switch source {
        case .contact:
            return IdentityDisplayPresentation.displayName(displayName)
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
}
