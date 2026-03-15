import Foundation

/// App-level signature verification result for display in the UI.
/// Wraps the UniFFI `SignatureStatus` with user-facing information.
struct SignatureVerification {
    /// The graded verification result.
    let status: SignatureStatus

    /// Fingerprint of the signer, if known.
    let signerFingerprint: String?

    /// The contact who signed (resolved from fingerprint), if available.
    var signerContact: Contact?

    /// SF Symbol name for the status indicator.
    var symbolName: String {
        switch status {
        case .valid: "checkmark.seal.fill"
        case .bad: "xmark.seal.fill"
        case .unknownSigner: "questionmark.circle.fill"
        case .notSigned: "minus.circle"
        case .expired: "clock.badge.exclamationmark"
        }
    }

    /// Color name for the status indicator.
    var statusColor: String {
        switch status {
        case .valid: "green"
        case .bad: "red"
        case .unknownSigner: "orange"
        case .notSigned: "secondary"
        case .expired: "orange"
        }
    }

    /// User-facing status description.
    var statusDescription: String {
        switch status {
        case .valid:
            if let contact = signerContact {
                String(localized: "signature.valid.known",
                       defaultValue: "Valid signature from \(contact.displayName)")
            } else if let fp = signerFingerprint {
                String(localized: "signature.valid.fingerprint",
                       defaultValue: "Valid signature from \(String(fp.suffix(16)))")
            } else {
                String(localized: "signature.valid", defaultValue: "Valid signature")
            }
        case .bad:
            String(localized: "signature.bad", defaultValue: "Signature verification failed — content may have been modified")
        case .unknownSigner:
            String(localized: "signature.unknown", defaultValue: "Signed by an unknown key — signer not in your contacts")
        case .notSigned:
            String(localized: "signature.none", defaultValue: "This message was not signed")
        case .expired:
            String(localized: "signature.expired", defaultValue: "Signed by an expired key — ask the sender to update their key")
        }
    }

    /// Whether this status represents a security concern.
    var isWarning: Bool {
        switch status {
        case .bad: true
        case .unknownSigner: true
        case .expired: true
        default: false
        }
    }
}
