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
        let signerPrimaryFingerprint: String?
        let signerIdentity: SignatureVerification.SignerIdentity?
    }

    let legacyStatus: SignatureStatus
    let legacySignerFingerprint: String?
    let legacySignerContact: Contact?
    let legacySignerIdentity: SignatureVerification.SignerIdentity?
    let signatures: [Entry]

    var legacyVerification: SignatureVerification {
        SignatureVerification(
            status: legacyStatus,
            signerFingerprint: legacySignerFingerprint,
            signerContact: legacySignerContact,
            signerIdentity: legacySignerIdentity
        )
    }
}
