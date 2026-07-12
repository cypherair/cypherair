import Foundation

/// Message-signature verification result carrying the folded summary state plus the detailed
/// per-signature outcomes used by the UI.
struct DetailedSignatureVerification: Equatable {
    struct Entry: Equatable {
        let verificationState: SignatureVerification.VerificationState
        let signerPrimaryFingerprint: String?
        let contactsUnavailableReason: ContactsAvailability?
        let signerIdentity: SignatureVerification.SignerIdentity?

        init(
            verificationState: SignatureVerification.VerificationState,
            signerPrimaryFingerprint: String?,
            contactsUnavailableReason: ContactsAvailability? = nil,
            signerIdentity: SignatureVerification.SignerIdentity?
        ) {
            self.verificationState = verificationState
            self.signerPrimaryFingerprint = signerPrimaryFingerprint
            self.contactsUnavailableReason = contactsUnavailableReason
            self.signerIdentity = signerIdentity
        }
    }

    let summaryState: SignatureVerification.VerificationState
    let summaryEntryIndex: UInt64?
    let contactsUnavailableReason: ContactsAvailability?
    let signatures: [Entry]

    init(
        summaryState: SignatureVerification.VerificationState,
        summaryEntryIndex: UInt64? = nil,
        contactsUnavailableReason: ContactsAvailability? = nil,
        signatures: [Entry]
    ) {
        self.summaryState = summaryState
        self.summaryEntryIndex = summaryEntryIndex
        self.contactsUnavailableReason = contactsUnavailableReason
        self.signatures = signatures
    }

    /// Single-row verification used when there are no per-signature entries to render. Renders from
    /// `summaryState`, which may legitimately be `.invalid`/`.expired` with empty `signatures`
    /// (e.g. a malformed signed message whose verifier setup failed), so this must not collapse to
    /// "not signed".
    var summaryVerification: SignatureVerification {
        SignatureVerification(
            signerFingerprint: nil,
            verificationState: summaryState,
            contactsUnavailableReason: contactsUnavailableReason
        )
    }

}
