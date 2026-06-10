import Foundation

/// Message-signature verification result carrying the folded summary state plus the detailed
/// per-signature outcomes used by the UI.
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
    /// `summaryState`; `status` is derived from the state so the two cannot disagree. `summaryState`
    /// may legitimately be `.invalid`/`.expired` with empty `signatures` (e.g. a malformed signed
    /// message whose verifier setup failed), so this must not collapse to "not signed".
    var summaryVerification: SignatureVerification {
        SignatureVerification(
            status: MessageSignatureStatus(verificationState: summaryState),
            signerFingerprint: nil,
            verificationState: summaryState,
            contactsUnavailableReason: contactsUnavailableReason
        )
    }

}

extension SignatureVerification.VerificationState {
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

extension MessageSignatureStatus {
    /// Graded status consistent with a verification state, for display models that still carry a
    /// `status` field alongside `verificationState`. The dual-field redundancy is tracked for a later
    /// "collapse the signature state model" cleanup (see docs/LEGACY_CLEANUP.md "Follow-Ups Outside
    /// This Roadmap").
    init(verificationState: SignatureVerification.VerificationState) {
        switch verificationState {
        case .verified:
            self = .valid
        case .invalid:
            self = .bad
        case .expired:
            self = .expired
        case .notSigned:
            self = .notSigned
        case .signerCertificateUnavailable, .contactsContextUnavailable:
            self = .unknownSigner
        }
    }
}
