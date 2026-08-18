import Foundation

/// A contact key seen in the role of a certification's signer.
struct ContactCertificationContactSigner: Equatable, Hashable, Sendable {
    let fingerprint: String
    let displayName: String
    let secondaryText: String?

    /// The user verified this contact's fingerprint themselves.
    let isVerifiedByUser: Bool

    /// Whether certifications made by this key currently count for anything —
    /// `ContactVouchingPolicy`'s answer, resolved at the same moment as the rest
    /// of the role. A verified contact whose key has since been revoked is
    /// verified and weightless at the same time, and the UI says so.
    let carriesVouchingWeight: Bool

    var voucher: ContactKeyVoucher {
        ContactKeyVoucher(fingerprint: fingerprint, displayName: displayName)
    }
}

/// Who made a certification, resolved against what the user holds right now.
///
/// One vocabulary covers every certification the app shows. A signature just
/// verified and one saved months ago are described by the same words because
/// both are resolved live from the same anchor set — the saved one is not a
/// remembered verdict with a bare key ID attached to it.
enum ContactCertificationSignerRole: Equatable, Hashable, Sendable {
    /// One of the user's own keys. Their own act, not a third party vouching for
    /// the contact, and never counted as one.
    case you(fingerprint: String, displayName: String)

    /// The certified key signing itself. A self-signature is part of what an
    /// OpenPGP certificate *is*; it attests nothing beyond the certificate's own
    /// claim about itself, and no one else stands behind it.
    case targetKeyItself(fingerprint: String)

    /// A contact key the user holds. Whether it carries weight is the signer's
    /// own `carriesVouchingWeight`.
    case contact(ContactCertificationContactSigner)

    /// No key the user holds matches the signer, so there is nothing to say
    /// about who they are.
    case unknown(fingerprint: String)

    var fingerprint: String {
        switch self {
        case .you(let fingerprint, _):
            fingerprint
        case .targetKeyItself(let fingerprint):
            fingerprint
        case .contact(let signer):
            signer.fingerprint
        case .unknown(let fingerprint):
            fingerprint
        }
    }

    /// The contact whose word this certification carries, if it carries anyone's.
    var voucher: ContactKeyVoucher? {
        guard case .contact(let signer) = self, signer.carriesVouchingWeight else {
            return nil
        }
        return signer.voucher
    }
}
