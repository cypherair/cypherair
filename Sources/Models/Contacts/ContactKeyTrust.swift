import Foundation

/// A contact whose own key the user personally verified, and whose certification
/// therefore carries weight over some other key.
struct ContactKeyVoucher: Identifiable, Equatable, Hashable, Sendable {
    var id: String { fingerprint }

    let fingerprint: String
    let displayName: String
}

/// What CypherAir is willing to assert about one contact key.
///
/// Both members are derived from the anchor set as it stands at the moment of
/// the read: the user's own fingerprint verifications, and — one hop out — the
/// certifications made by the contacts those verifications cover. Nothing here
/// is ever stored. A persisted answer would outlive the verification it rests
/// on, and withdrawing a verification has to drop the weight of everything
/// anchored on it at once; deriving it every time is what makes that true by
/// construction rather than by remembering to invalidate something.
struct ContactKeyTrust: Equatable, Hashable, Sendable {
    /// The user checked this key's fingerprint against its owner themselves.
    let isVerifiedByUser: Bool

    /// Contacts the user personally verified that have certified this key with a
    /// signature that still verifies. Empty unless something is anchored — a
    /// certification from an unverified signer never appears here.
    let vouchers: [ContactKeyVoucher]

    static let unanchored = ContactKeyTrust(isVerifiedByUser: false, vouchers: [])

    /// The strongest single statement the app is entitled to make about the key.
    ///
    /// Vouching never merges into the user's own verification: it is somebody
    /// else's word, and the two are separate cases so no surface can render them
    /// as the same badge.
    var anchor: Anchor {
        if isVerifiedByUser {
            return .verifiedByUser
        }
        if let voucher = vouchers.first {
            return .vouched(by: voucher, otherVoucherCount: vouchers.count - 1)
        }
        return .unanchored
    }

    enum Anchor: Equatable, Hashable, Sendable {
        /// The user verified this fingerprint themselves.
        case verifiedByUser
        /// A contact the user verified has certified this key.
        case vouched(by: ContactKeyVoucher, otherVoucherCount: Int)
        /// Nothing the app knows about this key traces back to the user.
        case unanchored
    }
}
