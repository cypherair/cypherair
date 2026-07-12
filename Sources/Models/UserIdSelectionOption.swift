import Foundation

/// App-owned selector-bearing metadata for one discovered User ID packet.
struct UserIdSelectionOption: Equatable, Hashable {
    /// 0-based occurrence index in the certificate's native User ID order.
    /// Together with `userIdData`, this identifies one concrete User ID occurrence.
    let occurrenceIndex: Int

    /// Raw User ID packet bytes used as the cryptographic selector content.
    /// Together with `occurrenceIndex`, this identifies one concrete User ID occurrence.
    let userIdData: Data

    /// Display-only lossy/best-effort text rendering of `userIdData`.
    let displayText: String

    /// Display-oriented current primary flag.
    let isCurrentlyPrimary: Bool

    /// Display-oriented current revocation state.
    let isCurrentlyRevoked: Bool

    /// Whether this User ID carries a valid self-certification binding it to the
    /// certificate's primary key. A raw User ID packet without one is an
    /// unauthenticated identity claim: nothing proves the key holder made it.
    let isSelfCertified: Bool

}
