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

}
