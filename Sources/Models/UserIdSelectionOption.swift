import Foundation

/// App-owned selector-bearing metadata for one discovered User ID packet.
struct UserIdSelectionOption: Equatable, Hashable {
    /// 0-based occurrence index in the certificate's native User ID order.
    let occurrenceIndex: Int

    /// Raw User ID packet bytes used as the existing crypto selector input.
    let userIdData: Data

    /// Display-only lossy/best-effort text rendering of `userIdData`.
    let displayText: String

    /// Display-oriented current primary flag.
    let isCurrentlyPrimary: Bool

    /// Display-oriented current revocation state.
    let isCurrentlyRevoked: Bool
}
