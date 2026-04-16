import Foundation

/// App-owned selector-bearing metadata for one discovered subkey.
struct SubkeySelectionOption: Equatable, Hashable {
    /// Canonical lowercase-hex subkey fingerprint.
    let fingerprint: String

    /// Display-only algorithm label from the FFI surface.
    let algorithmDisplay: String

    /// Display-oriented current transport-encryption capability.
    let isCurrentlyTransportEncryptionCapable: Bool

    /// Display-oriented current revocation state.
    let isCurrentlyRevoked: Bool

    /// Display-oriented current expiry state.
    let isCurrentlyExpired: Bool
}
