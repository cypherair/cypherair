import Foundation

/// App-owned selector catalog derived from the FFI discovery surface.
struct CertificateSelectionCatalog: Equatable, Hashable {
    /// Primary certificate fingerprint in canonical lowercase hex.
    let certificateFingerprint: String

    /// Discovered subkey selector options in native certificate order.
    let subkeys: [SubkeySelectionOption]

    /// Discovered User ID selector options in native certificate order.
    let userIds: [UserIdSelectionOption]
}
