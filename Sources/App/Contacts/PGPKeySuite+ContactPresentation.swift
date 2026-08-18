import Foundation

extension PGPKeySuite {
    /// Contact-key presentation. A contact's public certificate exposes message
    /// compatibility but not private-key custody, so contact surfaces avoid the
    /// key-family vocabulary used for the user's own keys. The buckets follow
    /// the compatibility story: v4 suites are the GnuPG-compatible ones,
    /// composite suites are post-quantum, and the remaining v6 suites are
    /// modern.
    var contactKeyKindDisplayName: String {
        switch self {
        case .ed25519LegacyCurve25519Legacy, .ecdsaNistP256EcdhNistP256V4:
            String(localized: "contactKey.compatible.name", defaultValue: "GnuPG Compatible")
        case .ed25519X25519, .ecdsaNistP256EcdhNistP256, .ed448X448:
            String(localized: "contactKey.modern.name", defaultValue: "Modern (RFC 9580)")
        case .mlDsa65Ed25519MlKem768X25519, .mlDsa87Ed448MlKem1024X448:
            String(localized: "contactKey.postQuantum.name", defaultValue: "Post-Quantum (RFC 9980)")
        }
    }
}
