import Foundation

extension PGPKeyProfile {
    /// Contact-key presentation. A contact's public certificate exposes message
    /// compatibility but not private-key custody, so contact surfaces avoid the
    /// key-family vocabulary used for the user's own keys.
    var contactKeyKindDisplayName: String {
        switch self {
        case .universal:
            String(localized: "contactKey.compatible.name", defaultValue: "GnuPG Compatible")
        case .modern, .advanced:
            String(localized: "contactKey.modern.name", defaultValue: "Modern (RFC 9580)")
        case .postQuantum, .postQuantumHigh:
            String(localized: "contactKey.postQuantum.name", defaultValue: "Post-Quantum (RFC 9980)")
        }
    }
}
