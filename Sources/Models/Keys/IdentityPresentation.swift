import Foundation

/// Shared formatting and parsing helpers for fingerprints, key IDs, and user IDs.
enum IdentityPresentation {
    /// The two OpenPGP fingerprint forms this app ever handles, distinguished by
    /// their hex length. The form decides which end of the fingerprint carries
    /// the Key ID, so the fingerprint string alone is enough to derive it —
    /// exactly how the OpenPGP engine reads a bare fingerprint.
    private enum FingerprintForm {
        /// 20-byte SHA-1 fingerprint. The Key ID is its low-order 64 bits.
        case v4
        /// 32-byte SHA-256 fingerprint. The Key ID is its high-order 64 bits.
        case v6

        init?(hexCharacterCount: Int) {
            switch hexCharacterCount {
            case 40:
                self = .v4
            case 64:
                self = .v6
            default:
                return nil
            }
        }
    }

    /// The 16-hex-character short Key ID for a fingerprint.
    ///
    /// A v4 Key ID is the *last* 64 bits of the fingerprint, while a v6 Key ID
    /// is the *first* 64 bits (RFC 9580 §5.5.4). Taking the wrong end produces
    /// an identifier that no other OpenPGP implementation will recognise, so the
    /// two forms are handled separately. A fingerprint of any other length is
    /// not a shape this app produces; it is returned unchanged rather than
    /// sliced into a Key ID that would be a fabrication.
    static func shortKeyId(from fingerprint: String) -> String {
        switch FingerprintForm(hexCharacterCount: fingerprint.count) {
        case .v4:
            return String(fingerprint.suffix(16))
        case .v6:
            return String(fingerprint.prefix(16))
        case nil:
            return fingerprint
        }
    }

    static func formattedFingerprint(_ fingerprint: String) -> String {
        fingerprintGroups(fingerprint).joined(separator: " ")
    }

    static func fingerprintGroups(_ fingerprint: String) -> [String] {
        stride(from: 0, to: fingerprint.count, by: 4).map { offset in
            let start = fingerprint.index(fingerprint.startIndex, offsetBy: offset)
            let end = fingerprint.index(start, offsetBy: min(4, fingerprint.count - offset))
            return String(fingerprint[start..<end])
        }
    }

    static func fingerprintAccessibilityGroupLabel(_ group: String) -> String {
        group.map(String.init).joined(separator: " ")
    }

    static func parsedDisplayName(from userId: String?) -> String? {
        guard let userId else { return nil }
        if let angleBracketIndex = userId.firstIndex(of: "<") {
            let name = userId[userId.startIndex..<angleBracketIndex]
                .trimmingCharacters(in: .whitespaces)
            return name.isEmpty ? userId : name
        }

        return userId
    }

    static func email(from userId: String?) -> String? {
        guard let userId,
              let start = userId.firstIndex(of: "<"),
              let end = userId.firstIndex(of: ">") else {
            return nil
        }

        let emailStart = userId.index(after: start)
        guard emailStart < end else { return nil }
        return String(userId[emailStart..<end])
    }
}
