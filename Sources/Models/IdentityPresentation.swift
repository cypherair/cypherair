import Foundation

/// Shared presentation helpers for fingerprints, key IDs, and user IDs.
enum IdentityPresentation {
    static func shortKeyId(from fingerprint: String) -> String {
        String(fingerprint.suffix(16))
    }

    static func formattedFingerprint(_ fingerprint: String) -> String {
        stride(from: 0, to: fingerprint.count, by: 4).map { offset in
            let start = fingerprint.index(fingerprint.startIndex, offsetBy: offset)
            let end = fingerprint.index(start, offsetBy: min(4, fingerprint.count - offset))
            return String(fingerprint[start..<end])
        }.joined(separator: " ")
    }

    static func fingerprintAccessibilityLabel(_ fingerprint: String) -> String {
        formattedFingerprint(fingerprint)
            .split(separator: " ")
            .map { group in
                group.map(String.init).joined(separator: " ")
            }
            .joined(separator: ", ")
    }

    static func displayName(from userId: String?) -> String {
        guard let userId else {
            return String(localized: "contact.unknown", defaultValue: "Unknown")
        }

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
