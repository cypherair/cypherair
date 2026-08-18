import Foundation

/// The one answer to "is this a hex identifier", shared by every Security-layer
/// format that names one: a letter-case rule, and a length bound where the
/// format has one. What a caller does with an invalid or mixed-case value —
/// reject it or normalize it — is that caller's decision, stated at its call
/// site.
enum HexIdentifier {
    enum LetterCase {
        /// Only `0-9a-f`.
        case lowercase
        /// `0-9a-fA-F`.
        case either
    }

    static func isValid(_ value: String, letterCase: LetterCase, maximumLength: Int? = nil) -> Bool {
        guard !value.isEmpty else {
            return false
        }
        if let maximumLength, value.utf8.count > maximumLength {
            return false
        }
        return value.utf8.allSatisfy { byte in
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "a")...UInt8(ascii: "f"):
                true
            case UInt8(ascii: "A")...UInt8(ascii: "F"):
                letterCase == .either
            default:
                false
            }
        }
    }
}
