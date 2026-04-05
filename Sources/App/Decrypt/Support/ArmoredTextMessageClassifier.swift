import Foundation

enum ArmoredTextMessageClassification: Equatable {
    case encryptedTextMessage
    case other
}

enum ArmoredTextMessageClassifier {
    static let maxInspectableFileSize = 256 * 1024

    static func classify(fileSize: Int, data: Data) -> ArmoredTextMessageClassification {
        guard fileSize <= maxInspectableFileSize else {
            return .other
        }

        guard let text = String(data: data, encoding: .utf8) else {
            return .other
        }

        return normalizedLeadingText(text).hasPrefix("-----BEGIN PGP MESSAGE-----")
            ? .encryptedTextMessage
            : .other
    }

    private static func normalizedLeadingText(_ text: String) -> String {
        var normalized = text
        if normalized.hasPrefix("\u{FEFF}") {
            normalized.removeFirst()
        }
        return String(normalized.drop(while: { $0.isWhitespace }))
    }
}
