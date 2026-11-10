import Foundation
internal import Sealing

/// The rule for every passphrase the user chooses: the unlock passphrase and
/// every backup. A passphrase that already protects something is never checked.
public enum Passphrase {
    public static let minimumLength = 12

    public static func problems(in passphrase: String) -> [PassphraseProblem] {
        var problems: [PassphraseProblem] = []
        if passphrase.count < minimumLength {
            problems.append(.tooShort)
        }
        if hasRunOfThree(passphrase) {
            problems.append(.repeatedCharacter)
        }
        return problems
    }

    /// Twenty characters from 56 that cannot be mistaken for one another, about
    /// 116 bits, in four groups.
    public static func suggestion() -> String {
        let alphabet = Array("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        var generator = SystemRandomNumberGenerator()
        while true {
            let groups = (0..<4).map { _ in String((0..<5).map { _ in alphabet.randomElement(using: &generator)! }) }
            let candidate = groups.joined(separator: "-")
            if problems(in: candidate).isEmpty {
                return candidate
            }
        }
    }

    private static func hasRunOfThree(_ text: String) -> Bool {
        var previous: Character?
        var run = 0
        for character in text {
            run = character == previous ? run + 1 : 1
            if run == 3 { return true }
            previous = character
        }
        return false
    }
}

public enum PassphraseProblem: Sendable, Hashable {
    /// Shorter than `Passphrase.minimumLength` characters.
    case tooShort
    /// One character three times in a row.
    case repeatedCharacter
}

extension SensitiveBuffer {
    /// A passphrase's UTF-8 bytes in canonical composed form, so the same
    /// characters typed on another keyboard give the same bytes.
    static func passphrase(_ text: String) -> SensitiveBuffer {
        var bytes = Data(text.precomposedStringWithCanonicalMapping.utf8)
        return SensitiveBuffer(consuming: &bytes)
    }
}
