import Foundation

/// What the app asks of a passphrase the user chooses, and nothing else.
///
/// Two requirements, both of them things a person can check by looking: it is
/// long enough, and it is not one character held down. Deliberately not a
/// strength score — a score invites arguing with a number, and any estimate
/// worth arguing with needs frequency corpora this app will not ship or
/// download. Length is what a passphrase gains resistance from, and the app's
/// real answer to guessability is `PassphraseGenerator`, offered before the
/// field on every screen where a passphrase is chosen.
///
/// Both constants are policy, not physics; they are here to be adjusted in one
/// place.
struct PassphraseRequirements: Equatable, Sendable {
    /// Characters, not bytes: one emoji or one Chinese character counts once.
    static let minimumLength = 12

    /// How many times one character may appear in an unbroken run. At the
    /// default, `aa` passes and `aaa` does not.
    static let maximumConsecutiveRepeats = 2

    let isLongEnough: Bool
    let avoidsRepeatedRuns: Bool

    /// The single question every passphrase surface asks.
    var isSatisfied: Bool { isLongEnough && avoidsRepeatedRuns }

    init(of passphrase: String) {
        let characters = Array(passphrase)
        isLongEnough = characters.count >= Self.minimumLength
        avoidsRepeatedRuns = Self.longestRun(in: characters) <= Self.maximumConsecutiveRepeats
    }

    static func longestRun(in characters: [Character]) -> Int {
        var longest = 0
        var run = 0
        var previous: Character?
        for character in characters {
            run = character == previous ? run + 1 : 1
            previous = character
            longest = max(longest, run)
        }
        return longest
    }
}
