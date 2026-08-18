import Foundation

/// The app's only passphrase strength estimate. Pure, deterministic, and
/// entirely offline — no corpus download, no network path, no SDK.
///
/// **The model.** Every character costs `log2(alphabet)` bits, where the
/// alphabet is the union of the character classes the passphrase actually uses.
/// A character that falls inside a pattern the estimator recognises — a token
/// from `CommonPassphraseTokens`, a repeat, a walk along the alphabet or a
/// keyboard row, a plausible year, a run confined to one character class — is
/// charged that pattern's much smaller cost instead. A short dynamic program
/// then picks the cheapest way to cover the whole string, so recognising a
/// pattern can only ever lower a score, never raise one.
///
/// **What it sees.** Short passphrases, repeated and sequential ones, keyboard
/// walks, and the well-known words that lead every breach corpus — which is the
/// list NIST SP 800-63B asks a verifier to refuse, and it is the list that
/// guessing attacks actually work through.
///
/// **What it does not see.** It cannot tell a remembered English or Chinese
/// phrase from the same number of random characters. Distinguishing those needs
/// word-frequency corpora measured in megabytes, and this app ships no corpus
/// and downloads nothing. The estimate is therefore a search-space figure, and
/// the honest response to that limit is not a cleverer heuristic — it is
/// `PassphraseGenerator`, offered first wherever a passphrase is chosen, whose
/// output is uniform and needs no corpus to be believed.
///
/// Where the model is unsure it charges less, so the gate refuses passphrases
/// it cannot vouch for rather than admitting ones it cannot read.
enum PassphraseStrengthEstimator {
    static func estimate(_ passphrase: String) -> PassphraseStrength {
        let characters = Array(passphrase)
        guard !characters.isEmpty else {
            return PassphraseStrength(bits: 0, tier: .empty)
        }

        let classes = characters.map(characterClass(of:))
        let bitsPerCharacter = log2(Double(alphabetSize(of: classes)))
        let lowered = characters.map(lowercasedCharacter)
        let folded = lowered.map { leetSubstitutions[$0] ?? $0 }

        var matches = commonTokenMatches(in: folded)
        matches += repeatMatches(in: folded, bitsPerCharacter: bitsPerCharacter)
        matches += alphabetWalkMatches(in: lowered)
        matches += keyboardWalkMatches(in: lowered)
        matches += yearMatches(in: characters)
        matches += singleClassRunMatches(in: classes)

        let bits = cheapestCover(
            length: characters.count,
            bitsPerCharacter: bitsPerCharacter,
            matches: matches
        )
        return PassphraseStrength(bits: bits, tier: tier(forBits: bits))
    }

    // MARK: - Verdict

    /// Bit thresholds for the meter. `good` is where the gate opens: below it a
    /// passphrase is short enough, or predictable enough, that an attacker
    /// holding the protected artifact can work through the possibilities
    /// offline. In practice the bar asks for roughly sixteen lowercase letters,
    /// or twelve characters once cases, digits and punctuation are mixed.
    private static func tier(forBits bits: Double) -> PassphraseStrengthTier {
        switch bits {
        case ..<45:
            .veryWeak
        case ..<75:
            .weak
        case ..<105:
            .good
        default:
            .strong
        }
    }

    // MARK: - Cheapest cover

    /// A stretch of the passphrase the estimator can price for less than
    /// brute force, over the half-open range `start..<end`.
    private struct Match {
        let start: Int
        let end: Int
        let bits: Double
    }

    /// Charged once per recognised pattern, for the arrangement of the pieces
    /// themselves: a passphrase assembled from several known parts still costs
    /// an attacker something to put back together.
    private static let arrangementBits = 2.0

    private static func cheapestCover(
        length: Int,
        bitsPerCharacter: Double,
        matches: [Match]
    ) -> Double {
        var matchesEndingAt = [[Match]](repeating: [], count: length + 1)
        for match in matches where match.end <= length {
            matchesEndingAt[match.end].append(match)
        }

        var cheapest = [Double](repeating: 0, count: length + 1)
        for end in 1...length {
            var best = cheapest[end - 1] + bitsPerCharacter
            for match in matchesEndingAt[end] {
                best = min(best, cheapest[match.start] + match.bits + arrangementBits)
            }
            cheapest[end] = best
        }
        return cheapest[length]
    }

    // MARK: - Matchers

    private static func commonTokenMatches(in folded: [Character]) -> [Match] {
        let count = folded.count
        var matches: [Match] = []
        for start in 0..<count {
            guard let candidates = foldedTokens[folded[start]] else { continue }
            for candidate in candidates where start + candidate.characters.count <= count {
                let end = start + candidate.characters.count
                guard folded[start..<end].elementsEqual(candidate.characters) else { continue }
                matches.append(
                    Match(start: start, end: end, bits: log2(Double(candidate.rank + 2)))
                )
            }
        }
        return matches
    }

    /// `abcabcabc` costs one `abc` plus the count. Periods longer than this are
    /// left to brute force; a passphrase built by repeating a 17-character unit
    /// is not a shape anyone types.
    private static let maximumRepeatPeriod = 16

    private static func repeatMatches(
        in folded: [Character],
        bitsPerCharacter: Double
    ) -> [Match] {
        let count = folded.count
        var matches: [Match] = []
        for period in 1...maximumRepeatPeriod where period * 2 <= count {
            var index = period
            while index < count {
                guard folded[index] == folded[index - period] else {
                    index += 1
                    continue
                }
                var end = index
                while end < count, folded[end] == folded[end - period] {
                    end += 1
                }
                let start = index - period
                let length = end - start
                if length >= period * 2 {
                    let repeats = Double(length) / Double(period)
                    matches.append(
                        Match(
                            start: start,
                            end: end,
                            bits: Double(period) * bitsPerCharacter + log2(repeats)
                        )
                    )
                }
                index = end
            }
        }
        return matches
    }

    private static func alphabetWalkMatches(in lowered: [Character]) -> [Match] {
        let coordinates: [WalkCoordinate?] = lowered.map { character in
            guard character.unicodeScalars.count == 1,
                  let scalar = character.unicodeScalars.first else {
                return nil
            }
            switch scalar.value {
            case 0x61...0x7A:
                return WalkCoordinate(space: 0, position: Int(scalar.value - 0x61))
            case 0x30...0x39:
                return WalkCoordinate(space: 1, position: Int(scalar.value - 0x30))
            default:
                return nil
            }
        }
        return walkMatches(over: coordinates) { length, space in
            let alphabet = space == 0 ? 26.0 : 10.0
            return log2(alphabet) + log2(Double(length)) + 1
        }
    }

    /// Rows as they sit under the fingers on a US keyboard; `qwerty` and `asdf`
    /// are walks along them, not random text.
    private static let keyboardRows = [
        Array("1234567890-="),
        Array("qwertyuiop[]\\"),
        Array("asdfghjkl;'"),
        Array("zxcvbnm,./"),
    ]

    private static let keyboardCoordinates: [Character: WalkCoordinate] = {
        var coordinates: [Character: WalkCoordinate] = [:]
        for (row, characters) in keyboardRows.enumerated() {
            for (column, character) in characters.enumerated() {
                coordinates[character] = WalkCoordinate(space: row, position: column)
            }
        }
        return coordinates
    }()

    private static func keyboardWalkMatches(in lowered: [Character]) -> [Match] {
        let coordinates = lowered.map { keyboardCoordinates[$0] }
        let rowChoices = log2(Double(keyboardRows.count))
        let startChoices = log2(Double(keyboardRows.map(\.count).max() ?? 1))
        return walkMatches(over: coordinates) { length, _ in
            rowChoices + startChoices + log2(Double(length)) + 1
        }
    }

    private static func yearMatches(in characters: [Character]) -> [Match] {
        let digits: [Int?] = characters.map { character in
            guard let value = character.wholeNumberValue, (0...9).contains(value) else {
                return nil
            }
            return value
        }
        guard digits.count >= 4 else { return [] }
        var matches: [Match] = []
        for start in 0...(digits.count - 4) {
            let window = digits[start..<(start + 4)].compactMap { $0 }
            guard window.count == 4 else { continue }
            let year = window.reduce(0) { $0 * 10 + $1 }
            guard (1900...2099).contains(year) else { continue }
            matches.append(Match(start: start, end: start + 4, bits: log2(200)))
        }
        return matches
    }

    /// A stretch drawn from one character class costs that class's own
    /// alphabet, not the union: four digits inside a passphrase that also uses
    /// letters and punctuation are still only four digits.
    private static func singleClassRunMatches(in classes: [CharacterClass]) -> [Match] {
        var matches: [Match] = []
        var start = 0
        while start < classes.count {
            var end = start + 1
            while end < classes.count, classes[end] == classes[start] {
                end += 1
            }
            let length = end - start
            if length >= 3 {
                matches.append(
                    Match(
                        start: start,
                        end: end,
                        bits: Double(length) * log2(Double(classes[start].alphabetSize)) + 1
                    )
                )
            }
            start = end
        }
        return matches
    }

    // MARK: - Walks

    private struct WalkCoordinate {
        let space: Int
        let position: Int
    }

    /// Maximal stretches that step one position at a time, in a consistent
    /// direction, through a single ordered space.
    private static func walkMatches(
        over coordinates: [WalkCoordinate?],
        bits: (_ length: Int, _ space: Int) -> Double
    ) -> [Match] {
        let count = coordinates.count
        var matches: [Match] = []
        var start = 0
        while start < count {
            guard let head = coordinates[start] else {
                start += 1
                continue
            }
            var previous = head
            var step: Int?
            var end = start + 1
            while end < count, let next = coordinates[end], next.space == head.space {
                let delta = next.position - previous.position
                guard delta == 1 || delta == -1, step == nil || step == delta else { break }
                step = delta
                previous = next
                end += 1
            }
            let length = end - start
            if length >= 3 {
                matches.append(Match(start: start, end: end, bits: bits(length, head.space)))
            }
            start = max(start + 1, end - 1)
        }
        return matches
    }

    // MARK: - Alphabet

    private enum CharacterClass {
        case lowercase
        case uppercase
        case digit
        case asciiSymbol
        case space
        case ideograph
        case other

        /// How many characters an attacker has to consider per position.
        ///
        /// The ASCII figures are the real counts. `ideograph` is far below the
        /// size of any common-character set: Chinese passphrases are drawn from
        /// a small, heavily skewed slice of it, and the gate is better off
        /// undercounting than flattering.
        var alphabetSize: Int {
            switch self {
            case .lowercase, .uppercase:
                26
            case .digit:
                10
            case .asciiSymbol:
                32
            case .space:
                1
            case .ideograph:
                512
            case .other:
                256
            }
        }
    }

    private static func alphabetSize(of classes: [CharacterClass]) -> Int {
        var present = Set<CharacterClass>()
        for characterClass in classes {
            present.insert(characterClass)
        }
        return max(2, present.reduce(0) { $0 + $1.alphabetSize })
    }

    private static func characterClass(of character: Character) -> CharacterClass {
        guard character.unicodeScalars.count == 1,
              let scalar = character.unicodeScalars.first else {
            return .other
        }
        switch scalar.value {
        case 0x61...0x7A:
            return .lowercase
        case 0x41...0x5A:
            return .uppercase
        case 0x30...0x39:
            return .digit
        case 0x20:
            return .space
        case 0x21...0x2F, 0x3A...0x40, 0x5B...0x60, 0x7B...0x7E:
            return .asciiSymbol
        case 0x3400...0x4DBF, 0x4E00...0x9FFF, 0xF900...0xFAFF, 0x20000...0x3FFFF:
            return .ideograph
        default:
            return .other
        }
    }

    // MARK: - Folding

    /// Substitutions that hide a word without making it harder to guess.
    private static let leetSubstitutions: [Character: Character] = [
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
        "@": "a", "$": "s", "!": "i", "|": "l",
    ]

    private static func lowercasedCharacter(_ character: Character) -> Character {
        let lowercased = character.lowercased()
        guard lowercased.count == 1, let single = lowercased.first else {
            return character
        }
        return single
    }

    private struct FoldedToken {
        let characters: [Character]
        let rank: Int
    }

    /// The token list folded the same way the passphrase is, bucketed by first
    /// character so a scan costs a handful of comparisons per position — this
    /// runs on every keystroke.
    private static let foldedTokens: [Character: [FoldedToken]] = {
        var buckets: [Character: [FoldedToken]] = [:]
        var seen = Set<String>()
        for (rank, token) in CommonPassphraseTokens.ordered.enumerated() {
            let characters = token.map(lowercasedCharacter).map { leetSubstitutions[$0] ?? $0 }
            guard characters.count >= CommonPassphraseTokens.minimumLength,
                  let first = characters.first,
                  seen.insert(String(characters)).inserted else {
                continue
            }
            buckets[first, default: []].append(FoldedToken(characters: characters, rank: rank))
        }
        return buckets
    }()
}
