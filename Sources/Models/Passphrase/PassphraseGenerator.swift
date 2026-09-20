import Foundation
import Security

/// Produces a passphrase the user does not have to invent.
///
/// Uniform characters rather than words, for two reasons. A word generator
/// needs a wordlist — several thousand entries, carrying someone else's licence,
/// and only ever in the languages it was built for. And a backup
/// passphrase is written down, not recited, so the property that matters is
/// transcribing it correctly months later — which is what the ambiguity-free
/// alphabet and the short groups are for.
enum PassphraseGenerator {
    /// The secure random source reported failure. There is no weaker source to
    /// fall back to.
    struct RandomSourceFailure: Error {}

    static let groupCount = 5
    static let groupLength = 4

    /// ASCII letters and digits minus the shapes that get read back wrong off
    /// paper — `0`/`O`, `1`/`l`/`I`. 56 characters, 5.8 bits each, so a
    /// generated passphrase is worth about 116 bits.
    static let alphabet = Array(
        "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz".utf8
    )

    /// The returned `String` is the caller's copy to manage; every buffer used
    /// to build it is zeroized here. Swift strings cannot be wiped in place, so
    /// a passphrase that reaches a text field lives as long as that field does
    /// — the same limit that already applies to a typed one.
    static func generate() throws -> String {
        var assembled = Data(capacity: groupCount * (groupLength + 1))
        defer { assembled.zeroize() }

        var randomness = try randomBytes(count: groupCount * groupLength * 2)
        defer { randomness.zeroize() }
        var offset = randomness.startIndex

        for group in 0..<groupCount {
            if group > 0 {
                assembled.append(UInt8(ascii: "-"))
            }
            for _ in 0..<groupLength {
                var position = try index(from: &randomness, offset: &offset)
                while extendsRunPastPolicy(assembled, with: alphabet[position]) {
                    position = try index(from: &randomness, offset: &offset)
                }
                assembled.append(alphabet[position])
            }
        }
        return String(decoding: assembled, as: UTF8.self)
    }

    /// The gate refuses a character repeated more times in a row than
    /// `PassphraseRequirements` allows, so the generator never draws one — its
    /// output satisfies the requirements by construction rather than by luck.
    /// At most one of the 56 characters is ever excluded, so the draw stays
    /// effectively uniform and the redraw always terminates.
    private static func extendsRunPastPolicy(_ assembled: Data, with character: UInt8) -> Bool {
        let limit = PassphraseRequirements.maximumConsecutiveRepeats
        guard limit > 0, assembled.count >= limit else { return false }
        return assembled.suffix(limit).allSatisfy { $0 == character }
    }

    /// One uniform index into `alphabet`, by rejection sampling: bytes at or
    /// above the largest whole multiple of the alphabet size are discarded, so
    /// no character is likelier than any other.
    private static func index(from randomness: inout Data, offset: inout Data.Index) throws -> Int {
        let bound = alphabet.count
        let ceiling = 256 - (256 % bound)
        while true {
            if offset == randomness.endIndex {
                // Replace the exhausted buffer rather than appending to it: an
                // append can reallocate and strand the spent random bytes in
                // freed memory, unzeroized.
                randomness.zeroize()
                randomness = try randomBytes(count: groupCount * groupLength)
                offset = randomness.startIndex
            }
            let byte = Int(randomness[offset])
            offset = randomness.index(after: offset)
            if byte < ceiling {
                return byte % bound
            }
        }
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            bytes.zeroize()
            throw RandomSourceFailure()
        }
        return bytes
    }
}
