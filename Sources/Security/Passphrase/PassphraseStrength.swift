import Foundation

/// How hard a passphrase is to guess, and whether it is allowed to protect
/// anything the user cares about.
///
/// `isAcceptable` is the app's single rule for user-chosen passphrases. Every
/// surface that takes one asks this question and no other; no screen carries a
/// second opinion about what "strong enough" means.
struct PassphraseStrength: Equatable, Sendable {
    /// Estimated cost of guessing the passphrase, in bits.
    ///
    /// A search-space figure, not a claim about any particular attacker:
    /// `PassphraseStrengthEstimator` documents exactly what it can and cannot
    /// see.
    let bits: Double

    let tier: PassphraseStrengthTier

    /// Whether the app will let this passphrase protect exported private-key
    /// material.
    var isAcceptable: Bool { tier >= .good }
}

/// The rungs the strength meter shows, ordered weakest to strongest.
enum PassphraseStrengthTier: Int, Comparable, Sendable {
    case empty
    case veryWeak
    case weak
    case good
    case strong

    static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}
