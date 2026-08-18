import Foundation
import XCTest
@testable import CypherAir

final class PassphraseStrengthTests: XCTestCase {
    /// The shapes the gate exists for. Each is refused for a different reason —
    /// a known token, a repeat, a walk, a keyboard row, a leet spelling, a year,
    /// a phrase in Chinese — so a matcher that stops firing is visible here
    /// rather than in the field.
    func test_guessablePassphrasesAreRefused() {
        let guessable = [
            "password",
            "Password1",
            "password123",
            "P@ssw0rd!",
            "12345678",
            "qwertyuiop",
            "1qaz2wsx",
            "aaaaaaaaaaaaaaaa",
            "abcdefghijklmnop",
            "abcabcabcabcabcabc",
            "monkey1999",
            "Butterfly1!",
            "letmein2024",
            "correct horse battery staple",
            "woaini1314",
            "我爱你1314",
            "Tr0ub4dor&3",
        ]

        for passphrase in guessable {
            let strength = PassphraseStrengthEstimator.estimate(passphrase)
            XCTAssertFalse(
                strength.isAcceptable,
                "\(passphrase) scored \(strength.bits) bits and was accepted"
            )
        }
    }

    func test_emptyPassphraseIsEmptyRatherThanWeak() {
        XCTAssertEqual(PassphraseStrengthEstimator.estimate("").tier, .empty)
        XCTAssertFalse(PassphraseStrengthEstimator.estimate("").isAcceptable)
    }

    /// The contract that lets the app offer generation as the answer to a
    /// refusal: what it hands back always clears the gate, and clears it on the
    /// estimator's own terms rather than by being recognised as ours.
    func test_generatedPassphrasesAlwaysClearTheGate() throws {
        var seen = Set<String>()
        for _ in 0..<200 {
            let generated = try PassphraseGenerator.generate()
            let strength = PassphraseStrengthEstimator.estimate(generated)
            XCTAssertEqual(strength.tier, .strong, "\(generated) scored \(strength.bits) bits")
            XCTAssertTrue(seen.insert(generated).inserted, "repeated draw: \(generated)")
        }
    }

    func test_generatedPassphrasesAvoidCharactersThatAreMisreadOffPaper() throws {
        let allowed = Set(String(decoding: PassphraseGenerator.alphabet, as: UTF8.self) + "-")
        for _ in 0..<50 {
            let generated = try PassphraseGenerator.generate()
            XCTAssertTrue(
                generated.allSatisfy(allowed.contains),
                "\(generated) left the alphabet"
            )
        }
        XCTAssertTrue("0O1lI".allSatisfy { !allowed.contains($0) })
    }

    /// Typing your own is the fallback, not a dead end: a long invented
    /// passphrase has to be able to reach the gate.
    func test_aLongInventedPassphraseIsAccepted() {
        XCTAssertTrue(
            PassphraseStrengthEstimator.estimate("harbour lantern 47 quiet drift").isAcceptable
        )
    }
}
