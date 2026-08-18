import Foundation
import XCTest
@testable import CypherAir

final class PassphraseRequirementsTests: XCTestCase {
    func test_tooShortIsRefused() {
        let short = String(repeating: "ab", count: (PassphraseRequirements.minimumLength - 1) / 2)
        let requirements = PassphraseRequirements(of: short)

        XCTAssertLessThan(short.count, PassphraseRequirements.minimumLength)
        XCTAssertFalse(requirements.isLongEnough)
        XCTAssertFalse(requirements.isSatisfied)
    }

    func test_emptyIsRefused() {
        XCTAssertFalse(PassphraseRequirements(of: "").isSatisfied)
    }

    /// One character held down is long but not a passphrase, which is the whole
    /// reason the second requirement exists.
    func test_repeatedCharacterIsRefused() {
        let held = String(repeating: "a", count: PassphraseRequirements.minimumLength * 2)
        let requirements = PassphraseRequirements(of: held)

        XCTAssertTrue(requirements.isLongEnough)
        XCTAssertFalse(requirements.avoidsRepeatedRuns)
        XCTAssertFalse(requirements.isSatisfied)
    }

    /// The run limit is a limit, not a ban on repetition: doubled letters are
    /// ordinary in real words and must not cost anyone their passphrase.
    func test_shortRunsAreAllowedAndTheLimitIsWhereItSays() {
        XCTAssertTrue(PassphraseRequirements(of: "coffee mission").isSatisfied)

        let atLimit = String(repeating: "a", count: PassphraseRequirements.maximumConsecutiveRepeats)
        let overLimit = atLimit + "a"
        let tail = String("bcdefghijklmnop".prefix(PassphraseRequirements.minimumLength))

        XCTAssertTrue(PassphraseRequirements(of: atLimit + tail).isSatisfied)
        XCTAssertFalse(PassphraseRequirements(of: overLimit + tail).isSatisfied)
    }

    func test_bothRequirementsMetIsAccepted() {
        XCTAssertTrue(PassphraseRequirements(of: "harbour lantern 47").isSatisfied)
    }

    /// The contract that lets the app answer a refusal with the generator:
    /// what it hands back always satisfies the requirements, by construction
    /// rather than by luck.
    func test_generatedPassphrasesAlwaysSatisfyTheRequirements() throws {
        var seen = Set<String>()
        for _ in 0..<500 {
            let generated = try PassphraseGenerator.generate()
            XCTAssertTrue(
                PassphraseRequirements(of: generated).isSatisfied,
                "\(generated) failed the requirements"
            )
            XCTAssertTrue(seen.insert(generated).inserted, "repeated draw: \(generated)")
        }
    }

    func test_generatedPassphrasesAvoidCharactersThatAreMisreadOffPaper() throws {
        let allowed = Set(String(decoding: PassphraseGenerator.alphabet, as: UTF8.self) + "-")
        for _ in 0..<50 {
            let generated = try PassphraseGenerator.generate()
            XCTAssertTrue(generated.allSatisfy(allowed.contains), "\(generated) left the alphabet")
        }
        XCTAssertTrue("0O1lI".allSatisfy { !allowed.contains($0) })
    }
}
