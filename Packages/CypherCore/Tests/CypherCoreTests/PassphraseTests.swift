import Testing
@testable import CypherCore

@Suite struct PassphraseTests {
    @Test(arguments: [
        ("abcdefghijk", [PassphraseProblem.tooShort]),
        ("abcdefghijkl", []),
        ("abcdeffghijk", []),
        ("abcdefffghij", [.repeatedCharacter]),
        ("aaa", [.tooShort, .repeatedCharacter]),
        ("AaAbBbCcCdDd", []),
        (String(repeating: "👍🏽🔑", count: 6), []),
        (String(repeating: "e\u{301}", count: 12), [.repeatedCharacter]),
    ])
    func problems(passphrase: String, expected: [PassphraseProblem]) {
        #expect(Passphrase.problems(in: passphrase) == expected)
    }

    @Test func `Suggestions pass the rule and differ`() {
        let suggestions = (0..<500).map { _ in Passphrase.suggestion() }
        for suggestion in suggestions {
            #expect(Passphrase.problems(in: suggestion).isEmpty)
            #expect(suggestion.count == 23)
        }
        #expect(Set(suggestions).count == suggestions.count)
    }
}
