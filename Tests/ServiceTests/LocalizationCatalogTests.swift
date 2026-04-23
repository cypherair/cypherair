import Foundation
import XCTest

final class LocalizationCatalogTests: XCTestCase {
    func test_allLocalizedKeysExistInCatalogAndAreFullyTranslated() throws {
        let catalog = try loadCatalog(at: "Sources/Resources/Localizable.xcstrings")
        let sourceURL = try RepositoryAuditLoader.sourcesRootURL()
        let keys = try localizedKeys(in: sourceURL)

        XCTAssertFalse(keys.isEmpty)

        for key in keys.sorted() {
            let entry = try XCTUnwrap(catalog.strings[key], "Missing catalog entry for \(key)")
            XCTAssertNotEqual(entry.extractionState, "stale", "\(key) should not be stale")
            assertFullyTranslated(entry, key: key)
        }
    }

    func test_localizedKeysIncludeLocalizedStringKeyArguments() throws {
        let sourceURL = try RepositoryAuditLoader.sourcesRootURL()
        let keys = try localizedKeys(in: sourceURL)

        XCTAssertTrue(keys.contains("decrypt.signature"))
        XCTAssertTrue(keys.contains("decrypt.signer"))
        XCTAssertTrue(keys.contains("verify.result"))
        XCTAssertTrue(keys.contains("verify.signer"))
    }

    func test_localizableCatalogEntriesAreFullyTranslatedAndNotStale() throws {
        let catalog = try loadCatalog(at: "Sources/Resources/Localizable.xcstrings")

        XCTAssertFalse(catalog.strings.isEmpty)

        for (key, entry) in catalog.strings.sorted(by: { $0.key < $1.key }) {
            XCTAssertNotEqual(entry.extractionState, "stale", "\(key) should not be stale")
            assertFullyTranslated(entry, key: key)
        }
    }

    func test_infoPlistCatalogEntriesAreFullyTranslatedAndNotStale() throws {
        let catalog = try loadCatalog(at: "Sources/Resources/InfoPlist.xcstrings")

        XCTAssertFalse(catalog.strings.isEmpty)

        for (key, entry) in catalog.strings.sorted(by: { $0.key < $1.key }) {
            XCTAssertNotEqual(entry.extractionState, "stale", "\(key) should not be stale")
            assertFullyTranslated(entry, key: key)
        }
    }

    private func assertFullyTranslated(_ entry: StringCatalogEntry, key: String) {
        let requiredLocales: Set<String> = ["en", "zh-Hans"]
        let locales = Set(entry.localizations.keys)

        XCTAssertTrue(
            locales.isSuperset(of: requiredLocales),
            "\(key) is missing required locales"
        )

        for locale in requiredLocales.sorted() {
            guard let localization = entry.localizations[locale] else {
                XCTFail("Missing \(locale) localization for \(key)")
                continue
            }
            guard let stringUnit = localization.stringUnit else {
                XCTFail("Missing string unit for \(key) (\(locale))")
                continue
            }
            XCTAssertEqual(
                stringUnit.state,
                "translated",
                "\(key) (\(locale)) should be translated"
            )
        }
    }

    private func loadCatalog(at relativePath: String) throws -> StringCatalog {
        let catalogData = try RepositoryAuditLoader.loadData(relativePath: relativePath)
        return try JSONDecoder().decode(StringCatalog.self, from: catalogData)
    }

    private func localizedKeys(in directoryURL: URL) throws -> Set<String> {
        let localizedExpression = try NSRegularExpression(pattern: #"localized:\s*"([^"]+)""#)
        let localizedStringKeyLabelExpression = try NSRegularExpression(
            pattern: #"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*LocalizedStringKey\b"#
        )
        let catalogStyleKeyExpression = try NSRegularExpression(
            pattern: #"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$"#
        )
        let sourceContents = try swiftSourceContents(in: directoryURL)
        var keys = Set<String>()

        for contents in sourceContents {
            let localizedMatches = capturedStrings(matching: localizedExpression, in: contents)
            for key in localizedMatches where matchesCatalogStyle(key, using: catalogStyleKeyExpression) {
                keys.insert(key)
            }
        }

        let localizedStringKeyLabels = Set(
            sourceContents.flatMap {
                capturedStrings(matching: localizedStringKeyLabelExpression, in: $0)
            }
        )

        if let localizedStringKeyLiteralExpression = try localizedStringKeyLiteralExpression(
            for: localizedStringKeyLabels
        ) {
            for contents in sourceContents {
                keys.formUnion(
                    capturedStrings(matching: localizedStringKeyLiteralExpression, in: contents)
                )
            }
        }

        return keys
    }

    private func swiftSourceContents(in directoryURL: URL) throws -> [String] {
        var contents = [String]()
        let enumerator = FileManager.default.enumerator(
            at: directoryURL,
            includingPropertiesForKeys: nil
        )

        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else { continue }
            guard !fileURL.path.contains("/Sources/PgpMobile/") else { continue }
            contents.append(try String(contentsOf: fileURL, encoding: .utf8))
        }

        return contents
    }

    private func localizedStringKeyLiteralExpression(
        for labels: Set<String>
    ) throws -> NSRegularExpression? {
        guard !labels.isEmpty else {
            return nil
        }

        let alternation = labels
            .sorted { lhs, rhs in
                if lhs.count != rhs.count {
                    return lhs.count > rhs.count
                }
                return lhs < rhs
            }
            .map(NSRegularExpression.escapedPattern(for:))
            .joined(separator: "|")

        let pattern = "\\b(?:\(alternation))\\s*:\\s*\"([A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)+)\""
        return try NSRegularExpression(pattern: pattern)
    }

    private func capturedStrings(
        matching expression: NSRegularExpression,
        in contents: String
    ) -> [String] {
        let range = NSRange(contents.startIndex..<contents.endIndex, in: contents)
        return expression.matches(in: contents, range: range).compactMap { match in
            guard let captureRange = Range(match.range(at: 1), in: contents) else {
                return nil
            }
            return String(contents[captureRange])
        }
    }

    private func matchesCatalogStyle(
        _ candidate: String,
        using expression: NSRegularExpression
    ) -> Bool {
        let range = NSRange(candidate.startIndex..<candidate.endIndex, in: candidate)
        return expression.firstMatch(in: candidate, range: range) != nil
    }
}

private struct StringCatalog: Decodable {
    let strings: [String: StringCatalogEntry]
}

private struct StringCatalogEntry: Decodable {
    let extractionState: String?
    let localizations: [String: StringCatalogLocalization]
}

private struct StringCatalogLocalization: Decodable {
    let stringUnit: StringCatalogStringUnit?
}

private struct StringCatalogStringUnit: Decodable {
    let state: String
}
