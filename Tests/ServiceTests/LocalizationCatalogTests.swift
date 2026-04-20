import Foundation
import XCTest

final class LocalizationCatalogTests: XCTestCase {
    func test_allLocalizedKeysExistInCatalogAndAreFullyTranslated() throws {
        let catalog = try loadCatalog(at: "Sources/Resources/Localizable.xcstrings")
        let sourceURL = repositoryRootURL().appending(path: "Sources", directoryHint: .isDirectory)
        let keys = try localizedKeys(in: sourceURL)

        XCTAssertFalse(keys.isEmpty)

        for key in keys.sorted() {
            let entry = try XCTUnwrap(catalog.strings[key], "Missing catalog entry for \(key)")
            XCTAssertNotEqual(entry.extractionState, "stale", "\(key) should not be stale")
            assertFullyTranslated(entry, key: key)
        }
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

    private func repositoryRootURL() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func loadCatalog(at relativePath: String) throws -> StringCatalog {
        let catalogURL = repositoryRootURL().appending(path: relativePath)
        let catalogData = try Data(contentsOf: catalogURL)
        return try JSONDecoder().decode(StringCatalog.self, from: catalogData)
    }

    private func localizedKeys(in directoryURL: URL) throws -> Set<String> {
        let expression = try NSRegularExpression(pattern: #"localized:\s*"([^"]+)""#)
        var keys = Set<String>()

        let enumerator = FileManager.default.enumerator(
            at: directoryURL,
            includingPropertiesForKeys: nil
        )

        while let fileURL = enumerator?.nextObject() as? URL {
            guard fileURL.pathExtension == "swift" else { continue }
            guard !fileURL.path.contains("/Sources/PgpMobile/") else { continue }

            let contents = try String(contentsOf: fileURL, encoding: .utf8)
            let range = NSRange(contents.startIndex..<contents.endIndex, in: contents)
            let matches = expression.matches(in: contents, range: range)

            for match in matches {
                guard
                    let keyRange = Range(match.range(at: 1), in: contents)
                else {
                    continue
                }

                keys.insert(String(contents[keyRange]))
            }
        }

        return keys
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
