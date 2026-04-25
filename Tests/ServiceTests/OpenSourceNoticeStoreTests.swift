import Foundation
import XCTest
@testable import CypherAir

private final class OpenSourceNoticeBundleMarker {}

private final class MockRepositoryURLClipboard: RepositoryURLCopying {
    private(set) var copiedURLs: [String] = []

    func copy(_ repositoryURL: String) {
        copiedURLs.append(repositoryURL)
    }
}

final class OpenSourceNoticeStoreTests: XCTestCase {
    private lazy var bundle = Bundle(for: OpenSourceNoticeBundleMarker.self)
    private lazy var store = OpenSourceNoticeStore(bundle: bundle)

    func test_loadNotices_decodesBundledManifest() throws {
        let notices = try store.loadNotices()

        XCTAssertEqual(notices.first?.kind, .app)
        XCTAssertTrue(notices.contains { $0.id == "cypherair" })
        XCTAssertTrue(notices.contains { $0.id == "sequoia-openpgp@2.2.0" })
        XCTAssertTrue(notices.contains { $0.id == "sequoia-openpgp@2.2.0" && $0.isDirectDependency })
    }

    func test_loadLicenseText_everyNoticeHasReadableText() throws {
        let notices = try store.loadNotices()

        for notice in notices {
            let licenseText = try store.loadLicenseText(for: notice)
            XCTAssertFalse(licenseText.isEmpty, "\(notice.id) should have bundled license text")
        }
    }

    func test_cypherAirLicense_matchesRepositoryLicenseFile() throws {
        let notices = try store.loadNotices()
        guard let appNotice = notices.first(where: { $0.kind == .app }) else {
            return XCTFail("Expected bundled app notice")
        }

        let bundledLicense = try store.loadLicenseText(for: appNotice)
        XCTAssertEqual(appNotice.licenseFileResourceName, "CypherAir-DUAL-LICENSE.txt")
        XCTAssertTrue(appNotice.licenseSourceItems.contains("LICENSE-GPL"))
        XCTAssertTrue(appNotice.licenseSourceItems.contains("LICENSE-MPL"))
        XCTAssertTrue(
            bundledLicense.contains("GNU GENERAL PUBLIC LICENSE")
                || bundledLicense.contains("GNU General Public License")
        )
        XCTAssertTrue(bundledLicense.contains("Mozilla Public License Version 2.0"))
        XCTAssertFalse(bundledLicense.isEmpty)
    }

    func test_sections_searchAndSorting_filtersThirdPartyBySearchText() throws {
        let notices = try store.loadNotices()

        let filtered = store.sections(for: notices, searchText: "openssl")

        XCTAssertTrue(filtered.appNotices.isEmpty)
        XCTAssertEqual(filtered.coreDependencyNotices.map(\.displayName), ["openssl"])
        XCTAssertEqual(filtered.thirdPartyNotices.map(\.displayName), ["openssl-src", "openssl-sys"])
    }

    func test_sections_withoutSearch_keepsAppFirstAndHighlightsCoreDependencies() throws {
        let notices = try store.loadNotices()

        let sections = store.sections(for: notices, searchText: "")
        let thirdPartyNames = sections.thirdPartyNotices.map(\.displayName)
        let sortedNames = thirdPartyNames.sorted {
            $0.localizedCaseInsensitiveCompare($1) == .orderedAscending
        }
        let coreNames = sections.coreDependencyNotices.map(\.displayName)

        XCTAssertEqual(sections.appNotices.map(\.id), ["cypherair"])
        XCTAssertEqual(
            coreNames,
            ["base64", "openssl", "sequoia-openpgp", "thiserror", "uniffi", "zeroize"]
        )
        XCTAssertEqual(thirdPartyNames, sortedNames)
    }

    func test_manifest_excludesTestOnlyDependencies() throws {
        let notices = try store.loadNotices()
        let ids = Set(notices.map(\.id))

        XCTAssertFalse(ids.contains("rand@0.8.5"))
        XCTAssertTrue(ids.contains("tempfile@3.27.0"))
    }

    func test_noticeSources_captureFallbackAndArchiveOrigins() throws {
        let notices = try store.loadNotices()

        let rEfi = try XCTUnwrap(notices.first { $0.id == "r-efi@6.0.0" })
        XCTAssertEqual(rEfi.licenseSourceKind, .spdxFallback)
        XCTAssertTrue(rEfi.licenseSourceItems.contains { $0.contains("LGPL-2.1") })

        let uniffi = try XCTUnwrap(notices.first { $0.id == "uniffi@0.31.1" })
        XCTAssertEqual(uniffi.licenseSourceKind, .repositoryArchive)
        XCTAssertTrue(uniffi.licenseSourceItems.contains("v0.31.1:LICENSE"))

        let sequoia = try XCTUnwrap(notices.first { $0.id == "sequoia-openpgp@2.2.0" })
        XCTAssertEqual(sequoia.licenseSourceKind, .cratePackage)
        XCTAssertTrue(sequoia.licenseSourceItems.contains("LICENSE.txt"))
    }

    func test_repositoryURLCopyAction_copyIfPresent_usesInjectedClipboard() {
        let clipboard = MockRepositoryURLClipboard()
        let action = RepositoryURLCopyAction(repositoryURLClipboard: clipboard)

        let copied = action.copyIfPresent("https://github.com/cypherair/cypherair")

        XCTAssertTrue(copied)
        XCTAssertEqual(clipboard.copiedURLs, ["https://github.com/cypherair/cypherair"])
    }

    func test_repositoryURLCopyAction_copyIfPresent_emptyURLDoesNothing() {
        let clipboard = MockRepositoryURLClipboard()
        let action = RepositoryURLCopyAction(repositoryURLClipboard: clipboard)

        let copied = action.copyIfPresent("")

        XCTAssertFalse(copied)
        XCTAssertTrue(clipboard.copiedURLs.isEmpty)
    }

}
