import Foundation
import XCTest
@testable import CypherAir

private final class OpenSourceNoticeBundleMarker {}

@MainActor
private final class RepositoryURLClipboardRecorder {
    private(set) var copiedURLs: [String] = []

    func record(_ repositoryURL: String) {
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
        XCTAssertTrue(notices.contains { $0.id == "sequoia-openpgp@2.4.1" })
        XCTAssertTrue(notices.contains { $0.id == "sequoia-openpgp@2.4.1" && $0.isDirectDependency })
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
            [
                "base64",
                "openssl",
                "sequoia-openpgp",
                "SQLCipher",
                "SQLite",
                "thiserror",
                "uniffi",
                "zeroize"
            ]
        )
        XCTAssertEqual(thirdPartyNames, sortedNames)
    }

    func test_manifest_excludesNonAppleTargetDependenciesAndKeepsReachableTransitiveDependencies() throws {
        let notices = try store.loadNotices()
        let ids = Set(notices.map(\.id))

        XCTAssertFalse(ids.contains("r-efi@6.0.0"))
        XCTAssertFalse(ids.contains { $0.hasPrefix("wasm-bindgen@") })
        XCTAssertFalse(ids.contains { $0.hasPrefix("windows-sys@") })
        XCTAssertTrue(ids.contains("tempfile@3.27.0"))
    }

    func test_noticeSources_captureFallbackAndArchiveOrigins() throws {
        let notices = try store.loadNotices()

        let uniffi = try XCTUnwrap(notices.first { $0.id == "uniffi@0.32.0" })
        XCTAssertEqual(uniffi.licenseSourceKind, .repositoryArchive)
        XCTAssertTrue(uniffi.licenseSourceItems.contains("v0.32.0:LICENSE"))

        let sequoia = try XCTUnwrap(notices.first { $0.id == "sequoia-openpgp@2.4.1" })
        XCTAssertEqual(sequoia.licenseSourceKind, .cratePackage)
        XCTAssertTrue(sequoia.licenseSourceItems.contains("LICENSE.txt"))
    }

    @MainActor
    func test_repositoryURLCopyAction_copyIfPresent_usesInjectedClipboard() {
        let recorder = RepositoryURLClipboardRecorder()
        let action = RepositoryURLCopyAction(copy: recorder.record)

        let copied = action.copyIfPresent("https://github.com/cypherair/cypherair")

        XCTAssertTrue(copied)
        XCTAssertEqual(recorder.copiedURLs, ["https://github.com/cypherair/cypherair"])
    }

    @MainActor
    func test_repositoryURLCopyAction_copyIfPresent_emptyURLDoesNothing() {
        let recorder = RepositoryURLClipboardRecorder()
        let action = RepositoryURLCopyAction(copy: recorder.record)

        let copied = action.copyIfPresent("")

        XCTAssertFalse(copied)
        XCTAssertTrue(recorder.copiedURLs.isEmpty)
    }

}
