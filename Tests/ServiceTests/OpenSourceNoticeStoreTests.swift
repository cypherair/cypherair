import Foundation
import XCTest
@testable import CypherAir

final class OpenSourceNoticeStoreTests: XCTestCase {
    // The unit tests are hosted by the app, so Bundle.main is the app bundle that ships the notices.
    private lazy var bundle = Bundle.main
    private lazy var store = OpenSourceNoticeStore(bundle: bundle)

    func test_loadLicenseText_everyNoticeHasReadableText() throws {
        let notices = try store.loadNotices()

        for notice in notices {
            let licenseText = try store.loadLicenseText(for: notice)
            XCTAssertFalse(licenseText.isEmpty, "\(notice.id) should have bundled license text")
        }
    }

    func test_sections_searchAndSorting_filtersThirdPartyBySearchText() throws {
        let notices = try store.loadNotices()

        let filtered = store.sections(for: notices, searchText: "openssl")

        XCTAssertTrue(filtered.appNotices.isEmpty)
        XCTAssertEqual(filtered.coreDependencyNotices.map(\.displayName), ["openssl"])
        XCTAssertEqual(filtered.thirdPartyNotices.map(\.displayName), ["openssl-src", "openssl-sys"])
    }

}
