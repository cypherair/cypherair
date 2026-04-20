import Foundation
import XCTest
@testable import CypherAir

private final class SourceComplianceBundleMarker {}

final class SourceComplianceStoreTests: XCTestCase {
    private lazy var bundle = Bundle(for: SourceComplianceBundleMarker.self)

    func test_loadInfo_decodesStableReleaseFixture() throws {
        let store = SourceComplianceStore(
            bundle: bundle,
            resourceName: "source_compliance_info_stable",
            resourceExtension: "txt",
            subdirectory: "Fixtures"
        )

        let info = try store.loadInfo()

        XCTAssertEqual(info.versionDisplay, "1.2.8 (27)")
        XCTAssertEqual(info.commitSHA, "1234567890abcdef1234567890abcdef12345678")
        XCTAssertEqual(info.stableReleaseTag, "cypherair-v1.2.8-build27")
        XCTAssertEqual(
            info.stableReleaseURL,
            "https://github.com/cypherair/cypherair/releases/tag/cypherair-v1.2.8-build27"
        )
        XCTAssertTrue(info.isStableReleaseBuild)
        XCTAssertEqual(
            info.dependencies,
            [
                SourceComplianceDependency(name: "sequoia-openpgp", version: "2.2.0"),
                SourceComplianceDependency(name: "buffered-reader", version: "1.4.0"),
            ]
        )
    }

    func test_loadInfo_decodesLocalBuildFixture() throws {
        let store = SourceComplianceStore(
            bundle: bundle,
            resourceName: "source_compliance_info_local",
            resourceExtension: "txt",
            subdirectory: "Fixtures"
        )

        let info = try store.loadInfo()

        XCTAssertFalse(info.isStableReleaseBuild)
        XCTAssertTrue(info.stableReleaseTag.isEmpty)
        XCTAssertTrue(info.stableReleaseURL.isEmpty)
        XCTAssertEqual(info.fulfillmentBasis, "LGPL 2.1")
        XCTAssertEqual(info.firstPartyLicense, "GPL-3.0-or-later OR MPL-2.0")
    }
}
