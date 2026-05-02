import XCTest
@testable import CypherAir

/// Tests for SelfTestService — the one-tap diagnostic.
/// SelfTestService only depends on PgpEngine (no mocks needed).
final class SelfTestServiceTests: XCTestCase {

    private var engine: PgpEngine!
    private var selfTestService: SelfTestService!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
        selfTestService = SelfTestService(engine: engine)
    }

    override func tearDown() {
        selfTestService = nil
        engine = nil
        super.tearDown()
    }

    // MARK: - M1: SelfTestService Tests

    func test_selfTest_profileA_allChecksPass() async {
        await selfTestService.runAllTests()

        guard case .completed(let results) = selfTestService.state else {
            XCTFail("Expected .completed state, got \(selfTestService.state)")
            return
        }

        // Profile A has 5 tests (keygen, encrypt/decrypt, sign/verify, tamper, export/import)
        let profileAResults = results.filter { $0.profile == .universal }
        XCTAssertEqual(profileAResults.count, 5, "Profile A should have 5 test results")

        for result in profileAResults {
            XCTAssertTrue(result.passed, "\(result.name) should pass for Profile A: \(result.message)")
        }
    }

    func test_selfTest_profileB_allChecksPass() async {
        await selfTestService.runAllTests()

        guard case .completed(let results) = selfTestService.state else {
            XCTFail("Expected .completed state, got \(selfTestService.state)")
            return
        }

        let profileBResults = results.filter { $0.profile == .advanced }
        XCTAssertEqual(profileBResults.count, 5, "Profile B should have 5 test results")

        for result in profileBResults {
            XCTAssertTrue(result.passed, "\(result.name) should pass for Profile B: \(result.message)")
        }
    }

    func test_selfTest_reportGeneration_containsAllSections() async throws {
        await selfTestService.runAllTests()

        guard case .completed(let results) = selfTestService.state else {
            XCTFail("Expected .completed state")
            return
        }

        // Verify all 11 results present (5 per profile + 1 QR)
        XCTAssertEqual(results.count, 11, "Should have 11 total test results")

        let report = try XCTUnwrap(selfTestService.latestReport)
        XCTAssertTrue(
            report.suggestedFilename.hasPrefix("CypherAir-SelfTest-Report-"),
            "Report should have a suggested export filename"
        )
        XCTAssertEqual((report.suggestedFilename as NSString).pathExtension, "txt")

        let reportString = String(data: report.data, encoding: .utf8)
        XCTAssertNotNil(reportString, "Report should be UTF-8 text in memory")
        XCTAssertTrue(reportString?.contains("11") == true, "Report should reference 11 tests")
        XCTAssertTrue(
            reportString?.contains("CypherAir Self-Test Report") == true,
            "Report should include the report title"
        )
    }
}
