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
        // Clean up self-test reports in Documents/self-test/
        if let url = selfTestService.lastReportURL {
            try? FileManager.default.removeItem(at: url)
        }
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

    func test_selfTest_reportGeneration_containsAllSections() async {
        await selfTestService.runAllTests()

        guard case .completed(let results) = selfTestService.state else {
            XCTFail("Expected .completed state")
            return
        }

        // Verify all 11 results present (5 per profile + 1 QR)
        XCTAssertEqual(results.count, 11, "Should have 11 total test results")

        // Verify report file was saved
        XCTAssertNotNil(selfTestService.lastReportURL, "Report URL should be set after test run")

        if let url = selfTestService.lastReportURL {
            let report = try? String(contentsOf: url, encoding: .utf8)
            XCTAssertNotNil(report, "Report file should be readable")
            // Verify report has results line
            if let report = report {
                XCTAssertTrue(report.contains("11"), "Report should reference 11 tests")
            }
        }
    }
}
