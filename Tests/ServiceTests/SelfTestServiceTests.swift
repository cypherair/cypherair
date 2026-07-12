import XCTest
@testable import CypherAir

private enum SelfTestReportExportTestError: Error {
    case failed
}

/// Tests for SelfTestService — the one-tap diagnostic.
/// SelfTestService uses real PGP adapters (no mocks needed).
final class SelfTestServiceTests: XCTestCase {

    private var engine: PgpEngine!
    private var selfTestService: SelfTestService!

    override func setUp() {
        super.setUp()
        engine = PgpEngine()
        selfTestService = SelfTestService(
            selfTestAdapter: PGPSelfTestOperationAdapter(engine: engine),
            messageAdapter: PGPMessageOperationAdapter(engine: engine)
        )
    }

    override func tearDown() {
        selfTestService = nil
        engine = nil
        super.tearDown()
    }

    // MARK: - M1: SelfTestService Tests

    func test_selfTest_legacy_allChecksPass() async {
        await selfTestService.runAllTests()

        guard case .completed(let results) = selfTestService.state else {
            XCTFail("Expected .completed state, got \(selfTestService.state)")
            return
        }

        // Legacy has 5 tests (keygen, encrypt/decrypt, sign/verify, tamper, export/import)
        let legacyResults = results.filter { $0.profile == .universal }
        XCTAssertEqual(legacyResults.count, 5, "Legacy should have 5 test results")

        for result in legacyResults {
            XCTAssertTrue(result.passed, "\(result.name) should pass for Legacy: \(result.message)")
        }
    }

    func test_selfTest_modernHigh_allChecksPass() async {
        await selfTestService.runAllTests()

        guard case .completed(let results) = selfTestService.state else {
            XCTFail("Expected .completed state, got \(selfTestService.state)")
            return
        }

        let modernHighResults = results.filter { $0.profile == .advanced }
        XCTAssertEqual(modernHighResults.count, 5, "Modern High should have 5 test results")

        for result in modernHighResults {
            XCTAssertTrue(result.passed, "\(result.name) should pass for Modern High: \(result.message)")
        }
    }

    func test_selfTest_reportGeneration_containsAllSections() async throws {
        await selfTestService.runAllTests()

        guard case .completed(let results) = selfTestService.state else {
            XCTFail("Expected .completed state")
            return
        }

        // Verify all results present (5 per software profile + 1 QR),
        // derived from the profile vocabulary so new families are covered.
        let expectedCount = PGPKeyProfile.allCases.count * 5 + 1
        XCTAssertEqual(
            results.count,
            expectedCount,
            "Should have \(expectedCount) total test results"
        )

        let report = try XCTUnwrap(selfTestService.latestReport)
        XCTAssertTrue(
            report.suggestedFilename.hasPrefix("CypherAir-X-SelfTest-Report-"),
            "Report should have a suggested export filename"
        )
        XCTAssertEqual((report.suggestedFilename as NSString).pathExtension, "txt")

        let reportString = String(data: report.data, encoding: .utf8)
        XCTAssertNotNil(reportString, "Report should be UTF-8 text in memory")
        XCTAssertTrue(
            reportString?.contains("\(expectedCount)") == true,
            "Report should reference \(expectedCount) tests"
        )
        XCTAssertTrue(
            reportString?.contains("CypherAir X Self-Test Report") == true,
            "Report should include the report title"
        )
    }

    func test_selfTest_reportExportCompletion_successClearsServiceReport() async throws {
        await selfTestService.runAllTests()
        var presentedReport: SelfTestService.SelfTestReport? = try XCTUnwrap(selfTestService.latestReport)

        let exportURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("CypherAir-X-SelfTest-Report-\(UUID().uuidString).txt")

        SelfTestReportExportCompletion.finish(
            .success(exportURL),
            clearLatestReport: {
                self.selfTestService.clearLatestReport()
            },
            clearPresentedReport: {
                presentedReport = nil
            }
        )

        XCTAssertNil(selfTestService.latestReport)
        XCTAssertNil(presentedReport)
    }

    func test_selfTest_reportExportCompletion_failurePreservesServiceReportForRetry() async throws {
        await selfTestService.runAllTests()
        let latestReport = try XCTUnwrap(selfTestService.latestReport)
        var presentedReport: SelfTestService.SelfTestReport? = latestReport

        SelfTestReportExportCompletion.finish(
            .failure(SelfTestReportExportTestError.failed),
            clearLatestReport: {
                self.selfTestService.clearLatestReport()
            },
            clearPresentedReport: {
                presentedReport = nil
            }
        )

        XCTAssertEqual(selfTestService.latestReport, latestReport)
        XCTAssertNil(presentedReport)
    }
}
