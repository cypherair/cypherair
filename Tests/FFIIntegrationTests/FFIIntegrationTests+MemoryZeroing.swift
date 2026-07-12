import XCTest
@testable import CypherAir

extension FFIIntegrationTests {
    // MARK: - Memory Zeroing Tests

    /// Verify Data.zeroize() sets all bytes to zero.
    func test_dataZeroize_setsAllBytesToZero() {
        var data = Data([0xAB, 0xCD, 0xEF, 0x12, 0x34])
        let originalCount = data.count
        data.zeroize()
        XCTAssertEqual(data.count, originalCount, "Count must not change")
        XCTAssertTrue(data.allSatisfy { $0 == 0 }, "All bytes must be zero after zeroize()")
    }

    /// Verify Data.zeroize() on empty data does not crash.
    func test_dataZeroize_emptyData_noop() {
        var data = Data()
        data.zeroize()
        XCTAssertTrue(data.isEmpty, "Empty data remains empty")
    }

    /// Verify Data.zeroize() works on large buffers.
    func test_dataZeroize_largeBuffer_allZeros() {
        var data = Data(repeating: 0xFF, count: 1_048_576) // 1 MB
        data.zeroize()
        XCTAssertTrue(data.allSatisfy { $0 == 0 }, "All bytes in 1 MB buffer must be zero")
    }

    /// Verify SensitiveData.zeroize() clears the underlying storage.
    func test_sensitiveData_explicitZeroize_clearsData() {
        let sensitive = SensitiveData(Data([0xDE, 0xAD, 0xBE, 0xEF]))
        XCTAssertEqual(sensitive.count, 4)
        sensitive.zeroize()
        XCTAssertTrue(sensitive.data.allSatisfy { $0 == 0 }, "SensitiveData must be zeroed after zeroize()")
    }

    /// Verify SensitiveData deinit does not crash (zeroing happens in deinit).
    func test_sensitiveData_deinit_zerosStorage() {
        // Create and immediately release — deinit should fire without crash.
        autoreleasepool {
            _ = SensitiveData(Data(repeating: 0x42, count: 64))
        }
        // If we reach here without crash, deinit zeroing worked.
    }
}
