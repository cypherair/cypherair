import Foundation
import XCTest
@testable import Sealing

final class SensitiveBufferTests: XCTestCase {
    func test_consumingInit_erasesTheSourceItOwned() {
        var source = Data([1, 2, 3, 4])
        let buffer = SensitiveBuffer(consuming: &source)
        XCTAssertEqual(source, Data([0, 0, 0, 0]))
        XCTAssertEqual(buffer.withUnsafeBytes { Array($0) }, [1, 2, 3, 4])
    }

    func test_contentEquals_isByValue() {
        let a = SensitiveBuffer(count: 3) { $0.copyBytes(from: [7, 8, 9]) }
        let b = SensitiveBuffer(count: 3) { $0.copyBytes(from: [7, 8, 9]) }
        let c = SensitiveBuffer(count: 3) { $0.copyBytes(from: [7, 8, 0]) }
        XCTAssertTrue(a.contentEquals(b))
        XCTAssertFalse(a.contentEquals(c))
    }
}
