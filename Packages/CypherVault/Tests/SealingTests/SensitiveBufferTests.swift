import Foundation
import Testing
@testable import Sealing

struct SensitiveBufferTests {
    @Test func `Consuming init erases the source it owned`() {
        var source = Data([1, 2, 3, 4])
        let buffer = SensitiveBuffer(consuming: &source)
        #expect(source == Data([0, 0, 0, 0]))
        #expect(buffer.withUnsafeBytes { Array($0) } == [1, 2, 3, 4])
    }

    @Test func `Content equals is by value`() {
        let a = SensitiveBuffer(count: 3) { $0.copyBytes(from: [7, 8, 9]) }
        let b = SensitiveBuffer(count: 3) { $0.copyBytes(from: [7, 8, 9]) }
        let c = SensitiveBuffer(count: 3) { $0.copyBytes(from: [7, 8, 0]) }
        let sameBytes = a.contentEquals(b)
        let otherBytes = a.contentEquals(c)
        #expect(sameBytes)
        #expect(!otherBytes)
    }
}
