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
}
