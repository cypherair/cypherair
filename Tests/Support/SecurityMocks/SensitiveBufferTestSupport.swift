import Foundation
import XCTest
@testable import CypherAir

// Test-side bridges into and out of `SensitiveBuffer`. They live here rather
// than on the production type on purpose: production code that needs a secret
// as a value is the defect this type exists to remove, while a test needs a
// fixture it can still compare against after handing a copy to the subject.
extension SensitiveBuffer {
    /// A buffer holding a copy of `data`, leaving the fixture intact.
    init(copying data: Data) {
        self.init(count: data.count) { destination in
            destination.copyBytes(from: data)
        }
    }

    /// The buffer's bytes, for assertions.
    func copiedBytes() -> Data {
        withUnsafeBytes { Data($0) }
    }
}

/// `XCTAssertThrowsError` for an expression whose result is noncopyable —
/// XCTest's own assertion is generic over a `Copyable` result, so a call
/// returning a `SensitiveBuffer` cannot go through it.
func assertThrowsError<R: ~Copyable>(
    _ expression: @autoclosure () throws -> R,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (any Error) -> Void = { _ in }
) {
    do {
        _ = try expression()
    } catch {
        errorHandler(error)
        return
    }
    let description = message()
    XCTFail(
        description.isEmpty ? "Expected an error, but no error was thrown." : description,
        file: file,
        line: line
    )
}
