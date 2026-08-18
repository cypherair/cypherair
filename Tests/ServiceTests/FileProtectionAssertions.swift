import Foundation
import XCTest

extension XCTestCase {
    /// The one shared assertion that an item carries the complete
    /// file-protection class — for the places a test pins the born-protected
    /// property itself (a directory created with the class as a creation
    /// attribute, or a file inheriting it from the directory it was born in).
    func assertCompleteFileProtection(
        at url: URL,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual(
            attributes[.protectionKey] as? FileProtectionType,
            .complete,
            file: file,
            line: line
        )
    }
}
