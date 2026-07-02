import XCTest
@testable import CypherAir

final class ToolScreenLayoutPolicyTests: XCTestCase {
    /// The default 900×560 window's detail column measures ~680pt after the
    /// sidebar; it must stay on the single-column form so default-size
    /// windows (and the UI smoke tests) keep the unsplit layout.
    func test_isWide_keepsDefaultWindowDetailWidthSingleColumn() {
        XCTAssertFalse(ToolScreenLayoutPolicy.isWide(width: 680))
        XCTAssertTrue(ToolScreenLayoutPolicy.isWide(width: ToolScreenLayoutPolicy.wideLayoutMinWidth))
    }
}
