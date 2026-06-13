import Foundation
import XCTest
@testable import CypherAir

/// Guards the sizing decision behind the iOS multiline-input fix: the editor is
/// pinned to a definite height equal to its measured content height clamped to the
/// visible range, so it grows with content up to the maximum and then scrolls
/// internally instead of ballooning the enclosing `Form` row.
final class MultilineTextInputSizingTests: XCTestCase {

    private let minHeight: CGFloat = 110
    private let idealHeight: CGFloat = 160
    private let maxHeight: CGFloat = 240

    func testReturnsContentHeightWhenWithinRange() {
        let height = MultilineTextInputSizing.editorHeight(
            contentHeight: 200,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight
        )

        XCTAssertEqual(height, 200)
    }

    func testClampsTallContentToMaxHeight() {
        // The core fix: a long paste caps at maxHeight, so the editor scrolls the
        // overflow instead of growing the Form row without bound.
        let height = MultilineTextInputSizing.editorHeight(
            contentHeight: 800,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight
        )

        XCTAssertEqual(height, maxHeight)
    }

    func testClampsShortContentToMinHeight() {
        let height = MultilineTextInputSizing.editorHeight(
            contentHeight: 40,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight
        )

        XCTAssertEqual(height, minHeight)
    }

    func testUsesIdealHeightBeforeContentIsMeasured() {
        // contentHeight == 0 means the text view has not been laid out yet; the
        // editor sits at its ideal height until the first measurement arrives.
        let height = MultilineTextInputSizing.editorHeight(
            contentHeight: 0,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight
        )

        XCTAssertEqual(height, idealHeight)
    }
}
