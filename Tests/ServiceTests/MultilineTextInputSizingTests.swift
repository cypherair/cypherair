import Foundation
import XCTest
@testable import CypherAir

/// Guards the sizing contract behind the iOS multiline-input fix: the editor must
/// report the content height *clamped* to its visible range — never the raw content
/// height (which made SwiftUI lay the text view out at full size and clip it, so it
/// could not scroll) and never a content-derived value on the no-width pass (which
/// leaked the full height into the enclosing `Form` row as empty space).
final class MultilineTextInputSizingTests: XCTestCase {

    private let minHeight: CGFloat = 110
    private let idealHeight: CGFloat = 160
    private let maxHeight: CGFloat = 240

    func testReportsContentHeightWhenWithinRange() {
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: 300,
            boundsWidth: 0,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight,
            contentHeight: 200
        )

        XCTAssertEqual(size.width, 300)
        XCTAssertEqual(size.height, 200)
    }

    func testClampsTallContentToMaxHeight() {
        // The core fix: a long paste must report maxHeight, not the full content
        // height, so the text view keeps its visible frame and scrolls the overflow
        // instead of being laid out at full height and clipped.
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: 300,
            boundsWidth: 0,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight,
            contentHeight: 800
        )

        XCTAssertEqual(size.height, maxHeight)
    }

    func testClampsShortContentToMinHeight() {
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: 300,
            boundsWidth: 0,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight,
            contentHeight: 40
        )

        XCTAssertEqual(size.height, minHeight)
    }

    func testFallsBackToBoundsWidthWhenProposalWidthIsNil() {
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: nil,
            boundsWidth: 250,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight,
            contentHeight: 130
        )

        XCTAssertEqual(size.width, 250)
        XCTAssertEqual(size.height, 130)
    }

    func testUsesIdealHeightWhenNoContentHeight() {
        // No resolvable width ⇒ the caller measured nothing (contentHeight nil), so
        // the editor reports its ideal height. The full text height can never leak
        // into the Form row on this pass.
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: nil,
            boundsWidth: 0,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight,
            contentHeight: nil
        )

        XCTAssertEqual(size.height, idealHeight)
    }
}
