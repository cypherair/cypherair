import Foundation
import XCTest
@testable import CypherAir

/// Guards the sizing contract behind the iOS multiline-input fix: the editor must
/// always report a bounded, concrete height to SwiftUI and must never let the text
/// view's own content height leak into the enclosing `Form` row. The leak was what
/// produced the large empty space after the first edit following a long paste.
final class MultilineTextInputSizingTests: XCTestCase {

    // MARK: - resolvedSize contract (platform-agnostic)

    func testResolvedSizeReportsMeasuredHeightForProposedWidth() {
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: 300,
            boundsWidth: 0,
            fallbackHeight: 160,
            measuredHeight: { _ in 512 }
        )

        XCTAssertEqual(size.width, 300)
        XCTAssertEqual(size.height, 512)
    }

    func testResolvedSizeFallsBackToBoundsWidthWhenProposalIsNil() {
        var measuredWidth: CGFloat?
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: nil,
            boundsWidth: 250,
            fallbackHeight: 160,
            measuredHeight: { width in
                measuredWidth = width
                return 88
            }
        )

        XCTAssertEqual(measuredWidth, 250)
        XCTAssertEqual(size.width, 250)
        XCTAssertEqual(size.height, 88)
    }

    func testResolvedSizeReturnsFallbackHeightAndSkipsMeasurementWhenNoWidth() {
        // The regression guard: with no resolvable width (SwiftUI's unspecified
        // measurement pass), the editor must report a bounded fallback height and
        // must NOT derive its height from content. Deferring to content-based
        // sizing on this pass is exactly what leaked the full pasted-text height
        // into the Form row.
        var didMeasure = false
        let size = MultilineTextInputSizing.resolvedSize(
            proposalWidth: nil,
            boundsWidth: 0,
            fallbackHeight: 160,
            measuredHeight: { _ in
                didMeasure = true
                return 9_999
            }
        )

        XCTAssertFalse(didMeasure, "Height must not be measured from content when no width is available")
        XCTAssertEqual(size.height, 160)
    }
}
