import SwiftUI

/// A wrapping layout that flows its subviews left-to-right and wraps to a new
/// line when the next subview would exceed the available width.
///
/// Used for the Encrypt recipient chips. Spacing follows the 8-pt grid. Works
/// uniformly on iOS, macOS, and visionOS (the `Layout` protocol is available on
/// all current deployment targets, so no availability guard is needed).
struct CypherChipFlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout Void) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        let rows = computeRows(maxWidth: maxWidth, subviews: subviews)
        let width = proposal.width ?? rows.map(\.width).max() ?? 0
        let height = rows.reduce(0) { $0 + $1.height } + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout Void) {
        let rows = computeRows(maxWidth: bounds.width, subviews: subviews)
        var y = bounds.minY
        for row in rows {
            var x = bounds.minX
            for index in row.indices {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(
                    at: CGPoint(x: x, y: y),
                    anchor: .topLeading,
                    proposal: ProposedViewSize(size)
                )
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row {
        var indices: [Int] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func computeRows(maxWidth: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = []
        var currentRow = Row()
        for index in subviews.indices {
            let size = subviews[index].sizeThatFits(.unspecified)
            let projectedWidth = currentRow.indices.isEmpty
                ? size.width
                : currentRow.width + spacing + size.width
            if !currentRow.indices.isEmpty && projectedWidth > maxWidth {
                rows.append(currentRow)
                currentRow = Row(indices: [index], width: size.width, height: size.height)
            } else {
                currentRow.indices.append(index)
                currentRow.width = projectedWidth
                currentRow.height = max(currentRow.height, size.height)
            }
        }
        if !currentRow.indices.isEmpty {
            rows.append(currentRow)
        }
        return rows
    }
}
