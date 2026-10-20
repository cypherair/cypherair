import SwiftUI

/// A screen's two related parts in a split `ArrangementView`: side by side
/// or one above the other in a regular-width, regular-height container, on
/// either side of a fold whenever one crosses the container, and in one
/// column everywhere else, where `primary` shows the secondary content
/// itself (its argument is `false` then).
///
/// The arrangement stays the same view in every pose and only its style
/// changes, so state inside `primary` (typed text, an open editor) survives
/// folding, unfolding and rotating. A sheet on the inner display of iPhone
/// Duo is compact width yet spans the fold, which is why the fold decides on
/// its own.
struct CypherSplitArrangement<Primary: View, Secondary: View>: View {
    @ViewBuilder let primary: (_ isSplit: Bool) -> Primary
    @ViewBuilder let secondary: () -> Secondary

    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    @State private var isFoldActive = false

    var body: some View {
        let isSplit = isFoldActive
            || (horizontalSizeClass == .regular && verticalSizeClass == .regular)

        ArrangementView {
            primary(isSplit)
                .environment(\.splitPane, isSplit ? .primary : nil)
        } secondary: {
            if isSplit {
                secondary()
                    .environment(\.splitPane, .secondary)
            }
        }
        .arrangementViewStyle(isSplit ? .split : .split.axes([]))
        .tracksActiveFold($isFoldActive)
    }
}

/// One view kept clear of a fold: full size on a flat display, and beside or
/// above the fold while one crosses it.
struct CypherFoldClearContent<Content: View>: View {
    @ViewBuilder let content: () -> Content

    @State private var isFoldActive = false

    var body: some View {
        ArrangementView {
            content()
        } secondary: {
            EmptyView()
        }
        .arrangementViewStyle(isFoldActive ? .split : .split.axes([]))
        .tracksActiveFold($isFoldActive)
    }
}

extension View {
    /// Fills its pane of a `CypherSplitArrangement` and, while the panes are
    /// stacked, sits against the edge they share, so the two parts of a
    /// short screen meet at the fold instead of floating in the middles of
    /// their halves. Centred side by side and in one column.
    func alignedTowardSplit() -> some View {
        modifier(SplitPaneAlignment())
    }

    /// The scroll view form of `alignedTowardSplit()`: content shorter than
    /// its pane sits against the shared edge while the panes are stacked,
    /// and starts at the top as usual otherwise.
    func scrollAlignedTowardSplit() -> some View {
        modifier(SplitPaneScrollAlignment())
    }

    /// Draws a hairline along the bottom of a primary pane stacked above the
    /// secondary, where the primary's scrolling content is cut off; without
    /// it a row half hidden at that edge looks clipped by mistake.
    func splitSeamDivider() -> some View {
        modifier(SplitSeamDivider())
    }

    /// Gives a split arrangement of grouped forms or lists their grouped
    /// background, so the gap at a fold and a pane without a form belong to
    /// the same surface as the forms beside them.
    func groupedPaneBackground() -> some View {
        #if os(iOS)
        background(Color(uiColor: .systemGroupedBackground))
        #else
        self
        #endif
    }

    fileprivate func tracksActiveFold(_ isActive: Binding<Bool>) -> some View {
        onGeometryChange(for: Bool.self) { proxy in
            proxy.activeFold != nil
        } action: { isFolded in
            isActive.wrappedValue = isFolded
        }
    }
}

extension GeometryProxy {
    /// The frame of an active fold that cuts this view in two, in its own
    /// coordinates. A fold that only runs along an edge does not count: a
    /// sheet the system moves beside the fold still reports the fold's
    /// margin overlapping its edge.
    var activeFold: CGRect? {
        reservedRegions(kind: .division)
            .map(\.frame)
            .first { fold in
                fold.height > fold.width
                    ? fold.minX > 0 && fold.maxX < size.width
                    : fold.minY > 0 && fold.maxY < size.height
            }
    }
}

private enum SplitPane {
    case primary
    case secondary
}

extension EnvironmentValues {
    /// Which pane of a split `CypherSplitArrangement` a view is in; nil in
    /// one column.
    @Entry fileprivate var splitPane: SplitPane? = nil
}

private struct SplitPaneAlignment: ViewModifier {
    @Environment(\.splitPane) private var pane
    @Environment(\.splitArrangementAxis) private var axis

    func body(content: Content) -> some View {
        content
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: alignment)
    }

    private var alignment: Alignment {
        guard axis == .vertical, let pane else { return .center }
        return pane == .primary ? .bottom : .top
    }
}

private struct SplitPaneScrollAlignment: ViewModifier {
    @Environment(\.splitPane) private var pane
    @Environment(\.splitArrangementAxis) private var axis

    func body(content: Content) -> some View {
        content
            .defaultScrollAnchor(anchor, for: .alignment)
    }

    private var anchor: UnitPoint? {
        guard axis == .vertical, let pane else { return nil }
        return pane == .primary ? .bottom : .top
    }
}

private struct SplitSeamDivider: ViewModifier {
    @Environment(\.splitPane) private var pane
    @Environment(\.splitArrangementAxis) private var axis

    func body(content: Content) -> some View {
        content
            .overlay(alignment: .bottom) {
                if pane == .primary, axis == .vertical {
                    Divider()
                }
            }
    }
}
