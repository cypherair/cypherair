import SwiftUI

/// A horizontal strip of tag-filter chips with a trailing "Clear" affordance,
/// shared by the Contacts list and the Encrypt recipient chooser so both surfaces
/// speak the same tag-filter language.
///
/// Renders only the chip row — not a `Section`, header, or `List` — so each caller
/// can wrap it in its own container. `selectedIds` is passed as a value (not a
/// per-chip closure) so membership is an O(1) check and the chip projection isn't
/// recomputed once per chip.
struct TagFilterStrip: View {
    let tags: [ContactTagSummary]
    let selectedIds: Set<String>
    let clearTitle: String
    let toggle: (String) -> Void
    let clear: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(tags) { tag in
                    CypherTagChip(
                        title: tag.displayName,
                        isSelected: selectedIds.contains(tag.tagId),
                        toggle: {
                            withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                toggle(tag.tagId)
                            }
                        }
                    )
                }

                if !selectedIds.isEmpty {
                    Button {
                        withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                            clear()
                        }
                    } label: {
                        Label(clearTitle, systemImage: "xmark.circle")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .transition(.opacity.combined(with: .scale(scale: 0.96)))
                }
            }
        }
    }
}
