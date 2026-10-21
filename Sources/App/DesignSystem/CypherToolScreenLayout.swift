import SwiftUI

/// Width policy for the macOS two-pane tool layout.
enum ToolScreenLayoutPolicy {
    /// Minimum content width before a tool screen splits into side-by-side
    /// panes. The default 900×560 window's detail column measures below this,
    /// so it keeps the single-column form; widened windows get the split.
    static let wideLayoutMinWidth: CGFloat = 700

    static func isWide(width: CGFloat) -> Bool {
        width >= wideLayoutMinWidth
    }
}

/// Shared layout for the Encrypt/Decrypt/Sign/Verify tool screens: the
/// workflow (mode, input, options, primary action) and the output it
/// produces. Where there is room or a fold to respect they are two forms
/// that scroll on their own — the panes of a `CypherSplitArrangement` on iOS
/// and visionOS, side-by-side panes in a wide macOS window — and elsewhere
/// one form with the output below the workflow.
///
/// A finished operation's output settles in rather than snapping: `hasOutput`
/// is the one place all four tools change from working to done, so the reveal
/// is animated here and nowhere else.
struct CypherToolScreenLayout<Workflow: View, Output: View>: View {
    let hasOutput: Bool
    @ViewBuilder let workflow: () -> Workflow
    @ViewBuilder let output: () -> Output

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    #if os(macOS)
    @State private var isWide = false
    #endif

    var body: some View {
        content
            .animation(CypherMotion.resultReveal(reduceMotion: reduceMotion), value: hasOutput)
    }

    @ViewBuilder
    private var content: some View {
        #if os(macOS)
        macContent
            .onGeometryChange(for: CGFloat.self, of: { $0.size.width }) { width in
                isWide = ToolScreenLayoutPolicy.isWide(width: width)
            }
        #else
        CypherSplitArrangement { isSplit in
            Form {
                workflow()

                if !isSplit {
                    output()
                }
            }
            .splitSeamDivider()
        } secondary: {
            outputPane
        }
        .groupedPaneBackground()
        #endif
    }

    #if os(macOS)
    @ViewBuilder
    private var macContent: some View {
        if isWide {
            HStack(alignment: .top, spacing: 0) {
                Form {
                    workflow()
                }
                .frame(minWidth: 380, maxWidth: 640)

                Divider()

                outputPane
                    .frame(minWidth: 320, maxWidth: 760)
            }
            .frame(maxWidth: .infinity, alignment: .center)
        } else {
            Form {
                workflow()
                output()
            }
            .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        }
    }
    #endif

    @ViewBuilder
    private var outputPane: some View {
        if hasOutput {
            Form {
                output()
            }
        } else {
            ContentUnavailableView {
                Label(
                    String(localized: "tool.output.placeholder.title", defaultValue: "No Output Yet"),
                    systemImage: "tray"
                )
            } description: {
                Text(String(
                    localized: "tool.output.placeholder.message",
                    defaultValue: "Results appear here after you run the operation."
                ))
            }
        }
    }
}

/// What Decrypt and Sign show while there is no key of one's own, which both
/// need: why, and the way to Keys, where keys are generated and imported. The
/// button needs a shell that offers its tab selection; the macOS sidebar
/// keeps Keys in view beside the tool instead.
struct CypherToolKeyRequiredView: View {
    let title: String
    let message: String

    @Environment(\.appShellTabSelection) private var shellTabSelection

    var body: some View {
        CypherFoldClearContent {
            ContentUnavailableView {
                Label(title, systemImage: "key.slash")
            } description: {
                Text(message)
            } actions: {
                if let shellTabSelection {
                    Button(String(localized: "tool.keyRequired.openKeys", defaultValue: "Go to Keys")) {
                        shellTabSelection.wrappedValue = .keys
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("tool.keyRequired.openKeys")
                }
            }
        }
    }
}
