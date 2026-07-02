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

/// Shared layout for the Encrypt/Decrypt/Sign/Verify tool screens: a single
/// scrolling `Form` everywhere, except on wide macOS windows where the
/// interactive workflow (input, options, primary action) and the produced
/// output sit in side-by-side panes.
struct CypherToolScreenLayout<Workflow: View, Output: View>: View {
    let hasOutput: Bool
    @ViewBuilder let workflow: () -> Workflow
    @ViewBuilder let output: () -> Output

    #if os(macOS)
    @State private var isWide = false
    #endif

    var body: some View {
        #if os(macOS)
        macContent
            .onGeometryChange(for: CGFloat.self, of: { $0.size.width }) { width in
                isWide = ToolScreenLayoutPolicy.isWide(width: width)
            }
        #else
        singleColumnForm
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

                Group {
                    if hasOutput {
                        Form {
                            output()
                        }
                    } else {
                        outputPlaceholder
                    }
                }
                .frame(minWidth: 320, maxWidth: 760)
            }
            .frame(maxWidth: .infinity, alignment: .center)
        } else {
            singleColumnForm
                .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
        }
    }

    private var outputPlaceholder: some View {
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
    #endif

    private var singleColumnForm: some View {
        Form {
            workflow()
            output()
        }
    }
}
