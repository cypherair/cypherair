import SwiftUI
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif

enum MacPresentationWidth {
    static let standard: CGFloat = 760
    static let textHeavy: CGFloat = 860
    static let themeGrid: CGFloat = 640
    static let qrContent: CGFloat = 360
    static let onboarding: CGFloat = 560
}

struct CypherStatusBadge: View {
    let title: String
    let color: Color

    var body: some View {
        Text(title)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.14), in: Capsule())
            .foregroundStyle(color)
    }
}

struct CypherClearImportedFileButton: View {
    let accessibilityLabel: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "xmark.circle.fill")
                .foregroundStyle(.secondary)
                #if os(macOS)
                .font(.body)
                .frame(width: 22, height: 22)
                #else
                .frame(minWidth: 44, minHeight: 44)
                #endif
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(accessibilityLabel)
    }
}

struct CypherOutputTextBlock: View {
    let text: String
    var font: Font = .system(.caption, design: .monospaced)
    var minHeight: CGFloat = 96
    var maxHeight: CGFloat = 260

    var body: some View {
        ScrollView {
            Text(text)
                .font(font)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
        }
        .frame(minHeight: minHeight, maxHeight: maxHeight)
        .background(outputTextSurface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.08), lineWidth: 1)
        }
    }

    private var outputTextSurface: Color {
        #if canImport(AppKit)
        Color(nsColor: .textBackgroundColor)
        #elseif canImport(UIKit)
        Color(uiColor: .secondarySystemGroupedBackground)
        #else
        Color.primary.opacity(0.04)
        #endif
    }
}

struct CypherScrollableTextLine: View {
    let text: String
    var font: Font = .system(.footnote, design: .monospaced)

    var body: some View {
        ScrollView(.horizontal, showsIndicators: true) {
            Text(verbatim: text)
                .font(font)
                .textSelection(.enabled)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.vertical, 1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct CypherImportedFileRow: View {
    let fileName: String
    let clearAccessibilityLabel: String
    let clearAction: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    Image(systemName: "doc.fill")
                        .accessibilityHidden(true)
                    Text(verbatim: fileName)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: true, vertical: false)
                }
                .padding(.vertical, 2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(fileName)

            CypherClearImportedFileButton(
                accessibilityLabel: clearAccessibilityLabel,
                action: clearAction
            )
        }
    }
}

extension View {
    @ViewBuilder
    func cypherMacReadableContent(
        maxWidth: CGFloat = MacPresentationWidth.standard,
        alignment: Alignment = .topLeading,
        outerAlignment: Alignment = .top
    ) -> some View {
        #if os(macOS)
        self
            .frame(maxWidth: maxWidth, alignment: alignment)
            .frame(maxWidth: .infinity, alignment: outerAlignment)
        #else
        self
        #endif
    }

    @ViewBuilder
    func cypherPrimaryActionLabelFrame(minWidth: CGFloat = 180) -> some View {
        #if os(macOS)
        self.frame(minWidth: minWidth)
        #else
        self.frame(maxWidth: .infinity)
        #endif
    }

    @ViewBuilder
    func cypherMacTextEditorChrome() -> some View {
        #if os(macOS)
        self
            .scrollContentBackground(.hidden)
            .padding(8)
            .background(macTextEditorSurface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.08), lineWidth: 1)
            }
        #else
        self
        #endif
    }

    @ViewBuilder
    func cypherMacCardSurface(cornerRadius: CGFloat = 8) -> some View {
        #if os(macOS)
        self
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        #else
        self
        #endif
    }

    #if os(macOS)
    private var macTextEditorSurface: Color {
        #if canImport(AppKit)
        Color(nsColor: .textBackgroundColor)
        #else
        Color.clear
        #endif
    }
    #endif
}
