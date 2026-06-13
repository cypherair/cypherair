import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

enum CypherMultilineTextInputMode {
    case prose
    case machineText
}

struct CypherMultilineTextInput: View {
    @Binding var text: String
    let mode: CypherMultilineTextInputMode

    var body: some View {
        #if canImport(UIKit)
        CypherMultilineTextInputRepresentable(
            text: $text,
            mode: mode
        )
        .privacySensitive()
        #else
        TextEditor(text: $text)
            .font(font)
            .applyMacWritingToolsPolicy()
            .privacySensitive()
            .cypherMacTextEditorChrome()
        #endif
    }

    private var font: Font {
        switch mode {
        case .prose:
            .body
        case .machineText:
            .system(.body, design: .monospaced)
        }
    }
}

/// Sizing contract for the multiline text editor, kept platform-agnostic so the
/// decision that fixes the Form-row height leak stays unit-testable everywhere.
enum MultilineTextInputSizing {
    /// The size the UIKit representable reports to SwiftUI from `sizeThatFits`.
    ///
    /// The invariant is that this never defers to the text view's own content-based
    /// sizing: when no width is resolvable yet it returns a neutral `fallbackHeight`
    /// rather than nil. Returning nil (or a content-derived height) here is what let
    /// the full pasted-text height leak into the enclosing Form row and produced the
    /// empty space after the first post-paste edit. When a width is available it
    /// reports the measured content height and lets the caller's
    /// `.frame(minHeight:idealHeight:maxHeight:)` clamp it to the visible range.
    static func resolvedSize(
        proposalWidth: CGFloat?,
        boundsWidth: CGFloat,
        fallbackHeight: CGFloat,
        measuredHeight: (CGFloat) -> CGFloat
    ) -> CGSize {
        let width = proposalWidth ?? boundsWidth
        guard width > 0 else {
            return CGSize(width: proposalWidth ?? 0, height: fallbackHeight)
        }
        return CGSize(width: width, height: measuredHeight(width))
    }
}

#if canImport(UIKit)
private struct CypherMultilineTextInputRepresentable: UIViewRepresentable {
    @Binding var text: String
    let mode: CypherMultilineTextInputMode

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeUIView(context: Context) -> CypherHardenedTextView {
        let textView = CypherHardenedTextView()
        textView.delegate = context.coordinator
        textView.backgroundColor = .clear
        textView.isEditable = true
        textView.isSelectable = true
        textView.isScrollEnabled = true
        textView.adjustsFontForContentSizeCategory = true
        textView.inputModeProfile = mode
        textView.text = text
        applyTraits(to: textView)
        return textView
    }

    func updateUIView(_ uiView: CypherHardenedTextView, context: Context) {
        if uiView.text != text {
            uiView.text = text
        }
        uiView.inputModeProfile = mode
        applyTraits(to: uiView)
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: CypherHardenedTextView,
        context: Context
    ) -> CGSize? {
        // Always report a concrete size. The caller's frame clamps the height to
        // its minHeight...maxHeight range, so the editor grows up to the maximum
        // and then scrolls (isScrollEnabled) instead of expanding the Form row.
        MultilineTextInputSizing.resolvedSize(
            proposalWidth: proposal.width,
            boundsWidth: uiView.bounds.width,
            fallbackHeight: Self.defaultMeasuredHeight,
            measuredHeight: { MultilineTextInputSizing.measuredHeight(for: uiView, width: $0) }
        )
    }

    private func applyTraits(to textView: UITextView) {
        textView.font = configuredFont
        textView.textContentType = nil
        textView.allowsEditingTextAttributes = false
        textView.dataDetectorTypes = []

        switch mode {
        case .prose:
            textView.autocorrectionType = .no
            textView.autocapitalizationType = .sentences
            textView.spellCheckingType = .no
            textView.smartQuotesType = .no
            textView.smartDashesType = .no
            textView.smartInsertDeleteType = .no
            textView.keyboardType = .default
        case .machineText:
            textView.autocorrectionType = .no
            textView.autocapitalizationType = .none
            textView.spellCheckingType = .no
            textView.smartQuotesType = .no
            textView.smartDashesType = .no
            textView.smartInsertDeleteType = .no
            textView.keyboardType = .asciiCapable
        }

        if #available(iOS 17.0, *) {
            textView.inlinePredictionType = .no
        }

        if #available(iOS 18.0, *) {
            textView.writingToolsBehavior = .none
            textView.allowedWritingToolsResultOptions = []
            textView.mathExpressionCompletionType = .no
        }

        #if os(iOS)
        if #available(iOS 18.4, *) {
            textView.conversationContext = nil
        }
        #endif

        if #available(iOS 16.0, *) {
            textView.isFindInteractionEnabled = false
        }

        #if os(iOS)
        textView.inputAssistantItem.leadingBarButtonGroups = []
        textView.inputAssistantItem.trailingBarButtonGroups = []
        #endif
        textView.textDragDelegate = nil
        textView.textDropDelegate = nil
        textView.textDragInteraction?.isEnabled = false
    }

    private static let defaultMeasuredHeight: CGFloat = 160

    private var configuredFont: UIFont {
        switch mode {
        case .prose:
            UIFont.preferredFont(forTextStyle: .body)
        case .machineText:
            UIFontMetrics(forTextStyle: .body).scaledFont(
                for: .monospacedSystemFont(ofSize: 17, weight: .regular)
            )
        }
    }

    final class Coordinator: NSObject, UITextViewDelegate {
        @Binding private var text: String

        init(text: Binding<String>) {
            self._text = text
        }

        func textViewDidChange(_ textView: UITextView) {
            let newText = textView.text ?? ""
            guard newText != text else { return }
            text = newText
        }
    }

    final class CypherHardenedTextView: UITextView {
        override var intrinsicContentSize: CGSize {
            CGSize(
                width: UIView.noIntrinsicMetric,
                height: UIView.noIntrinsicMetric
            )
        }

        var inputModeProfile: CypherMultilineTextInputMode = .prose {
            didSet {
                applyInteractionRestrictions()
            }
        }

        override func didMoveToWindow() {
            super.didMoveToWindow()
            applyInteractionRestrictions()
        }

        override func becomeFirstResponder() -> Bool {
            applyInteractionRestrictions()
            return super.becomeFirstResponder()
        }

        override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
            let allowedActions: Set<Selector> = [
                #selector(copy(_:)),
                #selector(paste(_:)),
                #selector(cut(_:)),
                #selector(select(_:)),
                #selector(selectAll(_:)),
                #selector(delete(_:))
            ]

            if allowedActions.contains(action) {
                return super.canPerformAction(action, withSender: sender)
            }

            return false
        }

        private func applyInteractionRestrictions() {
            #if os(iOS)
            inputAssistantItem.leadingBarButtonGroups = []
            inputAssistantItem.trailingBarButtonGroups = []
            #endif
            textDragDelegate = nil
            textDropDelegate = nil
            textDragInteraction?.isEnabled = false
            if #available(iOS 16.0, *) {
                isFindInteractionEnabled = false
            }
        }
    }

}

extension MultilineTextInputSizing {
    /// Height the text view needs to lay out all of its content at `width`.
    static func measuredHeight(for textView: UITextView, width: CGFloat) -> CGFloat {
        textView.sizeThatFits(
            CGSize(width: width, height: .greatestFiniteMagnitude)
        ).height
    }
}
#endif
