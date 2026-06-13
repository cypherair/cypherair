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
    var minHeight: CGFloat = 110
    var idealHeight: CGFloat = 160
    var maxHeight: CGFloat = 240

    #if canImport(UIKit)
    // The text view's measured content height (0 until first layout). SwiftUI's
    // Form sizes a UITextView-backed row to the text view's own content height and
    // ignores sizeThatFits / intrinsicContentSize / range frames, so we measure the
    // content ourselves and pin the editor to a *definite* height instead.
    @State private var measuredContentHeight: CGFloat = 0
    #endif

    var body: some View {
        #if canImport(UIKit)
        CypherMultilineTextInputRepresentable(
            text: $text,
            mode: mode,
            measuredContentHeight: $measuredContentHeight
        )
        .frame(height: MultilineTextInputSizing.editorHeight(
            contentHeight: measuredContentHeight,
            minHeight: minHeight,
            idealHeight: idealHeight,
            maxHeight: maxHeight
        ))
        .privacySensitive()
        #else
        TextEditor(text: $text)
            .font(font)
            .applyMacWritingToolsPolicy()
            .privacySensitive()
            .cypherMacTextEditorChrome()
            .frame(minHeight: minHeight, idealHeight: idealHeight, maxHeight: maxHeight)
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

/// Sizing decision for the multiline editor, kept platform-agnostic so it stays unit-testable.
enum MultilineTextInputSizing {
    /// The editor's definite height for a measured content height, clamped to the
    /// visible `minHeight...maxHeight` range so it grows with content up to the
    /// maximum and then scrolls internally. `contentHeight <= 0` means the content
    /// has not been measured yet, in which case the editor sits at `idealHeight`.
    static func editorHeight(
        contentHeight: CGFloat,
        minHeight: CGFloat,
        idealHeight: CGFloat,
        maxHeight: CGFloat
    ) -> CGFloat {
        let base = contentHeight > 0 ? contentHeight : idealHeight
        return min(max(base, minHeight), maxHeight)
    }
}

#if canImport(UIKit)
private struct CypherMultilineTextInputRepresentable: UIViewRepresentable {
    @Binding var text: String
    let mode: CypherMultilineTextInputMode
    @Binding var measuredContentHeight: CGFloat

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text, measuredContentHeight: $measuredContentHeight)
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
        let coordinator = context.coordinator
        textView.onLayout = { [weak textView] in
            guard let textView else { return }
            coordinator.reportContentHeight(of: textView)
        }
        applyTraits(to: textView)
        return textView
    }

    func updateUIView(_ uiView: CypherHardenedTextView, context: Context) {
        context.coordinator.measuredContentHeight = $measuredContentHeight
        if uiView.text != text {
            uiView.text = text
        }
        uiView.inputModeProfile = mode
        applyTraits(to: uiView)
        context.coordinator.reportContentHeight(of: uiView)
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
        var measuredContentHeight: Binding<CGFloat>
        private var lastReportedHeight: CGFloat = -1

        init(text: Binding<String>, measuredContentHeight: Binding<CGFloat>) {
            self._text = text
            self.measuredContentHeight = measuredContentHeight
        }

        func textViewDidChange(_ textView: UITextView) {
            let newText = textView.text ?? ""
            if newText != text {
                text = newText
            }
            reportContentHeight(of: textView)
        }

        /// Measures the height the content needs at the current width and pushes it
        /// back to SwiftUI (guarded against no-op churn). Dispatched async because
        /// this is also called from `updateUIView`, where mutating state inline is
        /// disallowed.
        func reportContentHeight(of textView: UITextView) {
            let width = textView.bounds.width
            guard width > 0 else { return }
            let height = textView.sizeThatFits(
                CGSize(width: width, height: .greatestFiniteMagnitude)
            ).height
            guard abs(height - lastReportedHeight) > 0.5 else { return }
            lastReportedHeight = height
            let binding = measuredContentHeight
            DispatchQueue.main.async {
                binding.wrappedValue = height
            }
        }
    }

    final class CypherHardenedTextView: UITextView {
        var onLayout: (() -> Void)?

        override func layoutSubviews() {
            super.layoutSubviews()
            onLayout?()
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
#endif
