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
        #else
        TextEditor(text: $text)
            .font(font)
            .applyMacWritingToolsPolicy()
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

extension View {
    @ViewBuilder
    func applyMacWritingToolsPolicy() -> some View {
        if #available(macOS 15.0, *) {
            self.writingToolsBehavior(.disabled)
        } else {
            self
        }
    }
}
