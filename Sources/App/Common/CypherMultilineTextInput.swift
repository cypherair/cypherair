import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
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
        if MIEWeakTeardownMitigation.isActive {
            // FB23066215 (#499): on macOS 27 a SwiftUI TextEditor's backing NSTextView
            // faults on teardown under MIE. Use a pooled, never-deallocated NSTextView.
            MIEPooledTextEditor(text: $text, mode: mode)
                .privacySensitive()
                .cypherMacTextEditorChrome()
        } else {
            TextEditor(text: $text)
                .font(font)
                .applyMacWritingToolsPolicy()
                .privacySensitive()
                .cypherMacTextEditorChrome()
        }
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

#if os(macOS)

/// Process-lifetime pool of multiline AppKit text views for the FB23066215 mitigation
/// (issue #499). Same rationale as `MIEPooledFieldStore`: `weak_clear_no_lock` faults only
/// inside `dealloc` under MIE on macOS 27, so we never deallocate the view. We pool the
/// `NSScrollView` (which owns its `NSTextView`) and recycle it across screens, held alive
/// for the process lifetime by `retained`. Reached only when
/// `MIEWeakTeardownMitigation.isActive`; remove with the rest of the mitigation once Apple
/// ships a fix.
@MainActor
final class MIEPooledTextViewStore {
    static let shared = MIEPooledTextViewStore()

    private var available: [NSScrollView] = []
    private var retained: [NSScrollView] = []   // strong, process-lifetime — never released

    func obtain() -> NSScrollView {
        if let reused = available.popLast() { return reused }
        let scroll = NSTextView.scrollableTextView()
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        if let textView = scroll.documentView as? NSTextView {
            textView.drawsBackground = false
            textView.isRichText = false
            textView.allowsUndo = true
            textView.usesFindBar = false
            textView.isAutomaticQuoteSubstitutionEnabled = false
            textView.isAutomaticDashSubstitutionEnabled = false
            textView.isAutomaticTextReplacementEnabled = false
            textView.isAutomaticSpellingCorrectionEnabled = false
            textView.isContinuousSpellCheckingEnabled = false
            textView.isAutomaticDataDetectionEnabled = false
            textView.textContainerInset = NSSize(width: 4, height: 8)
        }
        retained.append(scroll)
        return scroll
    }

    func recycle(_ scroll: NSScrollView) {
        if let textView = scroll.documentView as? NSTextView {
            textView.delegate = nil
            textView.string = ""   // scrub before reuse
        }
        scroll.removeFromSuperview()
        available.append(scroll)
    }
}

/// A pooled, never-deallocated multiline editor — FB23066215 mitigation. Drop-in for
/// SwiftUI `TextEditor` on macOS 27 inside `CypherMultilineTextInput`.
struct MIEPooledTextEditor: NSViewRepresentable {
    @Binding var text: String
    let mode: CypherMultilineTextInputMode

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = MIEPooledTextViewStore.shared.obtain()
        if let textView = scroll.documentView as? NSTextView {
            textView.delegate = context.coordinator
            textView.font = Self.font(for: mode)
            if textView.string != text { textView.string = text }
        }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.parent = self
        guard let textView = scroll.documentView as? NSTextView else { return }
        textView.delegate = context.coordinator
        textView.font = Self.font(for: mode)
        if textView.string != text { textView.string = text }
    }

    static func dismantleNSView(_ scroll: NSScrollView, coordinator: Coordinator) {
        MIEPooledTextViewStore.shared.recycle(scroll)
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    static func font(for mode: CypherMultilineTextInputMode) -> NSFont {
        switch mode {
        case .prose:
            return .preferredFont(forTextStyle: .body)
        case .machineText:
            return .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        }
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: MIEPooledTextEditor

        init(_ parent: MIEPooledTextEditor) {
            self.parent = parent
        }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            parent.text = textView.string
        }
    }
}
#endif
