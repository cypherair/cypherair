import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

enum CypherMultilineTextInputMode {
    case prose
    case machineText
}

/// Shared multi-line text input for the tool screens.
///
/// On UIKit platforms the Form row is a tap target that opens a dedicated
/// full-height editor sheet. The editor must not live inline in the Form row:
/// SwiftUI's Form sizes a `UITextView`-backed row to the text view's own
/// content height and ignores every cap short of a definite frame, so a long
/// paste balloons the row into a blank unscrollable area (issue #513, PR #510).
/// macOS keeps the inline `TextEditor`, which is unaffected.
struct CypherMultilineTextInput: View {
    @Binding var text: String
    let mode: CypherMultilineTextInputMode
    let title: String

    var body: some View {
        #if canImport(UIKit)
        CypherMultilineInputRow(
            text: $text,
            mode: mode,
            title: title
        )
        #else
        TextEditor(text: $text)
            .font(mode.editorFont)
            .applyMacWritingToolsPolicy()
            .privacySensitive()
            .cypherMacTextEditorChrome()
            .frame(minHeight: 120, idealHeight: 170, maxHeight: 240)
            .accessibilityLabel(title)
        #endif
    }
}

private extension CypherMultilineTextInputMode {
    var editorFont: Font {
        switch self {
        case .prose:
            .body
        case .machineText:
            .system(.body, design: .monospaced)
        }
    }

    var placeholder: String {
        switch self {
        case .prose:
            String(localized: "multilineInput.placeholder.prose", defaultValue: "Tap to write or paste…")
        case .machineText:
            String(localized: "multilineInput.placeholder.machine", defaultValue: "Tap to paste…")
        }
    }
}

#if canImport(UIKit)
private struct CypherMultilineInputRow: View {
    @Binding var text: String
    let mode: CypherMultilineTextInputMode
    let title: String

    @State private var isEditorPresented = false
    @Environment(\.isEnabled) private var isEnabled
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator: AppSessionOrchestrator?

    var body: some View {
        Button {
            isEditorPresented = true
        } label: {
            HStack(alignment: .top, spacing: CypherSpacing.tight) {
                previewText
                    .frame(maxWidth: .infinity, alignment: .leading)
                Image(systemName: "square.and.pencil")
                    .foregroundStyle(isEnabled ? AnyShapeStyle(.secondary) : AnyShapeStyle(.tertiary))
                    .accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .sheet(isPresented: $isEditorPresented) {
            CypherMultilineEditorSheet(
                text: $text,
                mode: mode,
                title: title
            )
        }
        // The relock signal (docs/SECURITY.md session model): the sheet is
        // window-level and floats above the in-hierarchy lock surface, so it
        // must dismiss itself when content clears.
        .onChange(of: appSessionOrchestrator?.contentClearGeneration) { _, _ in
            isEditorPresented = false
        }
    }

    @ViewBuilder
    private var previewText: some View {
        if text.isEmpty {
            Text(mode.placeholder)
                .foregroundStyle(isEnabled ? AnyShapeStyle(.secondary) : AnyShapeStyle(.tertiary))
        } else {
            // Cap what Text has to lay out; five body lines never need more
            // than a few hundred characters, and pastes can be megabytes.
            Text(String(text.prefix(400)))
                .font(mode.editorFont)
                .lineLimit(5)
                .foregroundStyle(isEnabled ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
                .privacySensitive()
        }
    }
}

private struct CypherMultilineEditorSheet: View {
    @Binding var text: String
    let mode: CypherMultilineTextInputMode
    let title: String

    @Environment(\.dismiss) private var dismiss
    @Environment(AppLockController.self) private var appLockController: AppLockController?

    var body: some View {
        NavigationStack {
            CypherMultilineTextInputRepresentable(
                text: $text,
                mode: mode
            )
            .privacySensitive()
            .navigationTitle(title)
            .toolbarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "common.done", defaultValue: "Done")) {
                        dismiss()
                    }
                }
            }
        }
        // The sheet escapes the main window content's cosmetic cover, so it
        // carries its own (docs/SECURITY.md: sensitive content never appears
        // in the app-switcher snapshot). Binds the same resolve-aware predicate
        // so it holds across a foreground return while the editor is open.
        .cosmeticPrivacyCover(isCovered: appLockController?.isCosmeticallyCovered ?? false)
    }
}

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
        textView.alwaysBounceVertical = true
        textView.textContainerInset = UIEdgeInsets(
            top: CypherSpacing.tight,
            left: CypherSpacing.tight,
            bottom: CypherSpacing.tight,
            right: CypherSpacing.tight
        )
        textView.adjustsFontForContentSizeCategory = true
        textView.inputModeProfile = mode
        textView.autoFocusesOnWindowAttach = true
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

        var autoFocusesOnWindowAttach = false

        override func didMoveToWindow() {
            super.didMoveToWindow()
            applyInteractionRestrictions()
            if window != nil, autoFocusesOnWindowAttach {
                autoFocusesOnWindowAttach = false
                Task { @MainActor [weak self] in
                    _ = self?.becomeFirstResponder()
                }
            }
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
