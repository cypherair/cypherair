import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif

enum CypherSingleLineTextInputProfile {
    case name
    case email
    case tagName
    case confirmationPhrase
}

enum CypherSecureTextInputProfile {
    case passphrase
}

enum CypherSearchTextInputProfile {
    case search
}

struct CypherSingleLineTextField: View {
    let title: String
    @Binding var text: String
    let profile: CypherSingleLineTextInputProfile
    var submitLabel: SubmitLabel = .done
    var onSubmit: () -> Void = {}

    init(
        _ title: String,
        text: Binding<String>,
        profile: CypherSingleLineTextInputProfile,
        submitLabel: SubmitLabel = .done,
        onSubmit: @escaping () -> Void = {}
    ) {
        self.title = title
        self._text = text
        self.profile = profile
        self.submitLabel = submitLabel
        self.onSubmit = onSubmit
    }

    var body: some View {
        #if os(macOS)
        if MIEWeakTeardownMitigation.isActive {
            // FB23066215 (#499): on macOS 27 a SwiftUI TextField's backing NSTextField
            // faults on teardown under MIE. Use a pooled, never-deallocated NSTextField.
            MIEPooledTextField(text: $text, kind: .plain, placeholder: title, onSubmit: onSubmit)
                .frame(maxWidth: .infinity)
                .privacySensitive()
        } else {
            swiftUIField
        }
        #else
        swiftUIField
        #endif
    }

    private var swiftUIField: some View {
        TextField(title, text: $text)
            .cypherSingleLineTextTraits(profile)
            .submitLabel(submitLabel)
            .onSubmit(onSubmit)
    }
}

struct CypherSecureTextField: View {
    let title: String
    @Binding var text: String
    let profile: CypherSecureTextInputProfile
    var submitLabel: SubmitLabel = .done
    var onSubmit: () -> Void = {}

    init(
        _ title: String,
        text: Binding<String>,
        profile: CypherSecureTextInputProfile = .passphrase,
        submitLabel: SubmitLabel = .done,
        onSubmit: @escaping () -> Void = {}
    ) {
        self.title = title
        self._text = text
        self.profile = profile
        self.submitLabel = submitLabel
        self.onSubmit = onSubmit
    }

    var body: some View {
        #if os(macOS)
        if MIEWeakTeardownMitigation.isActive {
            // FB23066215 (#499): pooled, never-deallocated NSSecureTextField on macOS 27.
            // The field is scrubbed (stringValue = "") on recycle so a reused field never
            // carries a prior passphrase forward; the authoritative passphrase String in
            // the screen model retains the app's existing zeroing.
            MIEPooledTextField(text: $text, kind: .secure, placeholder: title, onSubmit: onSubmit)
                .frame(maxWidth: .infinity)
                .privacySensitive()
        } else {
            swiftUIField
        }
        #else
        swiftUIField
        #endif
    }

    private var swiftUIField: some View {
        SecureField(title, text: $text)
            .cypherSecureTextTraits(profile)
            .submitLabel(submitLabel)
            .onSubmit(onSubmit)
    }
}

extension View {
    @ViewBuilder
    func cypherSearchable(
        text: Binding<String>,
        placement: SearchFieldPlacement = .automatic,
        prompt: String,
        profile: CypherSearchTextInputProfile = .search
    ) -> some View {
        self.searchable(text: text, placement: placement, prompt: prompt)
            .cypherSearchTextTraits(profile)
    }
}

private extension View {
    @ViewBuilder
    func cypherSingleLineTextTraits(_ profile: CypherSingleLineTextInputProfile) -> some View {
        #if canImport(UIKit)
        self.autocorrectionDisabled(true)
            .applyMacWritingToolsPolicy()
            .privacySensitive()
            .keyboardType(profile.keyboardType)
            .textInputAutocapitalization(profile.autocapitalization)
        #else
        self.autocorrectionDisabled(true)
            .applyMacWritingToolsPolicy()
            .privacySensitive()
        #endif
    }

    @ViewBuilder
    func cypherSecureTextTraits(_ profile: CypherSecureTextInputProfile) -> some View {
        switch profile {
        case .passphrase:
            #if canImport(UIKit)
            self.autocorrectionDisabled(true)
                .applyMacWritingToolsPolicy()
                .privacySensitive()
                .textInputAutocapitalization(.never)
            #else
            self.autocorrectionDisabled(true)
                .applyMacWritingToolsPolicy()
                .privacySensitive()
            #endif
        }
    }

    @ViewBuilder
    func cypherSearchTextTraits(_ profile: CypherSearchTextInputProfile) -> some View {
        switch profile {
        case .search:
            #if canImport(UIKit)
            self.autocorrectionDisabled(true)
                .applyMacWritingToolsPolicy()
                .privacySensitive()
                .textInputAutocapitalization(.never)
            #else
            self.autocorrectionDisabled(true)
                .applyMacWritingToolsPolicy()
                .privacySensitive()
            #endif
        }
    }
}

#if canImport(UIKit)
private extension CypherSingleLineTextInputProfile {
    var keyboardType: UIKeyboardType {
        switch self {
        case .email:
            .emailAddress
        case .name, .tagName, .confirmationPhrase:
            .default
        }
    }

    var autocapitalization: TextInputAutocapitalization {
        switch self {
        case .name:
            .words
        case .email, .tagName, .confirmationPhrase:
            .never
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

#if os(macOS)

/// Process-lifetime pool of single-line AppKit fields for the FB23066215 mitigation
/// (issue #499). On macOS 27 (MIE v2) a focused `NSTextField` faults in
/// `weak_clear_no_lock` when it deallocates — and that frame runs *only* inside `dealloc`.
/// So we never deallocate these fields: instances are vended from here and recycled across
/// screens, held alive for the process lifetime by `retained`. Reached only when
/// `MIEWeakTeardownMitigation.isActive` (macOS 27+); remove with the rest of the mitigation
/// once Apple ships a fix.
@MainActor
final class MIEPooledFieldStore {
    static let shared = MIEPooledFieldStore()

    enum Kind { case plain, secure }

    private var availablePlain: [NSTextField] = []
    private var availableSecure: [NSTextField] = []
    private var retained: [NSTextField] = []   // strong, process-lifetime — never released

    func obtain(_ kind: Kind) -> NSTextField {
        switch kind {
        case .plain:
            if let reused = availablePlain.popLast() { return reused }
        case .secure:
            if let reused = availableSecure.popLast() { return reused }
        }
        let field: NSTextField = (kind == .secure) ? NSSecureTextField() : NSTextField()
        configureBaseAppearance(field)
        retained.append(field)
        return field
    }

    func recycle(_ field: NSTextField, kind: Kind) {
        field.abortEditing()
        // Scrub before returning to the pool so a reused field never carries a prior value
        // (including a passphrase) into its next mount. The authoritative passphrase String
        // lives in the screen model and keeps the app's existing zeroing.
        field.stringValue = ""
        field.target = nil
        field.action = nil
        field.delegate = nil
        field.placeholderString = nil
        field.removeFromSuperview()
        switch kind {
        case .plain: availablePlain.append(field)
        case .secure: availableSecure.append(field)
        }
    }

    private func configureBaseAppearance(_ field: NSTextField) {
        field.isBordered = false
        field.isBezeled = false
        field.drawsBackground = false
        field.font = .preferredFont(forTextStyle: .body)
        field.lineBreakMode = .byTruncatingTail
        field.cell?.usesSingleLineMode = true
        field.cell?.wraps = false
        field.cell?.isScrollable = true
        field.isAutomaticTextCompletionEnabled = false
        field.allowsEditingTextAttributes = false
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
    }
}

/// A pooled, never-deallocated single-line field (plain or secure) — FB23066215 mitigation.
/// Drop-in for SwiftUI `TextField`/`SecureField` on macOS 27 inside the Cypher wrappers.
struct MIEPooledTextField: NSViewRepresentable {
    @Binding var text: String
    let kind: MIEPooledFieldStore.Kind
    let placeholder: String
    var onSubmit: () -> Void = {}

    func makeNSView(context: Context) -> NSTextField {
        let field = MIEPooledFieldStore.shared.obtain(kind)
        field.placeholderString = placeholder
        field.stringValue = text
        field.delegate = context.coordinator
        field.target = context.coordinator
        field.action = #selector(Coordinator.handleSubmit(_:))
        return field
    }

    func updateNSView(_ field: NSTextField, context: Context) {
        context.coordinator.parent = self
        field.placeholderString = placeholder
        if field.stringValue != text { field.stringValue = text }
        field.delegate = context.coordinator
        field.target = context.coordinator
        field.action = #selector(Coordinator.handleSubmit(_:))
    }

    static func dismantleNSView(_ field: NSTextField, coordinator: Coordinator) {
        MIEPooledFieldStore.shared.recycle(field, kind: coordinator.kind)
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: MIEPooledTextField
        let kind: MIEPooledFieldStore.Kind

        init(_ parent: MIEPooledTextField) {
            self.parent = parent
            self.kind = parent.kind
        }

        // Mirror the SwiftUI wrappers' autocorrect/smart-substitution policy on the
        // shared field editor when this field starts editing.
        func controlTextDidBeginEditing(_ obj: Notification) {
            guard let editor = (obj.object as? NSTextField)?.currentEditor() as? NSTextView else { return }
            editor.isAutomaticQuoteSubstitutionEnabled = false
            editor.isAutomaticDashSubstitutionEnabled = false
            editor.isAutomaticTextReplacementEnabled = false
            editor.isAutomaticSpellingCorrectionEnabled = false
            editor.isContinuousSpellCheckingEnabled = false
            editor.isAutomaticDataDetectionEnabled = false
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let field = obj.object as? NSTextField else { return }
            parent.text = field.stringValue
        }

        @objc func handleSubmit(_ sender: NSTextField) {
            parent.text = sender.stringValue
            parent.onSubmit()
        }
    }
}
#endif
