import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

enum CypherSingleLineTextInputProfile {
    case name
    case email
    case tagName
    case confirmationPhrase
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
        TextField(title, text: $text)
            .cypherSingleLineTextTraits(profile)
            .submitLabel(submitLabel)
            .onSubmit(onSubmit)
    }
}

struct CypherSecureTextField: View {
    let title: String
    @Binding var text: String
    /// Shows the text in the clear. A passphrase the user has to transcribe
    /// somewhere safe is unreadable behind dots.
    let isRevealed: Bool
    let submitLabel: SubmitLabel
    let onSubmit: () -> Void

    init(
        _ title: String,
        text: Binding<String>,
        isRevealed: Bool = false,
        submitLabel: SubmitLabel = .done,
        onSubmit: @escaping () -> Void = {}
    ) {
        self.title = title
        self._text = text
        self.isRevealed = isRevealed
        self.submitLabel = submitLabel
        self.onSubmit = onSubmit
    }

    var body: some View {
        Group {
            if isRevealed {
                TextField(title, text: $text)
            } else {
                SecureField(title, text: $text)
            }
        }
        .cypherOpaqueTextTraits()
        .submitLabel(submitLabel)
        .onSubmit(onSubmit)
    }
}

extension View {
    @ViewBuilder
    func cypherSearchable(
        text: Binding<String>,
        prompt: String
    ) -> some View {
        self.searchable(text: text, prompt: prompt)
            .cypherOpaqueTextTraits()
    }

    /// A search field only where there is something to search. `.searchable`
    /// has no "absent" state to bind to, so the modifier is applied or not —
    /// which does change view identity, and is why the caller should be a
    /// screen whose content is changing wholesale anyway.
    @ViewBuilder
    func cypherSearchable(
        when isSearchable: Bool,
        text: Binding<String>,
        prompt: String
    ) -> some View {
        if isSearchable {
            cypherSearchable(text: text, prompt: prompt)
        } else {
            self
        }
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

    /// Traits for text the keyboard must not learn from or transform: passphrases
    /// and search terms over contact data.
    @ViewBuilder
    func cypherOpaqueTextTraits() -> some View {
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
    func applyMacWritingToolsPolicy() -> some View {
        self.writingToolsBehavior(.disabled)
    }
}
