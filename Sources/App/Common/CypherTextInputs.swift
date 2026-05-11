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
