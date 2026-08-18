import SwiftUI

/// The app's one way of asking someone to choose a secret: generation offered
/// before the field, the requirements shown while typing, and the confirmation
/// alongside — so no screen invents its own idea of what an acceptable secret
/// is.
///
/// Emits form rows; drop it inside a `Section`. The caller keeps the two
/// strings and decides what an unsatisfied requirement means for its own
/// action, asking `PassphraseRequirements` the same question this view
/// displays.
struct CypherPassphraseEntry: View {
    enum Field: Hashable {
        case passphrase
        case confirmation
    }

    /// Which secret is being chosen, and so which word the surface uses for it.
    ///
    /// The rules, the generator and the layout are identical across purposes —
    /// only the vocabulary and the one sentence about what to do with the
    /// result differ. A key backup is kept; a message password is passed on to
    /// somebody else, and the copy has to say so.
    enum Purpose {
        case keyBackup
        case messagePassword
    }

    let purpose: Purpose
    @Binding var passphrase: String
    @Binding var confirmation: String
    @FocusState.Binding var focus: Field?

    @State private var isRevealed = false
    @State private var isGenerated = false

    private var requirements: PassphraseRequirements {
        PassphraseRequirements(of: passphrase)
    }

    /// Everything the field itself writes is a user edit, which is what makes
    /// the generated-secret note disappear. `generate()` writes the binding
    /// directly and so keeps the flag.
    private var typedPassphrase: Binding<String> {
        Binding(
            get: { passphrase },
            set: { edited in
                passphrase = edited
                isGenerated = false
            }
        )
    }

    var body: some View {
        Button(action: generate) {
            Label(generateTitle, systemImage: "wand.and.sparkles")
        }
        .accessibilityIdentifier("passphrase.generate")

        VStack(alignment: .leading, spacing: CypherSpacing.compact) {
            HStack(spacing: CypherSpacing.compact) {
                CypherSecureTextField(
                    fieldTitle,
                    text: typedPassphrase,
                    isRevealed: isRevealed,
                    submitLabel: .next,
                    onSubmit: { focus = .confirmation }
                )
                .font(isRevealed ? .system(.body, design: .monospaced) : .body)
                .focused($focus, equals: .passphrase)

                revealToggle
            }

            if !passphrase.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    PassphraseRequirementRow(
                        text: String(
                            localized: "passphrase.requirement.length",
                            defaultValue: "At least \(PassphraseRequirements.minimumLength) characters"
                        ),
                        isMet: requirements.isLongEnough
                    )
                    PassphraseRequirementRow(
                        text: String(
                            localized: "passphrase.requirement.noRepeatedRun",
                            defaultValue: "No character repeated \(PassphraseRequirements.maximumConsecutiveRepeats + 1) or more times in a row"
                        ),
                        isMet: requirements.avoidsRepeatedRuns
                    )
                }

                if isGenerated {
                    Text(generatedNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .onChange(of: passphrase) { _, updated in
            if updated.isEmpty {
                isRevealed = false
            }
        }

        CypherSecureTextField(
            confirmationTitle,
            text: $confirmation,
            isRevealed: isRevealed,
            submitLabel: .done,
            onSubmit: { focus = nil }
        )
        .font(isRevealed ? .system(.body, design: .monospaced) : .body)
        .focused($focus, equals: .confirmation)

        if !passphrase.isEmpty, !confirmation.isEmpty, passphrase != confirmation {
            Text(mismatchNote)
                .font(.footnote)
                .foregroundStyle(.red)
        }
    }

    private var revealToggle: some View {
        Button {
            isRevealed.toggle()
        } label: {
            Image(systemName: isRevealed ? "eye.slash" : "eye")
        }
        .buttonStyle(.borderless)
        .accessibilityLabel(isRevealed ? hideTitle : showTitle)
    }

    /// Fills both fields: a secret nobody chose is a secret nobody can mistype,
    /// so asking for it twice would only be ceremony. It is revealed because a
    /// value the user has never seen has to be written down before it protects
    /// anything.
    private func generate() {
        guard let generated = try? PassphraseGenerator.generate() else {
            // The system random source reported failure. Nothing weaker is an
            // acceptable substitute, so the fields keep what they held.
            return
        }
        focus = nil
        passphrase = generated
        confirmation = generated
        isRevealed = true
        isGenerated = true
    }

    // MARK: Vocabulary

    private var generateTitle: String {
        switch purpose {
        case .keyBackup:
            String(localized: "passphrase.generate", defaultValue: "Generate a Strong Passphrase")
        case .messagePassword:
            String(localized: "password.generate", defaultValue: "Generate a Strong Password")
        }
    }

    private var fieldTitle: String {
        switch purpose {
        case .keyBackup:
            String(localized: "passphrase.field", defaultValue: "Passphrase")
        case .messagePassword:
            String(localized: "password.field", defaultValue: "Password")
        }
    }

    private var confirmationTitle: String {
        switch purpose {
        case .keyBackup:
            String(localized: "passphrase.confirm", defaultValue: "Confirm Passphrase")
        case .messagePassword:
            String(localized: "password.confirm", defaultValue: "Confirm Password")
        }
    }

    private var generatedNote: String {
        switch purpose {
        case .keyBackup:
            String(
                localized: "passphrase.generated.note",
                defaultValue: "Write it down and keep it somewhere safe. It is stored nowhere, and no one can recover it for you."
            )
        case .messagePassword:
            String(
                localized: "password.generated.note",
                defaultValue: "Write it down before you send the message. It is stored nowhere, and the message cannot be opened without it."
            )
        }
    }

    private var mismatchNote: String {
        switch purpose {
        case .keyBackup:
            String(localized: "passphrase.mismatch", defaultValue: "Passphrases do not match.")
        case .messagePassword:
            String(localized: "password.mismatch", defaultValue: "Passwords do not match.")
        }
    }

    private var showTitle: String {
        switch purpose {
        case .keyBackup:
            String(localized: "passphrase.show", defaultValue: "Show Passphrase")
        case .messagePassword:
            String(localized: "password.show", defaultValue: "Show Password")
        }
    }

    private var hideTitle: String {
        switch purpose {
        case .keyBackup:
            String(localized: "passphrase.hide", defaultValue: "Hide Passphrase")
        case .messagePassword:
            String(localized: "password.hide", defaultValue: "Hide Password")
        }
    }
}

/// One requirement and whether the secret has reached it yet. Unmet reads as
/// "not there yet" rather than as an error: nothing here is a mistake the user
/// has already made.
private struct PassphraseRequirementRow: View {
    let text: String
    let isMet: Bool

    var body: some View {
        Label {
            Text(text)
                .font(.footnote)
                .foregroundStyle(isMet ? .primary : .secondary)
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: isMet ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(isMet ? Color.green : Color.secondary)
                .font(.footnote)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(text)
        .accessibilityValue(
            isMet
                ? String(localized: "passphrase.requirement.met", defaultValue: "Met")
                : String(localized: "passphrase.requirement.unmet", defaultValue: "Not met yet")
        )
    }
}
