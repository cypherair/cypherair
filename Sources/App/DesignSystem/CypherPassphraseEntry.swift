import SwiftUI

/// The app's one way of asking someone to choose a passphrase: generation
/// offered before the field, strength shown while typing, and the confirmation
/// alongside — so no screen invents its own idea of what a passphrase has to be.
///
/// Emits form rows; drop it inside a `Section`. The caller keeps the two
/// strings and decides what a passphrase that fails the gate means for its own
/// action, asking `PassphraseStrengthEstimator` the same question this view
/// displays.
struct CypherPassphraseEntry: View {
    enum Field: Hashable {
        case passphrase
        case confirmation
    }

    @Binding var passphrase: String
    @Binding var confirmation: String
    @FocusState.Binding var focus: Field?

    @State private var isRevealed = false
    @State private var isGenerated = false

    private var strength: PassphraseStrength {
        PassphraseStrengthEstimator.estimate(passphrase)
    }

    /// Everything the field itself writes is a user edit, which is what makes
    /// the generated-passphrase note disappear. `generate()` writes the binding
    /// directly and so keeps the flag.
    private var typedPassphrase: Binding<String> {
        Binding(
            get: { passphrase },
            set: { edited in
                passphrase = edited
                isGenerated = false
                if edited.isEmpty {
                    isRevealed = false
                }
            }
        )
    }

    var body: some View {
        Button(action: generate) {
            Label(
                String(localized: "passphrase.generate", defaultValue: "Generate a Strong Passphrase"),
                systemImage: "wand.and.sparkles"
            )
        }

        VStack(alignment: .leading, spacing: CypherSpacing.compact) {
            HStack(spacing: CypherSpacing.compact) {
                CypherSecureTextField(
                    String(localized: "passphrase.field", defaultValue: "Passphrase"),
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
                PassphraseStrengthMeter(strength: strength)

                if isGenerated {
                    guidance(
                        String(
                            localized: "passphrase.generated.note",
                            defaultValue: "Write it down and keep it somewhere safe. It is stored nowhere, and no one can recover it for you."
                        )
                    )
                } else if !strength.isAcceptable {
                    guidance(
                        String(
                            localized: "passphrase.tooWeak",
                            defaultValue: "Guessing is the attack a passphrase has to survive, and length is what beats it. Add more characters, or generate one."
                        )
                    )
                }
            }
        }
        .onChange(of: passphrase) { _, updated in
            if updated.isEmpty {
                isRevealed = false
            }
        }

        CypherSecureTextField(
            String(localized: "passphrase.confirm", defaultValue: "Confirm Passphrase"),
            text: $confirmation,
            isRevealed: isRevealed,
            submitLabel: .done,
            onSubmit: { focus = nil }
        )
        .font(isRevealed ? .system(.body, design: .monospaced) : .body)
        .focused($focus, equals: .confirmation)

        if !passphrase.isEmpty, !confirmation.isEmpty, passphrase != confirmation {
            Text(String(localized: "passphrase.mismatch", defaultValue: "Passphrases do not match."))
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
        .accessibilityLabel(
            isRevealed
                ? String(localized: "passphrase.hide", defaultValue: "Hide Passphrase")
                : String(localized: "passphrase.show", defaultValue: "Show Passphrase")
        )
    }

    private func guidance(_ text: String) -> some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Fills both fields: a passphrase nobody chose is a passphrase nobody can
    /// mistype, so asking for it twice would only be ceremony. It is revealed
    /// because a value the user has never seen has to be written down before it
    /// protects anything.
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
}

private struct PassphraseStrengthMeter: View {
    let strength: PassphraseStrength

    private static let segments = 4

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
                ForEach(0..<Self.segments, id: \.self) { segment in
                    Capsule()
                        .fill(segment < strength.tier.filledSegments ? strength.tier.tint : unfilled)
                        .frame(height: 4)
                }
            }

            Text(strength.tier.title)
                .font(.footnote)
                .foregroundStyle(strength.isAcceptable ? .secondary : strength.tier.tint)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(String(localized: "passphrase.strength", defaultValue: "Passphrase strength"))
        .accessibilityValue(strength.tier.title)
    }

    private var unfilled: Color {
        Color.secondary.opacity(0.25)
    }
}

/// The meter is only drawn for a passphrase that has something in it, so
/// `.empty` renders as nothing rather than as a verdict.
private extension PassphraseStrengthTier {
    var filledSegments: Int { rawValue }

    var tint: Color {
        switch self {
        case .empty:
            .secondary
        case .veryWeak:
            .red
        case .weak:
            .orange
        case .good, .strong:
            .green
        }
    }

    var title: String {
        switch self {
        case .empty:
            ""
        case .veryWeak:
            String(localized: "passphrase.strength.veryWeak", defaultValue: "Very weak")
        case .weak:
            String(localized: "passphrase.strength.weak", defaultValue: "Weak")
        case .good:
            String(localized: "passphrase.strength.good", defaultValue: "Good")
        case .strong:
            String(localized: "passphrase.strength.strong", defaultValue: "Strong")
        }
    }
}
