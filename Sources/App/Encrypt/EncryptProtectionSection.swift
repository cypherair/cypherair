import SwiftUI

/// The one place the Encrypt screen says what will hold the message shut.
///
/// The choice is exclusive by construction rather than by validation: a single
/// picker selects it, and the section below shows only what that choice needs —
/// recipients, or a password, never both. There is no state in which the screen
/// holds a recipient selection *and* a password that would both reach the
/// message, so "encrypted to keys and to a password" is not a thing the user
/// can accidentally build.
///
/// Signing and Encrypt to Self live in the options section, which the form hides
/// under password protection for the same reason: both are things done with the
/// sender's own keys, and a password message uses none.
struct EncryptProtectionSection: View {
    let model: EncryptScreenModel
    @FocusState.Binding var passwordFocus: CypherPassphraseEntry.Field?

    var body: some View {
        @Bindable var model = model

        Section {
            if model.isPasswordProtectionAvailable {
                CypherModePicker(
                    title: String(localized: "encrypt.protection", defaultValue: "Protect With"),
                    selection: $model.protection,
                    selectedValueLabel: model.protection.label,
                    isDisabled: model.operation.isRunning,
                    accessibilityIdentifier: "encrypt.protection.picker"
                ) {
                    ForEach(EncryptView.Protection.allCases, id: \.self) { protection in
                        Text(protection.label).tag(protection)
                    }
                }
            }

            switch model.activeProtection {
            case .recipientKeys:
                recipientsContent
            case .password:
                passwordContent
            }
        } header: {
            Text(headerTitle)
        } footer: {
            if model.activeProtection == .password {
                Text(String(
                    localized: "encrypt.password.stake",
                    defaultValue: "A password message is exactly as strong as its password. Anyone who gets the message can keep guessing at it offline, for as long as they like — so unless the password is strong, this protects the message less than encrypting to a key does. Send the password by a different route than the message."
                ))
            }
        }
    }

    private var headerTitle: String {
        model.isPasswordProtectionAvailable
            ? String(localized: "encrypt.protection", defaultValue: "Protect With")
            : String(localized: "encrypt.recipients", defaultValue: "Recipients")
    }

    @ViewBuilder
    private var recipientsContent: some View {
        if model.contactsAvailability.isAvailable {
            EncryptRecipientChooser(model: model)
        } else {
            Label(
                model.contactsAvailability.unavailableDescription,
                systemImage: "lock"
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var passwordContent: some View {
        @Bindable var model = model

        CypherPassphraseEntry(
            purpose: .messagePassword,
            passphrase: $model.password,
            confirmation: $model.passwordConfirmation,
            focus: $passwordFocus
        )

        Label(
            String(
                localized: "encrypt.password.noKeysUsed",
                defaultValue: "None of your keys are used: the message is not signed, and no copy is encrypted to you."
            ),
            systemImage: "key.slash"
        )
        .font(.footnote)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
}
