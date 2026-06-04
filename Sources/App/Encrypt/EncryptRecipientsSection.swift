import SwiftUI

/// The "Recipients" Form section. Hosts the inline, search-driven recipient
/// chooser when Contacts are available, or a locked notice otherwise.
struct EncryptRecipientsSection: View {
    let model: EncryptScreenModel

    var body: some View {
        Section {
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
        } header: {
            Text(String(localized: "encrypt.recipients", defaultValue: "Recipients"))
        }
    }
}
