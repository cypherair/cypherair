import SwiftUI

struct EncryptRecipientsSection: View {
    let model: EncryptScreenModel
    let openTagPicker: () -> Void

    var body: some View {
        Section {
            if model.contactsAvailability.isAvailable {
                availableRecipientsContent
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

    @ViewBuilder
    private var availableRecipientsContent: some View {
        if !model.recipientTagOptions.isEmpty {
            Button(action: openTagPicker) {
                HStack(spacing: 12) {
                    Label(
                        String(localized: "encrypt.addByTag", defaultValue: "Add from Tag"),
                        systemImage: "tag"
                    )
                    Spacer()
                    Text(recipientTagPickerStatus)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }
            }
            .buttonStyle(.plain)
        }

        HStack {
            Label(
                selectedRecipientsSummary,
                systemImage: "person.2.fill"
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            Spacer()
            Button {
                model.clearRecipients()
            } label: {
                Label(
                    String(localized: "encrypt.clearRecipients", defaultValue: "Clear All"),
                    systemImage: "xmark.circle"
                )
            }
            .controlSize(.small)
            .disabled(model.selectedRecipients.isEmpty)
        }

        if model.encryptableContacts.isEmpty {
            Text(String(localized: "encrypt.recipients.noMatches", defaultValue: "No matching recipients"))
                .foregroundStyle(.secondary)
        }

        ForEach(model.encryptableContacts) { contact in
            Toggle(isOn: Binding(
                get: { model.selectedRecipients.contains(contact.contactId) },
                set: { isOn in
                    model.toggleRecipient(contact.contactId, isOn: isOn)
                }
            )) {
                HStack {
                    compatibilityIndicator(for: contact)
                    VStack(alignment: .leading) {
                        Text(IdentityDisplayPresentation.displayName(contact.displayName))
                        HStack(spacing: 6) {
                            Text(contact.preferredKey.profile.displayName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if !contact.isPreferredKeyVerified {
                                CypherStatusBadge(
                                    title: String(localized: "encrypt.contact.unverified", defaultValue: "Unverified"),
                                    color: .orange
                                )
                            }
                        }
                    }
                }
            }
        }

        if let tagSelectionSkipMessage = model.tagSelectionSkipMessage {
            Label(
                tagSelectionSkipMessage,
                systemImage: "exclamationmark.triangle.fill"
            )
            .font(.footnote)
            .foregroundStyle(.orange)
            Button {
                model.dismissTagSelectionSkipMessage()
            } label: {
                Label(
                    String(localized: "common.dismiss", defaultValue: "Dismiss"),
                    systemImage: "xmark"
                )
            }
        }

        if !model.selectedUnverifiedContacts.isEmpty {
            Label(
                String(
                    localized: "encrypt.unverified.warning",
                    defaultValue: "One or more selected recipients are still unverified. Verify their fingerprints before relying on them."
                ),
                systemImage: "exclamationmark.triangle.fill"
            )
            .font(.footnote)
            .foregroundStyle(.orange)
        }
    }

    private func compatibilityIndicator(for contact: ContactRecipientSummary) -> some View {
        Group {
            if model.defaultKeyVersion == 6 && contact.preferredKey.keyVersion == 4 {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityLabel(String(localized: "encrypt.compat.downgrade", defaultValue: "Format downgrade to SEIPDv1"))
            } else {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .accessibilityLabel(String(localized: "encrypt.compat.ok", defaultValue: "Compatible"))
            }
        }
    }

    private var selectedRecipientsSummary: String {
        String.localizedStringWithFormat(
            String(localized: "encrypt.selectedRecipients.count", defaultValue: "%d recipients selected"),
            model.selectedRecipients.count
        )
    }

    private var recipientTagPickerStatus: String {
        String.localizedStringWithFormat(
            String(localized: "encrypt.tagPicker.availableTags", defaultValue: "%d tags"),
            model.recipientTagOptions.count
        )
    }
}
