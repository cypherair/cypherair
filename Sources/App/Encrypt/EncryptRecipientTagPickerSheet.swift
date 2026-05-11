import SwiftUI

struct RecipientTagPickerSheet: View {
    let model: EncryptScreenModel

    @Environment(\.dismiss) private var dismiss
    @State private var searchText = ""

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        Label(
                            selectedRecipientsSummary,
                            systemImage: "person.2.fill"
                        )
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
                        .disabled(model.selectedRecipients.isEmpty)
                    }
                }

                Section {
                    if filteredTagOptions.isEmpty {
                        Text(emptyTagListMessage)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(filteredTagOptions) { tagOption in
                            RecipientTagPickerRow(
                                tagOption: tagOption,
                                selectedCount: model.selectedRecipientCount(for: tagOption),
                                add: {
                                    model.selectRecipients(withTagId: tagOption.tagId)
                                }
                            )
                        }
                    }
                } header: {
                    Text(String(localized: "tagManagement.tags", defaultValue: "Tags"))
                }

                if let tagSelectionSkipMessage = model.tagSelectionSkipMessage {
                    Section {
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
                }
            }
            .scrollDismissesKeyboardInteractivelyIfAvailable()
            .navigationTitle(String(localized: "encrypt.addByTag", defaultValue: "Add by Tag"))
            .searchable(
                text: $searchText,
                placement: .automatic,
                prompt: String(localized: "tagManagement.search", defaultValue: "Search tags")
            )
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "common.done", defaultValue: "Done")) {
                        dismiss()
                    }
                }
            }
        }
    }

    private var filteredTagOptions: [RecipientTagSelectionOption] {
        let normalizedSearchText = ContactsSearchIndex.normalizedSearchText(searchText)
        guard !normalizedSearchText.isEmpty else {
            return model.recipientTagOptions
        }
        return model.recipientTagOptions.filter { tagOption in
            ContactsSearchIndex.normalizedSearchText(tagOption.displayName)
                .contains(normalizedSearchText)
        }
    }

    private var selectedRecipientsSummary: String {
        String.localizedStringWithFormat(
            String(localized: "encrypt.selectedRecipients.count", defaultValue: "%d recipients selected"),
            model.selectedRecipients.count
        )
    }

    private var emptyTagListMessage: String {
        if ContactsSearchIndex.normalizedSearchText(searchText).isEmpty {
            return String(localized: "tagManagement.empty", defaultValue: "No tags yet.")
        }
        return String(localized: "tagManagement.noMatchingTags", defaultValue: "No matching tags.")
    }
}

private struct RecipientTagPickerRow: View {
    let tagOption: RecipientTagSelectionOption
    let selectedCount: Int
    let add: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Label(tagOption.displayName, systemImage: "tag")
                    .font(.body)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(tagOption.skippedContactCount > 0 ? Color.orange : Color.secondary)
            }
            Spacer()
            Button {
                add()
            } label: {
                Label(actionTitle, systemImage: isFullySelected ? "checkmark.circle.fill" : "plus.circle")
                    .labelStyle(.titleAndIcon)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(isActionDisabled)
        }
    }

    private var isFullySelected: Bool {
        !tagOption.selectableContactIds.isEmpty &&
            selectedCount >= tagOption.selectableContactIds.count
    }

    private var isActionDisabled: Bool {
        tagOption.selectableContactIds.isEmpty || isFullySelected
    }

    private var actionTitle: String {
        if isFullySelected {
            return String(localized: "encrypt.tagPicker.added", defaultValue: "Added")
        }
        return String(localized: "encrypt.tagPicker.add", defaultValue: "Add")
    }

    private var subtitle: String {
        if tagOption.skippedContactCount > 0 {
            return String.localizedStringWithFormat(
                String(
                    localized: "encrypt.tagSelection.subtitleWithSkipped",
                    defaultValue: "%1$d available, %2$d skipped"
                ),
                tagOption.selectableContactIds.count,
                tagOption.skippedContactCount
            )
        }
        if selectedCount > 0 {
            return String.localizedStringWithFormat(
                String(localized: "encrypt.tagSelection.subtitleSelected", defaultValue: "%1$d of %2$d selected"),
                selectedCount,
                tagOption.selectableContactIds.count
            )
        }
        return String.localizedStringWithFormat(
            String(localized: "encrypt.tagSelection.subtitle", defaultValue: "%d available"),
            tagOption.selectableContactIds.count
        )
    }
}
