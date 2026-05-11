import SwiftUI

struct ContactTagAssignmentSheet: View {
    let availableTags: [ContactTagSummary]
    let assignedTagIds: Set<String>
    let assignExistingTag: (String) throws -> Void
    let createAndAssignTag: (String) throws -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @State private var searchText = ""
    @State private var newTagName = ""
    @State private var errorMessage: String?
    @State private var showError = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if assignableTags.isEmpty {
                        Text(emptyExistingTagMessage)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(assignableTags) { tag in
                            Button {
                                assign(tag)
                            } label: {
                                Label(tag.displayName, systemImage: "tag")
                            }
                        }
                    }
                } header: {
                    Text(String(localized: "contactdetail.addTag.existing", defaultValue: "Existing Tags"))
                }

                Section {
                    CypherSingleLineTextField(
                        String(localized: "contactdetail.addTag.field", defaultValue: "Tag Name"),
                        text: $newTagName,
                        profile: .tagName,
                        submitLabel: .done,
                        onSubmit: create
                    )
                    Button {
                        create()
                    } label: {
                        Label(
                            String(localized: "contactdetail.addTag.create", defaultValue: "Create and Add Tag"),
                            systemImage: "tag.badge.plus"
                        )
                    }
                    .disabled(ContactTag.displayName(for: newTagName).isEmpty)
                } header: {
                    Text(String(localized: "contactdetail.addTag.new", defaultValue: "New Tag"))
                }
            }
            .scrollDismissesKeyboardInteractivelyIfAvailable()
            .navigationTitle(String(localized: "contactdetail.addTag.title", defaultValue: "Add Tag"))
            .cypherSearchable(
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
            .alert(
                String(localized: "error.title", defaultValue: "Error"),
                isPresented: $showError
            ) {
                Button(String(localized: "error.ok", defaultValue: "OK")) {}
            } message: {
                if let errorMessage {
                    Text(errorMessage)
                }
            }
            .onChange(of: appSessionOrchestrator.contentClearGeneration) {
                searchText = ""
                newTagName = ""
            }
        }
    }

    private var assignableTags: [ContactTagSummary] {
        let normalizedSearchText = ContactsSearchIndex.normalizedSearchText(searchText)
        return availableTags.filter { tag in
            guard !assignedTagIds.contains(tag.tagId) else {
                return false
            }
            guard !normalizedSearchText.isEmpty else {
                return true
            }
            return ContactsSearchIndex.normalizedSearchText(tag.displayName)
                .contains(normalizedSearchText)
        }
    }

    private var emptyExistingTagMessage: String {
        if ContactsSearchIndex.normalizedSearchText(searchText).isEmpty {
            return String(
                localized: "contactdetail.addTag.noExisting",
                defaultValue: "No available existing tags."
            )
        }
        return String(
            localized: "tagManagement.noMatchingTags",
            defaultValue: "No matching tags."
        )
    }

    private func assign(_ tag: ContactTagSummary) {
        do {
            try assignExistingTag(tag.tagId)
            dismiss()
        } catch {
            presentError(error)
        }
    }

    private func create() {
        do {
            try createAndAssignTag(newTagName)
            dismiss()
        } catch {
            presentError(error)
        }
    }

    private func presentError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
