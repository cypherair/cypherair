import SwiftUI

struct ContactTagAssignmentSheet: View {
    let availableTags: [ContactTagSummary]
    let assignedTagIds: Set<String>
    let assignExistingTag: (String) throws -> Void
    let createAndAssignTag: (String) throws -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @State private var newTagName = ""
    @State private var errorMessage: String?
    @State private var showError = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if availableAssignableTags.isEmpty {
                        Text(String(localized: "contactdetail.addTag.noExisting", defaultValue: "No available existing tags."))
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(availableAssignableTags) { tag in
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
                newTagName = ""
            }
        }
    }

    private var availableAssignableTags: [ContactTagSummary] {
        availableTags.filter { tag in
            !assignedTagIds.contains(tag.tagId)
        }
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
