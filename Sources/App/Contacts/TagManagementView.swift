import SwiftUI

struct TagManagementView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator

    var body: some View {
        TagManagementHostView(
            contactService: contactService,
            appSessionOrchestrator: appSessionOrchestrator
        )
    }
}

private struct TagManagementHostView: View {
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: TagManagementScreenModel

    init(contactService: ContactService, appSessionOrchestrator: AppSessionOrchestrator) {
        self.appSessionOrchestrator = appSessionOrchestrator
        _model = State(initialValue: TagManagementScreenModel(contactService: contactService))
    }

    var body: some View {
        @Bindable var model = model

        Group {
            if model.canManageTags {
                managementContent(model: model)
            } else {
                tagManagementUnavailableContent(model.contactsAvailability)
            }
        }
        .navigationTitle(String(localized: "tagManagement.title", defaultValue: "Manage Tags"))
        .cypherSearchable(
            text: $model.searchText,
            placement: .automatic,
            prompt: String(localized: "tagManagement.search", defaultValue: "Search tags")
        )
        .onAppear {
            model.handleAppear()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            model.clearTransientInput()
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { model.showError },
                set: { if !$0 { model.dismissError() } }
            )
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: {
            if let errorMessage = model.errorMessage {
                Text(errorMessage)
            }
        }
        .confirmationDialog(
            String(localized: "tagManagement.delete.title", defaultValue: "Delete Tag"),
            isPresented: Binding(
                get: { model.pendingDeleteTag != nil },
                set: { if !$0 { model.cancelDeleteTag() } }
            ),
            titleVisibility: .visible,
            presenting: model.pendingDeleteTag
        ) { _ in
            Button(String(localized: "tagManagement.delete.confirm", defaultValue: "Delete Tag"), role: .destructive) {
                model.confirmDeleteTag()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {
                model.cancelDeleteTag()
            }
        } message: { tag in
            Text(
                String.localizedStringWithFormat(
                    String(
                        localized: "tagManagement.delete.message",
                        defaultValue: "Delete \"%@\" and remove it from all contacts?"
                    ),
                    tag.displayName
                )
            )
        }
    }

    @ViewBuilder
    private func managementContent(model: TagManagementScreenModel) -> some View {
        @Bindable var model = model

        Form {
            Section {
                CypherSingleLineTextField(
                    String(localized: "tagManagement.create.field", defaultValue: "Tag Name"),
                    text: $model.createTagName,
                    profile: .tagName,
                    submitLabel: .done,
                    onSubmit: model.createTagIfValid
                )
                Button {
                    model.createTag()
                } label: {
                    Label(
                        String(localized: "tagManagement.create", defaultValue: "Create Tag"),
                        systemImage: "tag.badge.plus"
                    )
                }
                .disabled(ContactTag.displayName(for: model.createTagName).isEmpty)
            } header: {
                Text(String(localized: "tagManagement.create.header", defaultValue: "New Tag"))
            }

            Section {
                if model.visibleTags.isEmpty {
                    Text(emptyTagListMessage(model: model))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.visibleTags) { tag in
                        Button {
                            model.selectTag(tag.tagId)
                        } label: {
                            HStack {
                                Label(tag.displayName, systemImage: "tag")
                                Spacer()
                                Text(contactCountText(tag.contactCount))
                                    .foregroundStyle(.secondary)
                                if model.selectedTagId == tag.tagId {
                                    Image(systemName: "checkmark")
                                        .foregroundStyle(.tint)
                                }
                            }
                        }
                    }
                }
            } header: {
                Text(String(localized: "tagManagement.tags", defaultValue: "Tags"))
            }

            if let selectedTag = model.selectedTag {
                selectedTagSection(selectedTag, model: model)
                membersSection(selectedTag, model: model)
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
    }

    private func selectedTagSection(
        _ selectedTag: ContactTagSummary,
        model: TagManagementScreenModel
    ) -> some View {
        @Bindable var model = model

        return Section {
            if model.isRenamingSelectedTag {
                CypherSingleLineTextField(
                    String(localized: "tagManagement.rename.field", defaultValue: "Tag Name"),
                    text: $model.renameText,
                    profile: .tagName,
                    submitLabel: .done,
                    onSubmit: model.commitRenameSelectedTagIfValid
                )
                Button {
                    model.commitRenameSelectedTag()
                } label: {
                    Label(
                        String(localized: "tagManagement.rename.save", defaultValue: "Save Name"),
                        systemImage: "checkmark"
                    )
                }
                .disabled(ContactTag.displayName(for: model.renameText).isEmpty)
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    model.cancelRename()
                }
            } else {
                LabeledContent(
                    String(localized: "tagManagement.selected.name", defaultValue: "Name"),
                    value: selectedTag.displayName
                )
                LabeledContent(
                    String(localized: "tagManagement.selected.members", defaultValue: "Members"),
                    value: contactCountText(selectedTag.contactCount)
                )
                Button {
                    model.beginRenameSelectedTag()
                } label: {
                    Label(
                        String(localized: "tagManagement.rename", defaultValue: "Rename Tag"),
                        systemImage: "pencil"
                    )
                }
                Button(role: .destructive) {
                    model.requestDeleteSelectedTag()
                } label: {
                    Label(
                        String(localized: "tagManagement.delete", defaultValue: "Delete Tag"),
                        systemImage: "trash"
                    )
                }
            }
        } header: {
            Text(String(localized: "tagManagement.selected", defaultValue: "Selected Tag"))
        }
    }

    private func membersSection(
        _ selectedTag: ContactTagSummary,
        model: TagManagementScreenModel
    ) -> some View {
        Section {
            if model.contacts.isEmpty {
                Text(String(localized: "tagManagement.members.empty", defaultValue: "No contacts available."))
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.contacts) { contact in
                    Toggle(isOn: Binding(
                        get: { model.membershipDraftContactIds.contains(contact.contactId) },
                        set: { isMember in
                            model.setMembership(contactId: contact.contactId, isMember: isMember)
                        }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(contact.displayName)
                            if let email = contact.primaryEmail {
                                Text(email)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }

            if model.hasMembershipDraftChanges {
                Button {
                    model.saveMembership()
                } label: {
                    Label(
                        String(localized: "tagManagement.members.save", defaultValue: "Save Members"),
                        systemImage: "checkmark.circle"
                    )
                }
                Button {
                    model.resetMembershipDraft()
                } label: {
                    Label(
                        String(localized: "tagManagement.members.revert", defaultValue: "Revert Changes"),
                        systemImage: "arrow.uturn.backward"
                    )
                }
            }
        } header: {
            Text(
                String.localizedStringWithFormat(
                    String(localized: "tagManagement.members.header", defaultValue: "Members of %@"),
                    selectedTag.displayName
                )
            )
        }
    }

    private func tagManagementUnavailableContent(_ availability: ContactsAvailability) -> some View {
        ContentUnavailableView {
            Label(tagManagementUnavailableTitle(availability), systemImage: "tag")
        } description: {
            Text(tagManagementUnavailableDescription(availability))
        } actions: {
            if availability == .opening {
                ProgressView()
            }
        }
    }

    private func tagManagementUnavailableTitle(_ availability: ContactsAvailability) -> String {
        if availability.isAvailable {
            return String(
                localized: "tagManagement.unavailable.protectedTitle",
                defaultValue: "Protected Contacts Required"
            )
        }
        return availability.unavailableTitle
    }

    private func tagManagementUnavailableDescription(_ availability: ContactsAvailability) -> String {
        if availability.isAvailable {
            return String(
                localized: "tagManagement.unavailable.protectedDescription",
                defaultValue: "Tag management is available when Contacts are backed by protected app data."
            )
        }
        return availability.unavailableDescription
    }

    private func emptyTagListMessage(model: TagManagementScreenModel) -> String {
        if ContactsSearchIndex.normalizedSearchText(model.searchText).isEmpty {
            return String(localized: "tagManagement.empty", defaultValue: "No tags yet.")
        }
        return String(localized: "tagManagement.noMatchingTags", defaultValue: "No matching tags.")
    }

    private func contactCountText(_ count: Int) -> String {
        String.localizedStringWithFormat(
            String(localized: "tagManagement.contactCount", defaultValue: "%d contacts"),
            count
        )
    }
}
