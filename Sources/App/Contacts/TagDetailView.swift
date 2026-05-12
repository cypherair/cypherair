import SwiftUI

struct TagDetailView: View {
    let tagId: String

    @Environment(ContactService.self) private var contactService
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator

    var body: some View {
        TagDetailHostView(
            tagId: tagId,
            contactService: contactService,
            appSessionOrchestrator: appSessionOrchestrator
        )
    }
}

private struct TagDetailHostView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let appSessionOrchestrator: AppSessionOrchestrator
    @State private var model: TagDetailScreenModel

    init(
        tagId: String,
        contactService: ContactService,
        appSessionOrchestrator: AppSessionOrchestrator
    ) {
        self.appSessionOrchestrator = appSessionOrchestrator
        _model = State(initialValue: TagDetailScreenModel(tagId: tagId, contactService: contactService))
    }

    var body: some View {
        @Bindable var model = model

        Group {
            if !model.contactsAvailability.isAvailable {
                tagManagementUnavailableContent(model.contactsAvailability)
            } else if !model.canManageTag {
                tagManagementUnavailableContent(model.contactsAvailability)
            } else if let tag = model.tag {
                tagDetailContent(tag: tag)
            } else {
                ContentUnavailableView(
                    String(localized: "tagManagement.detail.notFound", defaultValue: "Tag Not Found"),
                    systemImage: "tag.slash"
                )
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
        .navigationTitle(model.tag?.displayName ?? String(localized: "tagManagement.detail.title", defaultValue: "Tag"))
        .toolbar {
            toolbarContent
        }
        .sheet(isPresented: $model.isRenamingTag) {
            RenameTagSheet(model: model)
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
                if model.confirmDeleteTag() {
                    dismiss()
                }
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
        .confirmationDialog(
            String(localized: "tagManagement.members.discard.title", defaultValue: "Discard Member Changes?"),
            isPresented: $model.showDiscardMemberChangesConfirmation,
            titleVisibility: .visible
        ) {
            Button(String(localized: "tagManagement.members.discard.confirm", defaultValue: "Discard Changes"), role: .destructive) {
                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                    model.cancelMemberEditing()
                }
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: {
            Text(String(localized: "tagManagement.members.discard.message", defaultValue: "Your unsaved member changes will be lost."))
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
        .onAppear {
            model.handleAppear()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            model.clearTransientInput()
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        if model.isEditingMembers {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                        model.requestCancelMemberEditing()
                    }
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button(String(localized: "common.save", defaultValue: "Save")) {
                    withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                        model.saveMembership()
                    }
                }
                .disabled(!model.canSaveMembershipDraft)
            }
        } else if model.canManageTag && model.tag != nil {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(String(localized: "common.edit", defaultValue: "Edit")) {
                    withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                        model.beginMemberEditing()
                    }
                }
                Menu {
                    Button {
                        model.beginRenameTag()
                    } label: {
                        Label(
                            String(localized: "tagManagement.rename", defaultValue: "Rename Tag"),
                            systemImage: "pencil"
                        )
                    }
                    Button(role: .destructive) {
                        model.requestDeleteTag()
                    } label: {
                        Label(
                            String(localized: "tagManagement.delete", defaultValue: "Delete Tag"),
                            systemImage: "trash"
                        )
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .accessibilityLabel(String(localized: "tagManagement.detail.more", defaultValue: "More Tag Actions"))
            }
        }
    }

    private func tagDetailContent(tag: ContactTagSummary) -> some View {
        List {
            Section {
                LabeledContent(
                    String(localized: "tagManagement.selected.members", defaultValue: "Members"),
                    value: model.memberCountText
                )
            }

            Section {
                if model.isEditingMembers {
                    editableSavedMemberContactsList
                } else {
                    memberContactsList
                }
            } header: {
                Text(
                    model.isEditingMembers
                        ? String(localized: "tagManagement.members.current", defaultValue: "Current Members")
                        : String.localizedStringWithFormat(
                            String(localized: "tagManagement.members.header", defaultValue: "Members of %@"),
                            tag.displayName
                        )
                )
            }

            if model.isEditingMembers {
                Section {
                    editableAvailableContactsList
                } header: {
                    Text(String(localized: "tagManagement.members.available", defaultValue: "Available Contacts"))
                }
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        .animation(
            CypherMotion.quickEaseOut(reduceMotion: reduceMotion),
            value: model.isEditingMembers
        )
        .animation(
            CypherMotion.quickEaseOut(reduceMotion: reduceMotion),
            value: model.savedMemberContactIds
        )
        .animation(
            CypherMotion.quickEaseOut(reduceMotion: reduceMotion),
            value: model.savedAvailableContactIds
        )
        .animation(
            CypherMotion.quickEaseOut(reduceMotion: reduceMotion),
            value: model.membershipDraftContactIds
        )
    }

    @ViewBuilder
    private var memberContactsList: some View {
        if model.visibleMemberContacts.isEmpty {
            Text(String(localized: "tagManagement.members.none", defaultValue: "No members yet."))
                .foregroundStyle(.secondary)
        } else {
            ForEach(model.visibleMemberContacts) { contact in
                ContactMemberRow(contact: contact, isSelected: true, showsCheckmark: false)
            }
        }
    }

    @ViewBuilder
    private var editableSavedMemberContactsList: some View {
        if model.savedMemberContacts.isEmpty {
            Text(String(localized: "tagManagement.members.none", defaultValue: "No members yet."))
                .foregroundStyle(.secondary)
        } else {
            editableContactRows(model.savedMemberContacts)
        }
    }

    @ViewBuilder
    private var editableAvailableContactsList: some View {
        if model.savedAvailableContacts.isEmpty {
            Text(String(localized: "tagManagement.members.empty", defaultValue: "No contacts available."))
                .foregroundStyle(.secondary)
        } else {
            editableContactRows(model.savedAvailableContacts)
        }
    }

    @ViewBuilder
    private func editableContactRows(_ contacts: [ContactIdentitySummary]) -> some View {
        ForEach(contacts) { contact in
            let isSelected = model.membershipDraftContactIds.contains(contact.contactId)
            Button {
                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                    model.toggleDraftMembership(contactId: contact.contactId)
                }
            } label: {
                ContactMemberRow(
                    contact: contact,
                    isSelected: isSelected,
                    showsCheckmark: true
                )
            }
            .buttonStyle(.plain)
            .accessibilityLabel(accessibilityLabel(for: contact, isSelected: isSelected))
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

    private func accessibilityLabel(for contact: ContactIdentitySummary, isSelected: Bool) -> String {
        let state = isSelected
            ? String(localized: "tagManagement.members.selected", defaultValue: "Selected")
            : String(localized: "tagManagement.members.notSelected", defaultValue: "Not selected")
        if let email = contact.primaryEmail {
            return "\(contact.displayName), \(email), \(state)"
        }
        return "\(contact.displayName), \(state)"
    }
}

private struct ContactMemberRow: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let contact: ContactIdentitySummary
    let isSelected: Bool
    let showsCheckmark: Bool

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(contact.displayName)
                    .foregroundStyle(.primary)
                if let email = contact.primaryEmail {
                    Text(email)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if showsCheckmark {
                ZStack {
                    Image(systemName: "circle")
                        .foregroundStyle(Color.secondary)
                        .opacity(isSelected ? 0 : 1)
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(Color.accentColor)
                        .opacity(isSelected ? 1 : 0)
                }
                .imageScale(.large)
                .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: isSelected)
                .accessibilityHidden(true)
            }
        }
        .contentShape(Rectangle())
    }
}

private struct RenameTagSheet: View {
    let model: TagDetailScreenModel

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        @Bindable var model = model

        NavigationStack {
            Form {
                Section {
                    CypherSingleLineTextField(
                        String(localized: "tagManagement.rename.field", defaultValue: "Tag Name"),
                        text: $model.renameText,
                        profile: .tagName,
                        submitLabel: .done,
                        onSubmit: save
                    )
                }
            }
            .navigationTitle(String(localized: "tagManagement.rename", defaultValue: "Rename Tag"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                        model.cancelRenameTag()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button(String(localized: "common.save", defaultValue: "Save")) {
                        save()
                    }
                    .disabled(!model.canCommitRename)
                }
            }
        }
    }

    private func save() {
        guard model.canCommitRename else {
            return
        }
        model.commitRenameTag()
        if !model.isRenamingTag {
            dismiss()
        }
    }
}
