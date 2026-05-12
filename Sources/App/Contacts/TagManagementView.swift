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
    @Environment(\.appRouteNavigator) private var routeNavigator
    let appSessionOrchestrator: AppSessionOrchestrator

    @State private var model: TagManagementScreenModel
    @State private var isCreateTagSheetPresented = false

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
        .toolbar {
            if model.canManageTags {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        isCreateTagSheetPresented = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel(String(localized: "tagManagement.create", defaultValue: "Create Tag"))
                }
            }
        }
        .sheet(isPresented: $isCreateTagSheetPresented) {
            CreateTagSheet(model: model) { tag in
                isCreateTagSheetPresented = false
                routeNavigator.open(.tagDetail(tagId: tag.tagId))
            }
        }
        .onAppear {
            model.handleAppear()
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            model.clearTransientInput()
            isCreateTagSheetPresented = false
        }
    }

    @ViewBuilder
    private func managementContent(model: TagManagementScreenModel) -> some View {
        List {
            Section {
                if model.visibleTags.isEmpty {
                    Text(emptyTagListMessage(model: model))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.visibleTags) { tag in
                        NavigationLink(value: AppRoute.tagDetail(tagId: tag.tagId)) {
                            HStack {
                                Label(tag.displayName, systemImage: "tag")
                                Spacer()
                                Text(contactCountText(tag.contactCount))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            } header: {
                Text(String(localized: "tagManagement.tags", defaultValue: "Tags"))
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
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

private struct CreateTagSheet: View {
    let model: TagManagementScreenModel
    let onCreated: (ContactTagSummary) -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        @Bindable var model = model

        NavigationStack {
            Form {
                Section {
                    CypherSingleLineTextField(
                        String(localized: "tagManagement.create.field", defaultValue: "Tag Name"),
                        text: $model.createTagName,
                        profile: .tagName,
                        submitLabel: .done,
                        onSubmit: create
                    )
                }
            }
            .navigationTitle(String(localized: "tagManagement.create.header", defaultValue: "New Tag"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                        model.createTagName = ""
                        dismiss()
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button(String(localized: "tagManagement.create", defaultValue: "Create Tag")) {
                        create()
                    }
                    .disabled(ContactTag.displayName(for: model.createTagName).isEmpty)
                }
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
        }
    }

    private func create() {
        guard let tag = model.createTagIfValid() else {
            return
        }
        dismiss()
        onCreated(tag)
    }
}
