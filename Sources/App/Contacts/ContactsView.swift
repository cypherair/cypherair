import SwiftUI

/// Lists imported contacts (public keys).
struct ContactsView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator

    var body: some View {
        ContactsScreenHostView(
            contactService: contactService,
            appSessionOrchestrator: appSessionOrchestrator
        )
    }
}

private struct ContactsScreenHostView: View {
    @Environment(\.appRouteNavigator) private var routeNavigator
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let appSessionOrchestrator: AppSessionOrchestrator
    @State private var model: ContactsScreenModel

    init(contactService: ContactService, appSessionOrchestrator: AppSessionOrchestrator) {
        self.appSessionOrchestrator = appSessionOrchestrator
        _model = State(initialValue: ContactsScreenModel(contactService: contactService))
    }

    var body: some View {
        @Bindable var model = model

        Group {
            if model.contactsAvailability.isAvailable {
                contactsList
            } else {
                contactsUnavailableContent(model.contactsAvailability)
            }
        }
        .navigationTitle(String(localized: "contacts.title", defaultValue: "Contacts"))
        .cypherSearchable(
            text: $model.searchText,
            placement: .automatic,
            prompt: String(
                localized: "contacts.search.prompt",
                defaultValue: "Names, email, tags, fingerprints"
            )
        )
        .searchSuggestions {
            ForEach(model.tagSuggestions.prefix(6)) { tag in
                Button {
                    withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                        model.applyTagSuggestion(tag.tagId)
                    }
                } label: {
                    Label(tag.displayName, systemImage: "tag")
                }
            }
        }
        .toolbar {
            if model.contactsAvailability.isAvailable {
                ToolbarItemGroup(placement: .primaryAction) {
                    if model.canManageTags {
                        Button {
                            routeNavigator.open(.tagManagement)
                        } label: {
                            Image(systemName: "tag")
                        }
                        .accessibilityIdentifier("contacts.tags.toolbar")
                        .accessibilityLabel(String(localized: "contacts.manageTags", defaultValue: "Manage Tags"))
                    }

                    Button {
                        routeNavigator.open(.addContact)
                    } label: {
                        Image(systemName: "plus")
                    }
                    .tutorialAnchor(.contactsAddButton)
                    .accessibilityIdentifier("contacts.add.toolbar")
                    .accessibilityLabel(String(localized: "contacts.add", defaultValue: "Add Contact"))
                }
            }
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $model.showDeleteError
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: {
            if let deleteError = model.deleteError {
                Text(deleteError)
            }
        }
        .onChange(of: appSessionOrchestrator.contentClearGeneration) {
            model.clearTransientInput()
        }
    }
}

private extension ContactsScreenHostView {
    var contactsList: some View {
        let contacts = model.visibleContacts

        return List {
            if !model.tagFilters.isEmpty {
                Section {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(model.tagFilters) { tag in
                                TagFilterChipButton(
                                    tag: tag,
                                    isSelected: model.isTagFilterSelected(tag.tagId),
                                    toggle: {
                                        withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                            model.toggleTagFilter(tag.tagId)
                                        }
                                    }
                                )
                            }

                            if !model.selectedTagFilters.isEmpty {
                                Button {
                                    withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                        model.clearTagFilters()
                                    }
                                } label: {
                                    Label(
                                        String(localized: "contacts.clearTagFilters", defaultValue: "Clear"),
                                        systemImage: "xmark.circle"
                                    )
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .transition(.opacity.combined(with: .scale(scale: 0.96)))
                            }
                        }
                    }
                } header: {
                    Text(String(localized: "contacts.filterTags", defaultValue: "Filter Tags"))
                }
            }

            ForEach(contacts) { contact in
                NavigationLink(value: AppRoute.contactDetail(contactId: contact.contactId)) {
                    ContactRowView(contact: contact)
                }
                .accessibilityIdentifier("contacts.row")
            }
            .onDelete { indexSet in
                model.deleteContacts(at: indexSet, from: contacts)
            }
        }
        .scrollDismissesKeyboardInteractivelyIfAvailable()
        .overlay {
            if contacts.isEmpty {
                if model.hasActiveSearchOrFilters {
                    noResultsContent
                        .transition(.opacity)
                } else {
                    emptyStateContent
                        .transition(.opacity)
                }
            }
        }
        .animation(
            CypherMotion.quickEaseOut(reduceMotion: reduceMotion),
            value: contacts.map(\.contactId)
        )
        .animation(
            CypherMotion.quickEaseOut(reduceMotion: reduceMotion),
            value: model.selectedTagFilterIds
        )
        .animation(
            CypherMotion.quickEaseOut(reduceMotion: reduceMotion),
            value: model.hasActiveSearchOrFilters
        )
        .cypherMacReadableContent()
    }

    func contactsUnavailableContent(_ availability: ContactsAvailability) -> some View {
        ContentUnavailableView {
            Label(availability.unavailableTitle, systemImage: systemImage(for: availability))
        } description: {
            Text(availability.unavailableDescription)
        } actions: {
            if availability == .opening {
                ProgressView()
            }
        }
    }

    var emptyStateContent: some View {
        ContentUnavailableView {
            Label(
                String(localized: "contacts.empty.title", defaultValue: "No Contacts"),
                systemImage: "person.slash"
            )
        } description: {
            Text(String(localized: "contacts.empty.description", defaultValue: "Add a friend's public key to start encrypting messages to them."))
        } actions: {
            Button {
                routeNavigator.open(.addContact)
            } label: {
                Text(String(localized: "contacts.add", defaultValue: "Add Contact"))
            }
            .buttonStyle(.borderedProminent)
            .tutorialAnchor(.contactsAddButton)
            .accessibilityIdentifier("contacts.add")
        }
    }

    var noResultsContent: some View {
        ContentUnavailableView {
            Label(
                String(localized: "contacts.search.noResults.title", defaultValue: "No Matching Contacts"),
                systemImage: "magnifyingglass"
            )
        } description: {
            Text(String(localized: "contacts.search.noResults.description", defaultValue: "Try a different name, email, tag, fingerprint, or key ID."))
        }
    }

    func systemImage(for availability: ContactsAvailability) -> String {
        switch availability {
        case .opening:
            "lock.open"
        case .locked:
            "lock"
        case .recoveryNeeded:
            "exclamationmark.triangle"
        case .frameworkUnavailable:
            "externaldrive.badge.exclamationmark"
        case .restartRequired:
            "arrow.clockwise"
        case .availableLegacyCompatibility, .availableProtectedDomain:
            "person.2"
        }
    }
}

private struct ContactRowView: View {
    let contact: ContactIdentitySummary

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(IdentityDisplayPresentation.displayName(contact.displayName))
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                if contact.hasUnverifiedKeys {
                    CypherStatusBadge(
                        title: String(localized: "contacts.unverified", defaultValue: "Unverified"),
                        color: .orange
                    )
                }
                if !contact.canEncryptTo {
                    CypherStatusBadge(
                        title: String(localized: "contacts.noPreferredKey", defaultValue: "Needs Key"),
                        color: .red
                    )
                }
            }
            if let email = contact.primaryEmail {
                Text(email)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            HStack(spacing: 6) {
                Text(contact.keyCountDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack(spacing: 4) {
                    ForEach(contact.tags.prefix(3)) { tag in
                        CypherStatusBadge(title: tag.displayName, color: .blue)
                    }
                    if contact.tags.count > 3 {
                        CypherStatusBadge(
                            title: String.localizedStringWithFormat(
                                String(localized: "contacts.moreTags", defaultValue: "+%d"),
                                contact.tags.count - 3
                            ),
                            color: .secondary
                        )
                    }
                }
            }
        }
        .accessibilityIdentifier("contacts.row")
    }
}

private struct TagFilterChipButton: View {
    let tag: ContactTagSummary
    let isSelected: Bool
    let toggle: () -> Void

    var body: some View {
        if isSelected {
            Button(action: toggle) {
                Label(tag.displayName, systemImage: "checkmark.circle.fill")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .accessibilityLabel(tag.displayName)
        } else {
            Button(action: toggle) {
                Label(tag.displayName, systemImage: "tag")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .accessibilityLabel(tag.displayName)
        }
    }
}
