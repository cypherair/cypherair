import SwiftUI

/// Lists imported contacts (public keys).
struct ContactsView: View {
    @Environment(ContactService.self) private var contactService

    var body: some View {
        ContactsScreenHostView(contactService: contactService)
    }
}

private struct ContactsScreenHostView: View {
    @Environment(\.appRouteNavigator) private var routeNavigator
    @State private var model: ContactsScreenModel

    init(contactService: ContactService) {
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
        .searchable(
            text: $model.searchText,
            placement: .automatic,
            prompt: String(
                localized: "contacts.search.prompt",
                defaultValue: "Names, email, tags, fingerprints"
            )
        )
        .searchSuggestions {
            ForEach(model.tagSuggestions.prefix(6)) { tag in
                Label(tag.displayName, systemImage: "tag")
                    .searchCompletion(tag.displayName)
            }
        }
        .toolbar {
            if model.contactsAvailability.isAvailable {
                ToolbarItemGroup(placement: .primaryAction) {
                    if !model.tagFilters.isEmpty {
                        Menu {
                            ForEach(model.tagFilters) { tag in
                                Button {
                                    model.toggleTagFilter(tag.tagId)
                                } label: {
                                    if model.selectedTagFilterIds.contains(tag.tagId) {
                                        Label(tag.displayName, systemImage: "checkmark")
                                    } else {
                                        Text(tag.displayName)
                                    }
                                }
                            }
                            if !model.selectedTagFilterIds.isEmpty {
                                Divider()
                                Button {
                                    model.clearTagFilters()
                                } label: {
                                    Label(
                                        String(localized: "contacts.clearTagFilters", defaultValue: "Clear Tag Filters"),
                                        systemImage: "xmark.circle"
                                    )
                                }
                            }
                        } label: {
                            Image(systemName: "tag")
                        }
                        .accessibilityLabel(String(localized: "contacts.filterTags", defaultValue: "Filter Tags"))
                    }

                    Button {
                        routeNavigator.open(.recipientLists)
                    } label: {
                        Image(systemName: "person.3")
                    }
                    .accessibilityLabel(
                        String(localized: "contacts.manageRecipientLists", defaultValue: "Recipient Lists")
                    )

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
    }
}

private extension ContactsScreenHostView {
    var contactsList: some View {
        let contacts = model.visibleContacts

        return List {
            if !model.selectedTagFilters.isEmpty {
                Section {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(model.selectedTagFilters) { tag in
                                Button {
                                    model.toggleTagFilter(tag.tagId)
                                } label: {
                                    Label(tag.displayName, systemImage: "xmark.circle")
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                    }
                } header: {
                    Text(String(localized: "contacts.selectedTags", defaultValue: "Selected Tags"))
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
        .overlay {
            if contacts.isEmpty {
                if model.hasActiveSearchOrFilters {
                    noResultsContent
                } else {
                    emptyStateContent
                }
            }
        }
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
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(contact.displayName)
                    .font(.body.weight(.medium))
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
            HStack(spacing: 8) {
                Text(contact.keyCountDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let preferredKey = contact.preferredKey {
                    Text(preferredKey.profile.displayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let email = contact.primaryEmail {
                    Text(email)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if !contact.tags.isEmpty {
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
