import SwiftUI

struct RecipientListsView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(\.appRouteNavigator) private var routeNavigator
    @State private var newListName = ""
    @State private var errorMessage: String?
    @State private var showError = false

    private var recipientLists: [RecipientListSummary] {
        contactService.recipientListSummaries()
    }

    private var allowsEditing: Bool {
        contactService.contactsAvailability == .availableProtectedDomain
    }

    var body: some View {
        Group {
            if contactService.contactsAvailability.isAvailable {
                List {
                    Section {
                        HStack {
                            TextField(
                                String(localized: "recipientLists.name", defaultValue: "List Name"),
                                text: $newListName
                            )
                            Button {
                                createRecipientList()
                            } label: {
                                Label(
                                    String(localized: "recipientLists.create", defaultValue: "Create"),
                                    systemImage: "plus"
                                )
                            }
                            .disabled(!allowsEditing || ContactTag.displayName(for: newListName).isEmpty)
                        }
                    } header: {
                        Text(String(localized: "recipientLists.create.header", defaultValue: "New List"))
                    } footer: {
                        if !allowsEditing {
                            Text(String(localized: "recipientLists.protectedOnly", defaultValue: "Recipient lists can be edited after Contacts are opened from protected app data."))
                        }
                    }

                    Section {
                        if recipientLists.isEmpty {
                            Label(
                                String(localized: "recipientLists.empty.title", defaultValue: "No Recipient Lists"),
                                systemImage: "person.3"
                            )
                            Text(String(localized: "recipientLists.empty.description", defaultValue: "Create lists to encrypt to saved groups without reselecting each contact."))
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(recipientLists) { list in
                                NavigationLink(value: AppRoute.recipientListDetail(recipientListId: list.recipientListId)) {
                                    RecipientListRowView(list: list)
                                }
                            }
                            .onDelete(perform: deleteRecipientLists)
                        }
                    } header: {
                        Text(String(localized: "contacts.manageRecipientLists", defaultValue: "Recipient Lists"))
                    }
                }
            } else {
                contactsUnavailableContent(contactService.contactsAvailability)
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
        .navigationTitle(String(localized: "contacts.manageRecipientLists", defaultValue: "Recipient Lists"))
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
    }

    private func contactsUnavailableContent(_ availability: ContactsAvailability) -> some View {
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

    private func systemImage(for availability: ContactsAvailability) -> String {
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

    private func createRecipientList() {
        do {
            let list = try contactService.createRecipientList(named: newListName)
            newListName = ""
            routeNavigator.open(.recipientListDetail(recipientListId: list.recipientListId))
        } catch {
            presentError(error)
        }
    }

    private func deleteRecipientLists(at indexSet: IndexSet) {
        let lists = recipientLists
        let idsToDelete = RecipientListDeletionResolver.recipientListIdsToDelete(
            at: indexSet,
            from: lists
        )

        for recipientListId in idsToDelete {
            do {
                try contactService.deleteRecipientList(recipientListId)
            } catch {
                presentError(error)
            }
        }
    }

    private func presentError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}

enum RecipientListDeletionResolver {
    static func recipientListIdsToDelete(
        at indexSet: IndexSet,
        from recipientLists: [RecipientListSummary]
    ) -> [String] {
        indexSet.sorted().compactMap { index in
            guard recipientLists.indices.contains(index) else {
                return nil
            }
            return recipientLists[index].recipientListId
        }
    }
}

private struct RecipientListRowView: View {
    let list: RecipientListSummary

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(list.name)
                    .font(.body.weight(.medium))
                Text(
                    String.localizedStringWithFormat(
                        String(localized: "recipientLists.memberCount", defaultValue: "%d members"),
                        list.memberCount
                    )
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            if !list.canEncryptToAll {
                CypherStatusBadge(
                    title: list.memberCount == 0
                        ? String(localized: "recipientLists.emptyList", defaultValue: "Empty")
                        : String(localized: "recipientLists.cannotEncrypt", defaultValue: "Needs Keys"),
                    color: .orange
                )
            }
        }
    }
}
