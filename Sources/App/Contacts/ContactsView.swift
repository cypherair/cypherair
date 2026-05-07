import SwiftUI

/// Lists imported contacts (public keys).
struct ContactsView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(\.appRouteNavigator) private var routeNavigator
    @State private var deleteError: String?
    @State private var showDeleteError = false

    var body: some View {
        Group {
            if contactService.contactsAvailability.isAvailable {
                contactsList
            } else {
                contactsUnavailableContent(contactService.contactsAvailability)
            }
        }
        .navigationTitle(String(localized: "contacts.title", defaultValue: "Contacts"))
        .toolbar {
            if contactService.contactsAvailability.isAvailable {
                ToolbarItem(placement: .primaryAction) {
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
            isPresented: $showDeleteError
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: {
            if let deleteError {
                Text(deleteError)
            }
        }
    }

    private var contactsList: some View {
        let contacts = contactService.availableContacts

        return List {
            ForEach(contacts) { contact in
                NavigationLink(value: AppRoute.contactDetail(fingerprint: contact.fingerprint)) {
                    ContactRowView(contact: contact)
                }
                .accessibilityIdentifier("contacts.row")
            }
            .onDelete { indexSet in
                deleteContacts(at: indexSet, from: contacts)
            }
        }
        .overlay {
            if contacts.isEmpty {
                emptyStateContent
            }
        }
        .cypherMacReadableContent()
    }

    private func deleteContacts(at indexSet: IndexSet, from contacts: [Contact]) {
        for index in indexSet {
            let contact = contacts[index]
            do {
                try contactService.removeContact(fingerprint: contact.fingerprint)
            } catch {
                deleteError = error.localizedDescription
                showDeleteError = true
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

    private var emptyStateContent: some View {
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
}

private struct ContactRowView: View {
    let contact: Contact

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(contact.displayName)
                    .font(.body.weight(.medium))
                if !contact.isVerified {
                    CypherStatusBadge(
                        title: String(localized: "contacts.unverified", defaultValue: "Unverified"),
                        color: .orange
                    )
                }
            }
            HStack(spacing: 8) {
                Text(contact.profile.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let email = contact.email {
                    Text(email)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityIdentifier("contacts.row")
    }
}
