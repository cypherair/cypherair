import SwiftUI

/// Lists imported contacts (public keys).
struct ContactsView: View {
    @Environment(ContactService.self) private var contactService
    @Environment(\.appRouteNavigator) private var routeNavigator

    @State private var deleteError: String?
    @State private var showDeleteError = false

    var body: some View {
        List {
            ForEach(contactService.contacts) { contact in
                NavigationLink(value: AppRoute.contactDetail(fingerprint: contact.fingerprint)) {
                    ContactRowView(contact: contact)
                }
            }
            .onDelete { indexSet in
                for index in indexSet {
                    let contact = contactService.contacts[index]
                    do {
                        try contactService.removeContact(fingerprint: contact.fingerprint)
                    } catch {
                        deleteError = error.localizedDescription
                        showDeleteError = true
                    }
                }
            }
        }
        .overlay {
            if contactService.contacts.isEmpty {
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
                }
            }
        }
        .navigationTitle(String(localized: "contacts.title", defaultValue: "Contacts"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    routeNavigator.open(.addContact)
                } label: {
                    Image(systemName: "plus")
                }
                .tutorialAnchor(.contactsAddButton)
            }
        }
        .task {
            try? contactService.loadContacts()
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
}

private struct ContactRowView: View {
    let contact: Contact

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(contact.displayName)
                    .font(.body.weight(.medium))
                if !contact.isVerified {
                    Text(String(localized: "contacts.unverified", defaultValue: "Unverified"))
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.orange.opacity(0.14), in: Capsule())
                        .foregroundStyle(.orange)
                }
                Spacer()
                Text(contact.profile.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let email = contact.email {
                Text(email)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
