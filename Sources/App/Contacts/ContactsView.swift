import SwiftUI

/// Lists imported contacts (public keys).
struct ContactsView: View {
    @Environment(ContactService.self) private var contactService

    var body: some View {
        List {
            if contactService.contacts.isEmpty {
                ContentUnavailableView {
                    Label(
                        String(localized: "contacts.empty.title", defaultValue: "No Contacts"),
                        systemImage: "person.slash"
                    )
                } description: {
                    Text(String(localized: "contacts.empty.description", defaultValue: "Add a friend's public key to start encrypting messages to them."))
                } actions: {
                    NavigationLink(value: AppRoute.addContact) {
                        Text(String(localized: "contacts.add", defaultValue: "Add Contact"))
                    }
                    .buttonStyle(.borderedProminent)
                }
            } else {
                ForEach(contactService.contacts) { contact in
                    NavigationLink(value: AppRoute.contactDetail(fingerprint: contact.fingerprint)) {
                        ContactRowView(contact: contact)
                    }
                }
                .onDelete { indexSet in
                    for index in indexSet {
                        let contact = contactService.contacts[index]
                        try? contactService.removeContact(fingerprint: contact.fingerprint)
                    }
                }
            }
        }
        .navigationTitle(String(localized: "contacts.title", defaultValue: "Contacts"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                NavigationLink(value: AppRoute.addContact) {
                    Image(systemName: "plus")
                }
            }
        }
        .navigationDestination(for: AppRoute.self) { route in
            switch route {
            case .contactDetail(let fp):
                ContactDetailView(fingerprint: fp)
            case .addContact:
                AddContactView()
            default:
                Text("Coming soon")
            }
        }
        .task {
            try? contactService.loadContacts()
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
