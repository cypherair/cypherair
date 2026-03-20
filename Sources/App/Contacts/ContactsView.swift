import SwiftUI

/// Lists imported contacts (public keys).
struct ContactsView: View {
    @Environment(ContactService.self) private var contactService

    @State private var deleteError: String?
    @State private var showDeleteError = false
    #if os(macOS)
    @State private var showAddContact = false
    #endif

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
                    #if os(macOS)
                    Button(String(localized: "contacts.add", defaultValue: "Add Contact")) {
                        showAddContact = true
                    }
                    .buttonStyle(.borderedProminent)
                    #else
                    NavigationLink(value: AppRoute.addContact) {
                        Text(String(localized: "contacts.add", defaultValue: "Add Contact"))
                    }
                    .buttonStyle(.borderedProminent)
                    #endif
                }
            }
        }
        .navigationTitle(String(localized: "contacts.title", defaultValue: "Contacts"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                #if os(macOS)
                Button {
                    showAddContact = true
                } label: {
                    Image(systemName: "plus")
                }
                #else
                NavigationLink(value: AppRoute.addContact) {
                    Image(systemName: "plus")
                }
                #endif
            }
        }
        .navigationDestination(for: AppRoute.self) { route in
            switch route {
            case .contactDetail(let fp):
                ContactDetailView(fingerprint: fp)
            case .addContact:
                AddContactView()
            default:
                Text(String(localized: "common.comingSoon", defaultValue: "Coming soon"))
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
        #if os(macOS)
        .sheet(isPresented: $showAddContact) {
            NavigationStack {
                AddContactView()
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                                showAddContact = false
                            }
                        }
                    }
            }
            .frame(minWidth: 450, minHeight: 400)
        }
        #endif
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
