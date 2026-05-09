import SwiftUI

struct RecipientListDetailView: View {
    let recipientListId: String

    @Environment(ContactService.self) private var contactService
    @Environment(\.dismiss) private var dismiss
    @State private var nameDraft = ""
    @State private var errorMessage: String?
    @State private var showError = false
    @State private var showDeleteConfirmation = false

    private var recipientList: RecipientListSummary? {
        contactService.recipientListSummaries().first {
            $0.recipientListId == recipientListId
        }
    }

    private var contacts: [ContactIdentitySummary] {
        contactService.availableContactIdentities
    }

    private var memberContactIds: Set<String> {
        Set(recipientList?.memberContactIds ?? [])
    }

    private var allowsEditing: Bool {
        contactService.contactsAvailability == .availableProtectedDomain
    }

    var body: some View {
        Group {
            if !contactService.contactsAvailability.isAvailable {
                contactsUnavailableContent(contactService.contactsAvailability)
            } else if let recipientList {
                List {
                    Section {
                        TextField(
                            String(localized: "recipientLists.name", defaultValue: "List Name"),
                            text: $nameDraft
                        )
                        Button {
                            renameRecipientList()
                        } label: {
                            Label(
                                String(localized: "recipientLists.rename", defaultValue: "Rename"),
                                systemImage: "square.and.pencil"
                            )
                        }
                        .disabled(
                            !allowsEditing ||
                                ContactTag.displayName(for: nameDraft).isEmpty ||
                                ContactTag.displayName(for: nameDraft) == recipientList.name
                        )
                    } header: {
                        Text(String(localized: "recipientLists.name", defaultValue: "List Name"))
                    }

                    Section {
                        if contacts.isEmpty {
                            Text(String(localized: "recipientLists.noContacts", defaultValue: "Add contacts before editing members."))
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(contacts) { contact in
                                Toggle(isOn: Binding(
                                    get: { memberContactIds.contains(contact.contactId) },
                                    set: { isOn in
                                        setMembership(contact.contactId, isOn: isOn)
                                    }
                                )) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(contact.displayName)
                                        HStack(spacing: 6) {
                                            Text(contact.keyCountDescription)
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                            if !contact.canEncryptTo {
                                                CypherStatusBadge(
                                                    title: String(localized: "contacts.noPreferredKey", defaultValue: "Needs Key"),
                                                    color: .red
                                                )
                                            }
                                        }
                                    }
                                }
                                .disabled(!allowsEditing)
                            }
                        }
                    } header: {
                        Text(String(localized: "recipientLists.members", defaultValue: "Members"))
                    } footer: {
                        if !recipientList.canEncryptToAll {
                            Text(
                                recipientList.memberCount == 0
                                    ? String(localized: "recipientLists.emptyList.footer", defaultValue: "Empty lists are saved for organization but cannot be selected for encryption.")
                                    : String(localized: "recipientLists.cannotEncrypt.footer", defaultValue: "Every member needs a preferred encryptable key before this list can be used in Encrypt.")
                            )
                        }
                    }

                    Section {
                        Button(role: .destructive) {
                            showDeleteConfirmation = true
                        } label: {
                            Label(
                                String(localized: "recipientLists.delete", defaultValue: "Delete Recipient List"),
                                systemImage: "trash"
                            )
                        }
                        .disabled(!allowsEditing)
                    }
                }
                .onAppear {
                    if nameDraft.isEmpty {
                        nameDraft = recipientList.name
                    }
                }
            } else {
                ContentUnavailableView(
                    String(localized: "recipientLists.notFound", defaultValue: "Recipient List Not Found"),
                    systemImage: "person.3"
                )
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
        .navigationTitle(recipientList?.name ?? String(localized: "contacts.manageRecipientLists", defaultValue: "Recipient Lists"))
        .confirmationDialog(
            String(localized: "recipientLists.delete", defaultValue: "Delete Recipient List"),
            isPresented: $showDeleteConfirmation,
            titleVisibility: .visible
        ) {
            Button(String(localized: "recipientLists.delete.confirm", defaultValue: "Delete"), role: .destructive) {
                deleteRecipientList()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: {
            Text(String(localized: "recipientLists.delete.message", defaultValue: "This list will be removed. Contacts and keys will stay on this device."))
        }
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

    private func renameRecipientList() {
        do {
            let updated = try contactService.renameRecipientList(recipientListId, to: nameDraft)
            nameDraft = updated.name
        } catch {
            presentError(error)
        }
    }

    private func setMembership(_ contactId: String, isOn: Bool) {
        do {
            if isOn {
                try contactService.addContact(contactId, toRecipientList: recipientListId)
            } else {
                try contactService.removeContact(contactId, fromRecipientList: recipientListId)
            }
        } catch {
            presentError(error)
        }
    }

    private func deleteRecipientList() {
        do {
            try contactService.deleteRecipientList(recipientListId)
            dismiss()
        } catch {
            presentError(error)
        }
    }

    private func presentError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
