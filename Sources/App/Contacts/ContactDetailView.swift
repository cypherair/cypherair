import SwiftUI

/// Shows details for one contact identity and its associated public keys.
struct ContactDetailView: View {
    struct Configuration {
        var showsCertificateSignatureEntry = true
        var allowsCertificateSignatureLaunch = true
        var certificateSignatureRestrictionMessage: String?

        static let `default` = Configuration()
    }

    let contactId: String
    let configuration: Configuration

    @Environment(ContactService.self) private var contactService
    @Environment(\.dismiss) private var dismiss

    init(
        contactId: String,
        configuration: Configuration = .default
    ) {
        self.contactId = contactId
        self.configuration = configuration
    }

    @State private var showDeleteConfirmation = false
    @State private var showMergeDialog = false
    @State private var detailError: String?
    @State private var showDetailError = false

    private var contact: ContactIdentitySummary? {
        contactService.availableContactIdentity(forContactID: contactId)
    }

    private var mergeCandidates: [ContactIdentitySummary] {
        contactService.availableContactIdentities.filter { $0.contactId != contactId }
    }

    private var allowsProtectedIdentityActions: Bool {
        contactService.contactsAvailability == .availableProtectedDomain
    }

    var body: some View {
        Group {
            if !contactService.contactsAvailability.isAvailable {
                contactsUnavailableContent(contactService.contactsAvailability)
            } else if let contact {
                List {
                    identitySection(contact)
                    certificationSummarySection(contact)

                    if let preferredKey = contact.preferredKey {
                        keySection(
                            String(localized: "contactdetail.preferredKey", defaultValue: "Preferred Key"),
                            keys: [preferredKey]
                        )
                    } else {
                        Section {
                            Label(
                                String(
                                    localized: "contactdetail.noPreferredKey",
                                    defaultValue: "Choose one active encryption key before encrypting to this contact."
                                ),
                                systemImage: "exclamationmark.triangle.fill"
                            )
                            .foregroundStyle(.orange)
                        }
                    }

                    keySection(
                        String(localized: "contactdetail.additionalKeys", defaultValue: "Additional Active Keys"),
                        keys: contact.additionalActiveKeys
                    )
                    keySection(
                        String(localized: "contactdetail.historicalKeys", defaultValue: "Historical Keys"),
                        keys: contact.historicalKeys
                    )

                    actionsSection

                    Section {
                        Button(role: .destructive) {
                            showDeleteConfirmation = true
                        } label: {
                            Label(
                                String(localized: "contactdetail.delete", defaultValue: "Remove Contact"),
                                systemImage: "trash"
                            )
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    String(localized: "contactdetail.notFound", defaultValue: "Contact Not Found"),
                    systemImage: "person.slash"
                )
            }
        }
        #if os(macOS)
        .listStyle(.inset)
        #endif
        .cypherMacReadableContent()
        .accessibilityIdentifier("contactdetail.root")
        .screenReady("contactdetail.ready")
        .navigationTitle(String(localized: "contactdetail.title", defaultValue: "Contact"))
        .confirmationDialog(
            String(localized: "contactdetail.delete.title", defaultValue: "Remove Contact"),
            isPresented: $showDeleteConfirmation,
            titleVisibility: .visible
        ) {
            Button(String(localized: "contactdetail.delete.confirm", defaultValue: "Remove"), role: .destructive) {
                removeContactIdentity()
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: {
            Text(String(localized: "contactdetail.delete.message", defaultValue: "This will remove this contact and all of their public keys from your device."))
        }
        .confirmationDialog(
            String(localized: "contactdetail.merge.title", defaultValue: "Merge Contact"),
            isPresented: $showMergeDialog,
            titleVisibility: .visible
        ) {
            ForEach(mergeCandidates) { candidate in
                Button(candidate.displayName) {
                    mergeContact(sourceContactId: candidate.contactId)
                }
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {}
        } message: {
            Text(String(localized: "contactdetail.merge.message", defaultValue: "Choose another contact to merge into this contact. Their keys and memberships will move here."))
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showDetailError
        ) {
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: {
            if let detailError {
                Text(detailError)
            }
        }
    }

    private func identitySection(_ contact: ContactIdentitySummary) -> some View {
        Section {
            LabeledContent(
                String(localized: "contactdetail.name", defaultValue: "Name"),
                value: contact.displayName
            )
            if let email = contact.primaryEmail {
                LabeledContent(
                    String(localized: "contactdetail.email", defaultValue: "Email"),
                    value: email
                )
            }
            LabeledContent(
                String(localized: "contactdetail.keyCountLabel", defaultValue: "Keys"),
                value: contact.keyCountDescription
            )
            HStack {
                Text(String(localized: "contactdetail.canEncrypt", defaultValue: "Can Encrypt To"))
                Spacer()
                Image(systemName: contact.canEncryptTo ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundStyle(contact.canEncryptTo ? .green : .red)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                contact.canEncryptTo
                    ? String(localized: "contactdetail.canEncrypt.yes", defaultValue: "Can encrypt to this contact: Yes")
                    : String(localized: "contactdetail.canEncrypt.no", defaultValue: "Can encrypt to this contact: No")
            )
        }
    }

    private func certificationSummarySection(_ contact: ContactIdentitySummary) -> some View {
        Section {
            HStack {
                Text(
                    String(
                        localized: "contactdetail.manualVerification",
                        defaultValue: "Manual Fingerprint Verification"
                    )
                )
                Spacer()
                CypherStatusBadge(
                    title: contact.hasUnverifiedKeys
                        ? String(localized: "contactdetail.manualVerification.needsReview", defaultValue: "Needs Review")
                        : String(localized: "contactdetail.manualVerification.verified", defaultValue: "Verified"),
                    color: contact.hasUnverifiedKeys ? .orange : .green
                )
            }

            HStack {
                Text(
                    String(
                        localized: "contactdetail.openpgpCertification",
                        defaultValue: "OpenPGP Certification"
                    )
                )
                Spacer()
                CypherStatusBadge(
                    title: certificationSummaryTitle(for: contact),
                    color: certificationSummaryColor(for: contact)
                )
            }

            if configuration.showsCertificateSignatureEntry {
                NavigationLink(
                    value: AppRoute.contactCertification(
                        contactId: contact.contactId,
                        keyId: contact.preferredKey?.keyId,
                        intent: .certify
                    )
                ) {
                    Label(
                        String(
                            localized: "contactdetail.certifyContact",
                            defaultValue: "Certify This Contact"
                        ),
                        systemImage: "checkmark.seal"
                    )
                }
                .disabled(
                    !configuration.allowsCertificateSignatureLaunch ||
                        !contactService.contactsAvailability.allowsProtectedCertificationPersistence
                )
                .accessibilityIdentifier("contactdetail.certifyContact")
            }

            if let restrictionMessage = configuration.certificateSignatureRestrictionMessage {
                Text(restrictionMessage)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text(String(localized: "contactdetail.trust", defaultValue: "Trust"))
        } footer: {
            Text(
                String(
                    localized: "contactdetail.trust.footer",
                    defaultValue: "Manual fingerprint verification and OpenPGP certification are tracked separately."
                )
            )
        }
    }

    private func keySection(
        _ title: String,
        keys: [ContactKeySummary]
    ) -> some View {
        Section {
            if keys.isEmpty {
                Text(String(localized: "contactdetail.noKeysInSection", defaultValue: "None"))
                    .foregroundStyle(.secondary)
            } else {
                ForEach(keys) { key in
                    ContactKeySummaryView(
                        key: key,
                        configuration: configuration,
                        allowsUsageActions: allowsProtectedIdentityActions,
                        markVerified: { markVerified(fingerprint: $0) },
                        setPreferred: { setPreferredKey(fingerprint: $0) },
                        markHistorical: { setKeyUsage(.historical, fingerprint: $0) },
                        markAdditionalActive: { setKeyUsage(.additionalActive, fingerprint: $0) }
                    )
                }
            }
        } header: {
            Text(title)
        }
    }

    private var actionsSection: some View {
        Section {
            if allowsProtectedIdentityActions {
                Button {
                    showMergeDialog = true
                } label: {
                    Label(
                        String(localized: "contactdetail.merge", defaultValue: "Merge Another Contact Into This Contact"),
                        systemImage: "person.2.fill"
                    )
                }
                .disabled(mergeCandidates.isEmpty)
                .accessibilityIdentifier("contactdetail.merge")
            }
        } header: {
            Text(String(localized: "contactdetail.actions", defaultValue: "Actions"))
        } footer: {
            if allowsProtectedIdentityActions && mergeCandidates.isEmpty {
                Text(String(localized: "contactdetail.merge.none", defaultValue: "There are no other contacts to merge."))
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

    private func removeContactIdentity() {
        do {
            try contactService.removeContactIdentity(contactId: contactId)
            dismiss()
        } catch {
            presentError(error)
        }
    }

    private func mergeContact(sourceContactId: String) {
        do {
            _ = try contactService.mergeContact(sourceContactId: sourceContactId, into: contactId)
        } catch {
            presentError(error)
        }
    }

    private func markVerified(fingerprint: String) {
        do {
            try contactService.setVerificationState(.verified, for: fingerprint)
        } catch {
            presentError(error)
        }
    }

    private func setPreferredKey(fingerprint: String) {
        do {
            try contactService.setPreferredKey(fingerprint: fingerprint, for: contactId)
        } catch {
            presentError(error)
        }
    }

    private func setKeyUsage(_ usageState: ContactKeyUsageState, fingerprint: String) {
        do {
            try contactService.setKeyUsageState(usageState, fingerprint: fingerprint)
        } catch {
            presentError(error)
        }
    }

    private func presentError(_ error: Error) {
        detailError = error.localizedDescription
        showDetailError = true
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
            "person"
        }
    }

    private func certificationSummaryTitle(for contact: ContactIdentitySummary) -> String {
        let statuses = contact.keys.map(\.certificationProjection.status)
        if statuses.contains(.certified) {
            return String(localized: "contactdetail.openpgpCertification.certified", defaultValue: "Certified")
        }
        if statuses.contains(.invalidOrStale) {
            return String(localized: "contactdetail.openpgpCertification.invalid", defaultValue: "Invalid or Stale")
        }
        if statuses.contains(.revalidationNeeded) {
            return String(localized: "contactdetail.openpgpCertification.revalidation", defaultValue: "Revalidation Needed")
        }
        return String(localized: "contactdetail.openpgpCertification.none", defaultValue: "Not Certified")
    }

    private func certificationSummaryColor(for contact: ContactIdentitySummary) -> Color {
        let statuses = contact.keys.map(\.certificationProjection.status)
        if statuses.contains(.certified) {
            return .green
        }
        if statuses.contains(.invalidOrStale) {
            return .red
        }
        if statuses.contains(.revalidationNeeded) {
            return .orange
        }
        return .secondary
    }
}
