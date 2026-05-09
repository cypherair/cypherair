import SwiftUI
import UniformTypeIdentifiers

struct ContactCertificationDetailsView: View {
    let contactId: String
    let keyId: String?
    let intent: ContactCertificationRouteIntent
    let configuration: ContactCertificationDetailsConfiguration

    @Environment(ContactService.self) private var contactService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(CertificateSignatureService.self) private var certificateSignatureService

    init(
        contactId: String,
        keyId: String?,
        intent: ContactCertificationRouteIntent,
        configuration: ContactCertificationDetailsConfiguration = .default
    ) {
        self.contactId = contactId
        self.keyId = keyId
        self.intent = intent
        self.configuration = configuration
    }

    var body: some View {
        ContactCertificationDetailsHostView(
            contactId: contactId,
            keyId: keyId,
            intent: intent,
            contactService: contactService,
            keyManagement: keyManagement,
            certificateSignatureService: certificateSignatureService,
            configuration: configuration
        )
    }
}

private struct ContactCertificationDetailsHostView: View {
    @State private var model: ContactCertificationDetailsScreenModel

    init(
        contactId: String,
        keyId: String?,
        intent: ContactCertificationRouteIntent,
        contactService: ContactService,
        keyManagement: KeyManagementService,
        certificateSignatureService: CertificateSignatureService,
        configuration: ContactCertificationDetailsConfiguration
    ) {
        _model = State(
            initialValue: ContactCertificationDetailsScreenModel(
                contactId: contactId,
                initialKeyId: keyId,
                intent: intent,
                contactService: contactService,
                keyManagement: keyManagement,
                certificateSignatureService: certificateSignatureService,
                configuration: configuration
            )
        )
    }

    var body: some View {
        @Bindable var model = model
        let exportController = model.exportController

        Group {
            if !model.contactsAvailability.isAvailable {
                ContentUnavailableView {
                    Label(model.contactsAvailability.unavailableTitle, systemImage: "lock")
                } description: {
                    Text(model.contactsAvailability.unavailableDescription)
                }
            } else if model.contact == nil {
                ContentUnavailableView(
                    String(localized: "contactcertification.notFound.title", defaultValue: "Contact Not Found"),
                    systemImage: "person.slash"
                )
            } else {
                Form {
                    content
                }
                #if os(macOS)
                .formStyle(.grouped)
                #endif
                .cypherMacReadableContent(maxWidth: MacPresentationWidth.textHeavy)
                .scrollDismissesKeyboardInteractivelyIfAvailable()
            }
        }
        .accessibilityIdentifier("contactcertification.root")
        .screenReady("contactcertification.ready")
        .navigationTitle(
            String(localized: "contactcertification.title", defaultValue: "Certification Details")
        )
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { model.showError },
                set: { if !$0 { model.dismissError() } }
            ),
            presenting: model.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                model.dismissError()
            }
        } message: { err in
            Text(err.localizedDescription)
        }
        .fileImporter(
            isPresented: $model.showFileImporter,
            allowedContentTypes: model.allowedImportContentTypes,
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                model.handleImportedFile(url)
            }
        }
        .fileExporter(
            isPresented: Binding(
                get: { exportController.isPresented },
                set: { if !$0 { model.finishExport() } }
            ),
            item: exportController.payload,
            contentTypes: [.data],
            defaultFilename: exportController.defaultFilename
        ) { result in
            model.finishExport()
            if case .failure(let exportError) = result {
                model.handleExportError(exportError)
            }
        }
        .onAppear {
            model.loadIfNeeded()
        }
        .onDisappear {
            model.handleDisappear()
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.loadState {
        case .idle, .loading:
            loadingSection
        case .failed:
            failedSection
        case .loaded:
            overviewSection
            keySelectionSection
            savedHistorySection
            certifySection
            importSection
            if let verification = model.verification {
                resultSection(verification)
            }
        }
    }

    private var loadingSection: some View {
        Section {
            HStack(spacing: 12) {
                ProgressView()
                Text(
                    String(
                        localized: "contactcertification.loading",
                        defaultValue: "Loading certification context..."
                    )
                )
            }
        }
    }

    private var failedSection: some View {
        Section {
            ContentUnavailableView {
                Label(
                    String(
                        localized: "contactcertification.loadFailed.title",
                        defaultValue: "Could Not Load Certification Details"
                    ),
                    systemImage: "exclamationmark.triangle"
                )
            } description: {
                Text(
                    model.loadError?.localizedDescription
                        ?? String(localized: "error.generic", defaultValue: "An error occurred.")
                )
            } actions: {
                Button(String(localized: "common.retry", defaultValue: "Retry")) {
                    model.retry()
                }
            }
        }
    }

    private var overviewSection: some View {
        Section {
            if let contact = model.contact {
                LabeledContent(
                    String(localized: "contactcertsig.contact", defaultValue: "Contact"),
                    value: contact.displayName
                )
                if let email = contact.primaryEmail {
                    LabeledContent(
                        String(localized: "contactdetail.email", defaultValue: "Email"),
                        value: email
                    )
                }
            }
            if let selectedKey = model.selectedKey {
                LabeledContent(
                    String(localized: "contactdetail.shortKeyId", defaultValue: "Short Key ID"),
                    value: selectedKey.shortKeyId
                )
                HStack {
                    Text(String(localized: "contactcertification.summary.openpgp", defaultValue: "OpenPGP Certification"))
                    Spacer()
                    ContactCertificationStatusPill(
                        title: projectionTitle(selectedKey.certificationProjection.status),
                        color: projectionColor(selectedKey.certificationProjection.status)
                    )
                }
            }
        } header: {
            Text(String(localized: "contactcertification.overview", defaultValue: "Overview"))
        }
    }

    private var keySelectionSection: some View {
        Section {
            if model.keys.count <= 1 {
                if let key = model.selectedKey {
                    LabeledContent(
                        String(localized: "contactcertification.key", defaultValue: "Key"),
                        value: key.displayName
                    )
                }
            } else {
                Picker(
                    String(localized: "contactcertification.key", defaultValue: "Key"),
                    selection: Binding(
                        get: { model.selectedKeyId },
                        set: { model.selectKey($0) }
                    )
                ) {
                    ForEach(model.keys) { key in
                        Text(key.displayName)
                            .tag(Optional(key.keyId))
                    }
                }
                .disabled(model.isOperationLocked)
            }
        } header: {
            Text(String(localized: "contactcertification.key.header", defaultValue: "Target Key"))
        }
    }

    private var savedHistorySection: some View {
        Section {
            if model.savedArtifacts.isEmpty {
                Label(
                    String(
                        localized: "contactcertification.history.empty",
                        defaultValue: "No saved certification signatures for this key."
                    ),
                    systemImage: "checkmark.seal"
                )
                .foregroundStyle(.secondary)
            } else {
                ForEach(model.savedArtifacts) { artifact in
                    ContactCertificationArtifactRow(
                        artifact: artifact,
                        statusTitle: model.title(for: artifact.validationStatus),
                        statusColor: statusColor(artifact.validationStatus),
                        isExporting: model.activeOperation == .exportArtifact(artifact.artifactId),
                        export: {
                            model.exportArtifact(artifact)
                        }
                    )
                    .disabled(model.isOperationLocked)
                }
            }
        } header: {
            Text(String(localized: "contactcertification.history", defaultValue: "Saved History"))
        }
    }

    private var certifySection: some View {
        Section {
            if model.userIds.isEmpty {
                Label(
                    String(
                        localized: "contactcertsig.userIds.empty",
                        defaultValue: "No selectable User IDs were found."
                    ),
                    systemImage: "person.slash"
                )
                .foregroundStyle(.secondary)
            } else {
                Picker(
                    String(localized: "contactcertsig.userIds", defaultValue: "User ID"),
                    selection: Binding(
                        get: { model.selectedUserId },
                        set: { model.selectUserId($0) }
                    )
                ) {
                    ForEach(model.userIds, id: \.self) { userId in
                        Text(userId.displayText)
                            .tag(Optional(userId))
                    }
                }
                .disabled(model.isOperationLocked)
            }

            if model.signers.isEmpty {
                Label(
                    String(
                        localized: "contactcertsig.signer.empty",
                        defaultValue: "No local keys are available to certify this contact."
                    ),
                    systemImage: "key.slash"
                )
                .foregroundStyle(.secondary)
            } else {
                Picker(
                    String(localized: "contactcertsig.signer", defaultValue: "Signer"),
                    selection: Binding(
                        get: { model.selectedSignerFingerprint },
                        set: { model.selectSigner($0) }
                    )
                ) {
                    ForEach(model.signers, id: \.fingerprint) { signer in
                        Text(signer.userId ?? signer.shortKeyId)
                            .tag(Optional(signer.fingerprint))
                    }
                }
                .disabled(model.isOperationLocked)
            }

            Picker(
                String(localized: "contactcertsig.certificationKind", defaultValue: "Certification Kind"),
                selection: Binding(
                    get: { model.selectedCertificationKind },
                    set: { model.selectCertificationKind($0) }
                )
            ) {
                ForEach(model.certificationKinds, id: \.self) { kind in
                    Text(model.title(for: kind)).tag(kind)
                }
            }
            .disabled(model.isOperationLocked)

            Button {
                model.generateAndSaveCertification()
            } label: {
                ContactCertificationActionLabel(
                    title: String(
                        localized: "contactcertification.certify.action",
                        defaultValue: "Certify This Contact"
                    ),
                    isRunning: model.activeOperation == .generateAndSave
                )
            }
            .buttonStyle(.borderedProminent)
            .disabled(!model.canGenerateAndSave)

            if let saved = model.lastSavedArtifact {
                Button {
                    model.exportArtifact(saved)
                } label: {
                    Label(
                        String(
                            localized: "contactcertification.export.latest",
                            defaultValue: "Export Saved Signature"
                        ),
                        systemImage: "square.and.arrow.up"
                    )
                }
                .disabled(model.isOperationLocked)
            }
        } header: {
            Text(String(localized: "contactcertification.certify.header", defaultValue: "Certify This Contact"))
        }
    }

    private var importSection: some View {
        Section {
            Picker(
                String(localized: "contactcertification.import.mode", defaultValue: "Signature Type"),
                selection: Binding(
                    get: { model.importMode },
                    set: { model.selectImportMode($0) }
                )
            ) {
                ForEach(ContactCertificationDetailsScreenModel.ImportMode.allCases) { mode in
                    Text(model.title(for: mode)).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .disabled(model.isOperationLocked)

            CypherMultilineTextInput(
                text: Binding(
                    get: { model.signatureInput },
                    set: { model.setSignatureInput($0) }
                ),
                mode: .machineText
            )
            .frame(minHeight: 100, idealHeight: 140, maxHeight: 220)
            .disabled(model.isOperationLocked)

            Button {
                model.requestSignatureFileImport()
            } label: {
                Label(
                    String(localized: "contactcertsig.importSignature", defaultValue: "Import Signature File"),
                    systemImage: "doc.badge.plus"
                )
            }
            .disabled(model.isOperationLocked)

            if let fileName = model.signatureFileName,
               model.importedSignature.hasImportedFile {
                CypherImportedFileRow(
                    fileName: fileName,
                    clearAccessibilityLabel: String(
                        localized: "contactcertsig.clearImportedFile",
                        defaultValue: "Clear imported signature file"
                    )
                ) {
                    model.clearImportedSignature()
                }
            }

            Button {
                model.verifyImportedSignature()
            } label: {
                ContactCertificationActionLabel(
                    title: String(
                        localized: "contactcertification.import.verify",
                        defaultValue: "Verify Signature"
                    ),
                    isRunning: model.activeOperation == .verifyImport
                )
            }
            .disabled(!model.canVerifyImport)

            if model.canSavePendingArtifact {
                Button {
                    model.savePendingSignature()
                } label: {
                    ContactCertificationActionLabel(
                        title: String(
                            localized: "contactcertification.import.save",
                            defaultValue: "Save Signature"
                        ),
                        isRunning: model.activeOperation == .savePending
                    )
                }
                .buttonStyle(.borderedProminent)
            }
        } header: {
            Text(String(localized: "contactcertification.import.header", defaultValue: "Import or Verify"))
        } footer: {
            Text(
                String(
                    localized: "contactcertification.import.footer",
                    defaultValue: "Preview and verification are read-only. Save Signature appears only when the signature is valid for this contact key and selector."
                )
            )
        }
    }

    private func resultSection(
        _ verification: CertificateSignatureVerification
    ) -> some View {
        Section {
            LabeledContent(
                String(localized: "contactcertsig.result.status", defaultValue: "Status"),
                value: model.title(for: verification.status)
            )
            if let certificationKind = verification.certificationKind {
                LabeledContent(
                    String(localized: "contactcertsig.result.kind", defaultValue: "Certification Kind"),
                    value: model.title(for: certificationKind)
                )
            }
            if let signingKeyFingerprint = verification.signingKeyFingerprint {
                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "contactcertsig.result.signingKey", defaultValue: "Signing Key"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    FingerprintView(
                        fingerprint: signingKeyFingerprint,
                        font: .system(.body, design: .monospaced),
                        textSelectionEnabled: true
                    )
                }
            }
            if let signerIdentity = verification.signerIdentity {
                ContactCertificationSignerIdentityView(identity: signerIdentity)
            }
        } header: {
            Text(String(localized: "contactcertsig.result", defaultValue: "Result"))
        }
    }

    private func projectionTitle(_ status: ContactCertificationProjection.Status) -> String {
        switch status {
        case .notCertified:
            String(localized: "contactcertification.projection.none", defaultValue: "Not Certified")
        case .certified:
            String(localized: "contactcertification.projection.certified", defaultValue: "Certified")
        case .invalidOrStale:
            String(localized: "contactcertification.projection.invalid", defaultValue: "Invalid or Stale")
        case .revalidationNeeded:
            String(localized: "contactcertification.projection.revalidation", defaultValue: "Revalidation Needed")
        }
    }

    private func projectionColor(_ status: ContactCertificationProjection.Status) -> Color {
        switch status {
        case .notCertified:
            .secondary
        case .certified:
            .green
        case .invalidOrStale:
            .red
        case .revalidationNeeded:
            .orange
        }
    }

    private func statusColor(_ status: ContactCertificationValidationStatus) -> Color {
        switch status {
        case .valid:
            .green
        case .invalidOrStale:
            .red
        case .revalidationNeeded:
            .orange
        }
    }
}

private struct ContactCertificationArtifactRow: View {
    let artifact: ContactCertificationArtifactReference
    let statusTitle: String
    let statusColor: Color
    let isExporting: Bool
    let export: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(targetTitle)
                    .font(.body.weight(.medium))
                Spacer()
                ContactCertificationStatusPill(title: statusTitle, color: statusColor)
            }

            if let signerPrimaryFingerprint = artifact.signerPrimaryFingerprint {
                Text(
                    String(
                        localized: "contactcertification.history.signer",
                        defaultValue: "Signer \(IdentityPresentation.shortKeyId(from: signerPrimaryFingerprint))"
                    )
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            if let digest = artifact.effectiveSignatureDigest {
                Text(digest)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }

            HStack {
                Text(artifact.createdAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button(action: export) {
                    if isExporting {
                        ProgressView()
                    } else {
                        Label(
                            String(localized: "common.export", defaultValue: "Export"),
                            systemImage: "square.and.arrow.up"
                        )
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var targetTitle: String {
        switch artifact.targetSelector.kind {
        case .directKey:
            String(localized: "contactcertification.history.directKey", defaultValue: "Direct Key Certification")
        case .userId:
            artifact.targetSelector.userIdDisplayText
                ?? String(localized: "contactcertification.history.userId", defaultValue: "User ID Certification")
        }
    }
}

private struct ContactCertificationActionLabel: View {
    let title: String
    let isRunning: Bool

    var body: some View {
        if isRunning {
            HStack {
                ProgressView()
                Text(String(localized: "common.working", defaultValue: "Working..."))
            }
            .cypherPrimaryActionLabelFrame(minWidth: 220)
        } else {
            Text(title)
                .cypherPrimaryActionLabelFrame(minWidth: 220)
        }
    }
}

private struct ContactCertificationSignerIdentityView: View {
    let identity: CertificateSignatureSignerIdentity

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "contactcertsig.result.signer", defaultValue: "Signer"))
                .font(.subheadline.weight(.semibold))
            Text(identity.displayName)
                .font(.headline)
            if let secondaryText = identity.secondaryText {
                Text(secondaryText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            FingerprintView(
                fingerprint: identity.fingerprint,
                font: .system(.caption, design: .monospaced),
                foregroundColor: .secondary,
                textSelectionEnabled: true,
                expandsHorizontally: false
            )
        }
        .padding(.vertical, 4)
    }
}

private struct ContactCertificationStatusPill: View {
    let title: String
    let color: Color

    var body: some View {
        CypherStatusBadge(title: title, color: color)
    }
}
