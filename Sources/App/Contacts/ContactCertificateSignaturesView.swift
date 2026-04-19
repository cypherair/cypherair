import SwiftUI
import UniformTypeIdentifiers

struct ContactCertificateSignaturesView: View {
    struct Configuration {
        var outputInterceptionPolicy: OutputInterceptionPolicy = .passthrough

        static let `default` = Configuration()
    }

    let fingerprint: String
    let configuration: Configuration

    @Environment(ContactService.self) private var contactService
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(CertificateSignatureService.self) private var certificateSignatureService

    init(
        fingerprint: String,
        configuration: Configuration = .default
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
    }

    var body: some View {
        ContactCertificateSignaturesHostView(
            fingerprint: fingerprint,
            contactService: contactService,
            keyManagement: keyManagement,
            certificateSignatureService: certificateSignatureService,
            configuration: configuration
        )
    }
}

private struct ContactCertificateSignaturesHostView: View {
    @State private var model: ContactCertificateSignaturesScreenModel

    init(
        fingerprint: String,
        contactService: ContactService,
        keyManagement: KeyManagementService,
        certificateSignatureService: CertificateSignatureService,
        configuration: ContactCertificateSignaturesView.Configuration
    ) {
        _model = State(
            initialValue: ContactCertificateSignaturesScreenModel(
                fingerprint: fingerprint,
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
            if model.contact == nil {
                ContentUnavailableView(
                    String(
                        localized: "contactcertsig.notFound.title",
                        defaultValue: "Contact Not Found"
                    ),
                    systemImage: "person.slash"
                )
            } else {
                Form {
                    content
                }
                #if os(macOS)
                .formStyle(.grouped)
                #endif
                .scrollDismissesKeyboardInteractivelyIfAvailable()
            }
        }
        .accessibilityIdentifier("contactcertsig.root")
        .screenReady("contactcertsig.ready")
        .navigationTitle(
            String(
                localized: "contactcertsig.title",
                defaultValue: "Certificate Signatures"
            )
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
            modeSection

            if model.mode != .certifyUserId {
                signatureInputSection
            }

            if model.mode != .directKeyVerify {
                userIdSection
            }

            if model.mode == .certifyUserId {
                signerSection
                certificationKindSection
            }

            actionSection

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
                        localized: "contactcertsig.loading",
                        defaultValue: "Loading certificate signature context..."
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
                        localized: "contactcertsig.loadFailed.title",
                        defaultValue: "Could Not Load Certificate Details"
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
                if let email = contact.email {
                    LabeledContent(
                        String(localized: "contactdetail.email", defaultValue: "Email"),
                        value: email
                    )
                }
                LabeledContent(
                    String(localized: "contactdetail.profile", defaultValue: "Profile"),
                    value: contact.profile.displayName
                )
                LabeledContent(
                    String(localized: "contactdetail.shortKeyId", defaultValue: "Short Key ID"),
                    value: contact.shortKeyId
                )
            }
        } header: {
            Text(String(localized: "contactcertsig.overview", defaultValue: "Overview"))
        }
    }

    private var modeSection: some View {
        Section {
            Picker(
                String(localized: "contactcertsig.mode", defaultValue: "Mode"),
                selection: Binding(
                    get: { model.mode },
                    set: { model.setMode($0) }
                )
            ) {
                ForEach(ContactCertificateSignaturesScreenModel.Mode.allCases) { mode in
                    Text(model.title(for: mode)).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .disabled(model.isOperationLocked)
        }
    }

    private var signatureInputSection: some View {
        Section {
            CypherMultilineTextInput(
                text: Binding(
                    get: { model.signatureInput },
                    set: { model.setSignatureInput($0) }
                ),
                mode: .machineText
            )
            #if canImport(UIKit)
            .frame(minHeight: 120)
            #else
            .frame(minHeight: 200)
            #endif
            .disabled(model.isOperationLocked)

            Button {
                model.requestSignatureFileImport()
            } label: {
                Label(
                    String(
                        localized: "contactcertsig.importSignature",
                        defaultValue: "Import Signature File"
                    ),
                    systemImage: "doc.badge.plus"
                )
            }
            .disabled(model.isOperationLocked)

            if let importedFileName = model.signatureFileName,
               model.importedSignature.hasImportedFile {
                HStack {
                    Label(importedFileName, systemImage: "doc.fill")
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        model.clearImportedSignature()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .frame(minWidth: 44, minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(
                        String(
                            localized: "contactcertsig.clearImportedFile",
                            defaultValue: "Clear imported signature file"
                        )
                    )
                }
            }
        } header: {
            Text(
                String(
                    localized: "contactcertsig.signature",
                    defaultValue: "Signature"
                )
            )
        } footer: {
            Text(
                String(
                    localized: "contactcertsig.signature.footer",
                    defaultValue: "Supports .asc and .sig signature files. Imported file bytes remain authoritative until the text is edited or cleared."
                )
            )
        }
    }

    private var userIdSection: some View {
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
                ForEach(model.userIds, id: \.self) { userId in
                    Button {
                        model.selectUserId(userId)
                    } label: {
                        ContactCertificateSelectableUserIdRow(
                            userId: userId,
                            isSelected: model.selectedUserId == userId
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(model.isOperationLocked)
                }
            }
        } header: {
            Text(
                String(
                    localized: "contactcertsig.userIds",
                    defaultValue: "User ID"
                )
            )
        } footer: {
            Text(
                String(
                    localized: "contactcertsig.userIds.footer",
                    defaultValue: "Duplicate User IDs remain separate choices. The occurrence number identifies the exact packet."
                )
            )
        }
    }

    private var signerSection: some View {
        Section {
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
        } footer: {
            if model.signers.isEmpty {
                Text(
                    String(
                        localized: "contactcertsig.signer.footer.empty",
                        defaultValue: "Create or import one of your own keys before generating a certification signature."
                    )
                )
            }
        }
    }

    private var certificationKindSection: some View {
        Section {
            Picker(
                String(
                    localized: "contactcertsig.certificationKind",
                    defaultValue: "Certification Kind"
                ),
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
        }
    }

    private var actionSection: some View {
        Section {
            Button {
                switch model.mode {
                case .directKeyVerify:
                    model.verifyDirectKey()
                case .userIdBindingVerify:
                    model.verifyUserIdBinding()
                case .certifyUserId:
                    model.certifyUserId()
                }
            } label: {
                ContactCertificateActionButtonLabel(
                    title: actionTitle,
                    isRunning: model.activeOperation == currentOperation
                )
            }
            .buttonStyle(.borderedProminent)
            .disabled(actionDisabled)
        }
    }

    private func resultSection(
        _ verification: CertificateSignatureVerification
    ) -> some View {
        Section {
            LabeledContent(
                String(localized: "contactcertsig.result.status", defaultValue: "Status"),
                value: statusTitle(for: verification.status)
            )

            if let certificationKind = verification.certificationKind {
                LabeledContent(
                    String(
                        localized: "contactcertsig.result.kind",
                        defaultValue: "Certification Kind"
                    ),
                    value: model.title(for: certificationKind)
                )
            }

            if let signingKeyFingerprint = verification.signingKeyFingerprint {
                LabeledContent(
                    String(
                        localized: "contactcertsig.result.signingKey",
                        defaultValue: "Signing Key"
                    ),
                    value: IdentityPresentation.formattedFingerprint(signingKeyFingerprint)
                )
            }

            if let signerIdentity = verification.signerIdentity {
                ContactCertificateSignerIdentityCard(identity: signerIdentity)
            }
        } header: {
            Text(String(localized: "contactcertsig.result", defaultValue: "Result"))
        }
    }

    private var actionDisabled: Bool {
        switch model.mode {
        case .directKeyVerify:
            !model.canVerifyDirectKey
        case .userIdBindingVerify:
            !model.canVerifyUserIdBinding
        case .certifyUserId:
            !model.canCertifyUserId
        }
    }

    private var actionTitle: String {
        switch model.mode {
        case .directKeyVerify:
            String(localized: "contactcertsig.action.verifyDirect", defaultValue: "Verify Direct-Key Signature")
        case .userIdBindingVerify:
            String(localized: "contactcertsig.action.verifyBinding", defaultValue: "Verify User ID Binding")
        case .certifyUserId:
            String(localized: "contactcertsig.action.certify", defaultValue: "Generate Certification")
        }
    }

    private var currentOperation: ContactCertificateSignaturesScreenModel.ActiveOperation {
        switch model.mode {
        case .directKeyVerify:
            .directKeyVerify
        case .userIdBindingVerify:
            .userIdBindingVerify
        case .certifyUserId:
            .certifyUserId
        }
    }

    private func statusTitle(for status: CertificateSignatureStatus) -> String {
        switch status {
        case .valid:
            String(localized: "contactcertsig.status.valid", defaultValue: "Valid")
        case .invalid:
            String(localized: "contactcertsig.status.invalid", defaultValue: "Invalid")
        case .signerMissing:
            String(localized: "contactcertsig.status.signerMissing", defaultValue: "Signer Missing")
        }
    }
}

private struct ContactCertificateSelectableUserIdRow: View {
    let userId: UserIdSelectionOption
    let isSelected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text(userId.displayText)
                    .font(.headline)
                Text(
                    String(
                        localized: "contactcertsig.userId.occurrence",
                        defaultValue: "Occurrence \(userId.occurrenceIndex + 1)"
                    )
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                HStack {
                    if userId.isCurrentlyPrimary {
                        ContactCertificateStatusBadge(
                            title: String(localized: "contactcertsig.userId.primary", defaultValue: "Primary"),
                            color: .blue
                        )
                    }
                    if userId.isCurrentlyRevoked {
                        ContactCertificateStatusBadge(
                            title: String(localized: "contactcertsig.userId.revoked", defaultValue: "Revoked"),
                            color: .red
                        )
                    }
                }
            }

            Spacer()

            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.tint)
            }
        }
        .contentShape(Rectangle())
    }
}

private struct ContactCertificateActionButtonLabel: View {
    let title: String
    let isRunning: Bool

    var body: some View {
        if isRunning {
            HStack {
                ProgressView()
                Text(String(localized: "common.working", defaultValue: "Working..."))
            }
            .frame(maxWidth: .infinity)
        } else {
            Text(title)
                .frame(maxWidth: .infinity)
        }
    }
}

private struct ContactCertificateSignerIdentityCard: View {
    let identity: CertificateSignatureSignerIdentity

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(
                String(
                    localized: "contactcertsig.result.signer",
                    defaultValue: "Signer"
                )
            )
            .font(.subheadline.weight(.semibold))

            Text(identity.displayName)
                .font(.headline)

            if let secondaryText = identity.secondaryText {
                Text(secondaryText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text(IdentityPresentation.formattedFingerprint(identity.fingerprint))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)

            HStack {
                ContactCertificateStatusBadge(
                    title: sourceTitle,
                    color: sourceColor
                )
                if identity.source == .contact && identity.isVerifiedContact {
                    ContactCertificateStatusBadge(
                        title: String(
                            localized: "contactcertsig.signer.verified",
                            defaultValue: "Verified Contact"
                        ),
                        color: .green
                    )
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var sourceTitle: String {
        switch identity.source {
        case .contact:
            String(localized: "contactcertsig.signer.contact", defaultValue: "Contact")
        case .ownKey:
            String(localized: "contactcertsig.signer.ownKey", defaultValue: "Your Key")
        case .unknown:
            String(localized: "contactcertsig.signer.unknown", defaultValue: "Unknown")
        }
    }

    private var sourceColor: Color {
        switch identity.source {
        case .contact:
            .blue
        case .ownKey:
            .green
        case .unknown:
            .secondary
        }
    }
}

private struct ContactCertificateStatusBadge: View {
    let title: String
    let color: Color

    var body: some View {
        Text(title)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.14), in: Capsule())
            .foregroundStyle(color)
    }
}
