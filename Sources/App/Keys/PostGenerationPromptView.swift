import SwiftUI

/// Shown after key generation to prompt the user to back up and share their key.
/// Per PRD Section 4.1: "Done → Prompt: back up private key & share public key"
///
/// Device-bound Secure Enclave custody keys have no private-key backup: their
/// variant states that consequence and makes revocation-certificate export the
/// primary action instead.
struct PostGenerationPromptView: View {
    let identity: PGPKeyIdentity
    let onDone: (() -> Void)?

    @Environment(KeyManagementService.self) private var keyManagement

    init(
        identity: PGPKeyIdentity,
        onDone: (() -> Void)? = nil
    ) {
        self.identity = identity
        self.onDone = onDone
    }

    var body: some View {
        PostGenerationPromptHostView(
            identity: identity,
            onDone: onDone,
            keyManagement: keyManagement
        )
    }
}

private struct PostGenerationPromptHostView: View {
    let onDone: (() -> Void)?

    @State private var model: PostGenerationPromptScreenModel
    @Environment(\.dismiss) private var dismiss

    init(
        identity: PGPKeyIdentity,
        onDone: (() -> Void)?,
        keyManagement: KeyManagementService
    ) {
        self.onDone = onDone
        _model = State(
            initialValue: PostGenerationPromptScreenModel(
                identity: identity,
                keyManagement: keyManagement
            )
        )
    }

    private var identity: PGPKeyIdentity { model.identity }

    var body: some View {
        let exportController = model.exportController

        List {
            if model.isDeviceBound {
                deviceBoundHeaderSection
                deviceBoundActionsSection
            } else {
                softwareHeaderSection
                softwareActionsSection
            }
        }
        .cypherMacReadableContent()
        .accessibilityIdentifier("postgen.root")
        .screenReady("postgen.ready")
        .navigationTitle(String(localized: "postgen.title", defaultValue: "Key Ready"))
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "postgen.done", defaultValue: "Done")) {
                    handleDone()
                }
                .accessibilityIdentifier("postgen.done")
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
        .onDisappear {
            model.handleDisappear()
        }
    }

    private var softwareHeaderSection: some View {
        Section {
            VStack(spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.green)
                    .accessibilityHidden(true)

                Text(String(localized: "postgen.success", defaultValue: "Key Generated"))
                    .font(.headline)

                Text(String(localized: "postgen.subtitle", defaultValue: "Back up your private key and share your public key with contacts."))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical)
        }
    }

    private var softwareActionsSection: some View {
        Section {
            NavigationLink(value: AppRoute.backupKey(fingerprint: identity.fingerprint)) {
                Label(
                    String(localized: "postgen.backup", defaultValue: "Back Up Private Key"),
                    systemImage: "lock.doc"
                )
            }
            .accessibilityIdentifier("postgen.backup")

            shareQRLink
            keyDetailLink
        } header: {
            Text(String(localized: "postgen.nextSteps", defaultValue: "Next Steps"))
        }
    }

    private var deviceBoundHeaderSection: some View {
        Section {
            VStack(spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.green)
                    .accessibilityHidden(true)

                Text(String(localized: "postgen.deviceBound.success", defaultValue: "Key Created"))
                    .font(.headline)

                Text(String(
                    localized: "postgen.deviceBound.subtitle",
                    defaultValue: "This key cannot be backed up. Export its revocation certificate and share your public key with contacts."
                ))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical)
        }
    }

    private var deviceBoundActionsSection: some View {
        Section {
            Button {
                model.exportRevocationCertificate()
            } label: {
                if model.isPreparingRevocationExport {
                    ProgressView()
                        .cypherPrimaryActionLabelFrame()
                } else {
                    Text(String(
                        localized: "postgen.deviceBound.exportRevocation",
                        defaultValue: "Export Revocation Certificate"
                    ))
                    .cypherPrimaryActionLabelFrame()
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isPreparingRevocationExport)
            .accessibilityIdentifier("postgen.deviceBound.exportRevocation")

            shareQRLink
            keyDetailLink
        } header: {
            Text(String(localized: "postgen.nextSteps", defaultValue: "Next Steps"))
        }
    }

    private var shareQRLink: some View {
        NavigationLink(value: AppRoute.qrDisplay(publicKeyData: identity.publicKeyData, displayName: identity.userId ?? identity.shortKeyId)) {
            Label(
                String(localized: "postgen.shareQR", defaultValue: "Share Public Key via QR"),
                systemImage: "qrcode"
            )
        }
        .accessibilityIdentifier("postgen.qr")
    }

    private var keyDetailLink: some View {
        NavigationLink(value: AppRoute.keyDetail(fingerprint: identity.fingerprint)) {
            Label(
                String(localized: "postgen.viewKey", defaultValue: "View Key Details"),
                systemImage: "key"
            )
        }
        .accessibilityIdentifier("postgen.keyDetail")
    }

    private func handleDone() {
        if let onDone {
            onDone()
        } else {
            dismiss()
        }
    }
}
