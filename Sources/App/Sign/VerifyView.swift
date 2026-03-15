import SwiftUI
import UniformTypeIdentifiers

/// Signature verification view — supports cleartext and detached signatures.
struct VerifyView: View {
    @Environment(SigningService.self) private var signingService

    enum VerifyMode: String, CaseIterable {
        case cleartext, detached
        var label: String {
            switch self {
            case .cleartext: String(localized: "verify.mode.cleartext", defaultValue: "Cleartext")
            case .detached: String(localized: "verify.mode.detached", defaultValue: "Detached")
            }
        }
    }

    @State private var verifyMode: VerifyMode = .cleartext
    @State private var signedInput = ""
    @State private var isVerifying = false
    @State private var originalText: String?
    @State private var verification: SignatureVerification?
    @State private var error: CypherAirError?
    @State private var showError = false

    // Detached mode state
    @State private var showOriginalFileImporter = false
    @State private var showSignatureFileImporter = false
    @State private var originalFileURL: URL?
    @State private var originalFileName: String?
    @State private var signatureFileURL: URL?
    @State private var signatureFileName: String?

    var body: some View {
        Form {
            Section {
                Picker(String(localized: "verify.mode", defaultValue: "Mode"), selection: $verifyMode) {
                    ForEach(VerifyMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            if verifyMode == .cleartext {
                cleartextContent
            } else {
                detachedContent
            }

            Section {
                Button {
                    if verifyMode == .cleartext {
                        verifyCleartext()
                    } else {
                        verifyDetached()
                    }
                } label: {
                    if isVerifying {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "verify.button", defaultValue: "Verify"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(verifyButtonDisabled)
            }

            if let originalText {
                Section {
                    Text(originalText)
                        .textSelection(.enabled)
                } header: {
                    Text(String(localized: "verify.originalText", defaultValue: "Original Message"))
                }
            }

            if let verification {
                Section {
                    HStack {
                        Image(systemName: verification.symbolName)
                            .foregroundStyle(verification.statusColor)
                        Text(verification.statusDescription)
                            .font(.subheadline)
                    }
                    .accessibilityElement(children: .combine)
                } header: {
                    Text(String(localized: "verify.result", defaultValue: "Verification Result"))
                }
            }
        }
        .scrollDismissesKeyboard(.interactively)
        .navigationTitle(String(localized: "verify.title", defaultValue: "Verify"))
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .fileImporter(
            isPresented: $showOriginalFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                originalFileURL = url
                originalFileName = url.lastPathComponent
            }
        }
        .fileImporter(
            isPresented: $showSignatureFileImporter,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                signatureFileURL = url
                signatureFileName = url.lastPathComponent
            }
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private var cleartextContent: some View {
        Section {
            TextEditor(text: $signedInput)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 100)
        } header: {
            Text(String(localized: "verify.input", defaultValue: "Signed Message"))
        }
    }

    @ViewBuilder
    private var detachedContent: some View {
        Section {
            Button {
                showOriginalFileImporter = true
            } label: {
                Label(
                    String(localized: "verify.selectOriginal", defaultValue: "Select Original File"),
                    systemImage: "doc"
                )
            }
            if let originalFileName {
                LabeledContent(
                    String(localized: "verify.originalFile", defaultValue: "Original"),
                    value: originalFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.original", defaultValue: "Original File"))
        }

        Section {
            Button {
                showSignatureFileImporter = true
            } label: {
                Label(
                    String(localized: "verify.selectSignature", defaultValue: "Select .sig File"),
                    systemImage: "signature"
                )
            }
            if let signatureFileName {
                LabeledContent(
                    String(localized: "verify.signatureFile", defaultValue: "Signature"),
                    value: signatureFileName
                )
            }
        } header: {
            Text(String(localized: "verify.detached.signature", defaultValue: "Signature File"))
        }
    }

    // MARK: - State

    private var verifyButtonDisabled: Bool {
        if isVerifying { return true }
        switch verifyMode {
        case .cleartext: return signedInput.isEmpty
        case .detached: return originalFileURL == nil || signatureFileURL == nil
        }
    }

    // MARK: - Actions

    private func verifyCleartext() {
        isVerifying = true
        let service = signingService
        let inputData = Data(signedInput.utf8)
        Task {
            do {
                let result = try await service.verifyCleartext(inputData)
                if let content = result.text {
                    originalText = String(data: content, encoding: .utf8)
                }
                verification = result.verification
            } catch {
                self.error = CypherAirError.from(error) { _ in .badSignature }
                showError = true
            }
            isVerifying = false
        }
    }

    private func verifyDetached() {
        guard let origURL = originalFileURL, let sigURL = signatureFileURL else { return }
        isVerifying = true
        let service = signingService
        Task {
            do {
                guard origURL.startAccessingSecurityScopedResource() else {
                    throw CypherAirError.internalError(reason: String(localized: "verify.cannotAccessOriginal", defaultValue: "Cannot access original file"))
                }
                defer { origURL.stopAccessingSecurityScopedResource() }

                guard sigURL.startAccessingSecurityScopedResource() else {
                    throw CypherAirError.internalError(reason: String(localized: "verify.cannotAccessSignature", defaultValue: "Cannot access signature file"))
                }
                defer { sigURL.stopAccessingSecurityScopedResource() }

                let fileData = try Data(contentsOf: origURL)
                let sigData = try Data(contentsOf: sigURL)
                let result = try await service.verifyDetached(data: fileData, signature: sigData)
                verification = result
            } catch {
                self.error = CypherAirError.from(error) { _ in .badSignature }
                showError = true
            }
            isVerifying = false
        }
    }
}
