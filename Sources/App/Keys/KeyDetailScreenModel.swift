import Foundation
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif

@MainActor
@Observable
final class KeyDetailScreenModel {
    typealias PublicKeyExportAction = @MainActor (String) throws -> Data
    typealias RevocationExportAction = @MainActor (String) async throws -> Data
    typealias DefaultKeyAction = @MainActor (String) throws -> Void
    typealias DeleteKeyAction = @MainActor (String) throws -> Void
    typealias ClipboardCopyAction = @MainActor (String) -> Void

    let fingerprint: String
    let configuration: KeyDetailView.Configuration
    let exportController: FileExportController

    private let appConfiguration: AppConfiguration
    private let keyManagement: KeyManagementService
    private let macPresentationController: MacPresentationController?
    private let dismissAction: @MainActor () -> Void
    private let publicKeyExportAction: PublicKeyExportAction
    private let revocationExportAction: RevocationExportAction
    private let defaultKeyAction: DefaultKeyAction
    private let deleteKeyAction: DeleteKeyAction
    private let clipboardCopyAction: ClipboardCopyAction

    private var hasPrepared = false

    var armoredPublicKey: Data?
    var showDeleteConfirmation = false
    var error: CypherAirError?
    var showError = false
    var showCopiedNotice = false
    var isPreparingRevocationExport = false
    var localModifyExpiryRequest: ModifyExpiryRequest?
    var suggestedExpiryDate = Calendar.current.date(byAdding: .year, value: 2, to: Date()) ?? Date()

    init(
        fingerprint: String,
        config: AppConfiguration,
        keyManagement: KeyManagementService,
        macPresentationController: MacPresentationController?,
        configuration: KeyDetailView.Configuration,
        exportController: FileExportController = FileExportController(),
        dismissAction: @escaping @MainActor () -> Void,
        publicKeyExportAction: PublicKeyExportAction? = nil,
        revocationExportAction: RevocationExportAction? = nil,
        defaultKeyAction: DefaultKeyAction? = nil,
        deleteKeyAction: DeleteKeyAction? = nil,
        clipboardCopyAction: ClipboardCopyAction? = nil
    ) {
        self.fingerprint = fingerprint
        self.configuration = configuration
        self.exportController = exportController
        self.appConfiguration = config
        self.keyManagement = keyManagement
        self.macPresentationController = macPresentationController
        self.dismissAction = dismissAction
        self.publicKeyExportAction = publicKeyExportAction ?? { fingerprint in
            try keyManagement.exportPublicKey(fingerprint: fingerprint)
        }
        self.revocationExportAction = revocationExportAction ?? { fingerprint in
            try await keyManagement.exportRevocationCertificate(fingerprint: fingerprint)
        }
        self.defaultKeyAction = defaultKeyAction ?? { fingerprint in
            try keyManagement.setDefaultKey(fingerprint: fingerprint)
        }
        self.deleteKeyAction = deleteKeyAction ?? { fingerprint in
            try keyManagement.deleteKey(fingerprint: fingerprint)
        }
        self.clipboardCopyAction = clipboardCopyAction ?? { string in
            #if canImport(UIKit)
            UIPasteboard.general.string = string
            #elseif canImport(AppKit)
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(string, forType: .string)
            #endif
        }
    }

    var key: PGPKeyIdentity? {
        keyManagement.keys.first { $0.fingerprint == fingerprint }
    }

    func prepareIfNeeded() {
        guard !hasPrepared else { return }
        reloadPublicKey()
        hasPrepared = true
    }

    func exportPublicKey() {
        guard configuration.allowsPublicKeySave,
              let armoredPublicKey else {
            return
        }

        do {
            if try configuration.outputInterceptionPolicy.interceptDataExport?(
                armoredPublicKey,
                exportFilename(for: .publicKey),
                .publicKey
            ) != true {
                try exportController.prepareDataExport(
                    armoredPublicKey,
                    suggestedFilename: exportFilename(for: .publicKey)
                )
            }
        } catch {
            presentMappedError(error)
        }
    }

    func copyPublicKey() {
        guard configuration.allowsPublicKeyCopy,
              let armoredPublicKey,
              let armoredString = String(data: armoredPublicKey, encoding: .utf8) else {
            return
        }

        if configuration.outputInterceptionPolicy.interceptClipboardCopy?(
            armoredString,
            appConfiguration,
            .publicKey
        ) != true {
            clipboardCopyAction(armoredString)
            showCopiedNotice = true
        }
    }

    func exportRevocationCertificate() {
        guard configuration.allowsRevocationExport,
              !isPreparingRevocationExport else {
            return
        }

        isPreparingRevocationExport = true

        Task {
            defer {
                isPreparingRevocationExport = false
            }

            do {
                let exported = try await revocationExportAction(fingerprint)
                if try configuration.outputInterceptionPolicy.interceptDataExport?(
                    exported,
                    exportFilename(for: .revocation),
                    .revocation
                ) != true {
                    try exportController.prepareDataExport(
                        exported,
                        suggestedFilename: exportFilename(for: .revocation)
                    )
                }
            } catch {
                presentMappedError(error)
            }
        }
    }

    func setDefaultKey() {
        do {
            try defaultKeyAction(fingerprint)
        } catch {
            presentMappedError(error)
        }
    }

    func deleteKey() {
        do {
            try deleteKeyAction(fingerprint)
            dismissAction()
        } catch {
            presentMappedError(error)
        }
    }

    func presentModifyExpiry() {
        let request = makeModifyExpiryRequest()

        if let macPresentationController {
            macPresentationController.present(.modifyExpiry(request))
        } else {
            localModifyExpiryRequest = request
        }
    }

    func dismissModifyExpiryPresentation() {
        localModifyExpiryRequest = nil
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func dismissCopiedNotice() {
        showCopiedNotice = false
    }

    func finishExport() {
        exportController.finish()
    }

    func handleExportError(_ error: Error) {
        presentMappedError(error)
    }

    private func makeModifyExpiryRequest() -> ModifyExpiryRequest {
        ModifyExpiryRequest(
            fingerprint: fingerprint,
            initialDate: suggestedExpiryDate
        ) { [weak self] in
            self?.reloadPublicKey()
            self?.localModifyExpiryRequest = nil
        }
    }

    private func reloadPublicKey() {
        do {
            armoredPublicKey = try publicKeyExportAction(fingerprint)
        } catch {
            armoredPublicKey = nil
        }
    }

    private func presentMappedError(_ error: Error) {
        self.error = CypherAirError.from(error) { .keychainError($0) }
        showError = true
    }

    private func exportFilename(for exportType: ExportType) -> String {
        switch exportType {
        case .publicKey:
            "\(key?.shortKeyId ?? "key").asc"
        case .revocation:
            "revocation-\(key?.shortKeyId ?? "key").asc"
        }
    }

    private enum ExportType {
        case publicKey
        case revocation
    }
}
