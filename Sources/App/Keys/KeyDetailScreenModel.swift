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
    typealias RecoveryReportProvider = @MainActor () -> SecureEnclaveCustodyGenerationRecoveryReport

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
    private let recoveryReportProvider: RecoveryReportProvider

    private var hasPrepared = false
    private var revocationExportTask: Task<Void, Never>?
    private var revocationExportGeneration: UInt64 = 0

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
        clipboardCopyAction: ClipboardCopyAction? = nil,
        recoveryReportProvider: RecoveryReportProvider? = nil
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
        self.recoveryReportProvider = recoveryReportProvider ?? {
            keyManagement.secureEnclaveCustodyRecoveryReport
        }
    }

    var key: PGPKeyIdentity? {
        keyManagement.keys.first { $0.fingerprint == fingerprint }
    }

    var isDeviceBound: Bool {
        key?.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations
    }

    /// Whether the sanitized recovery report shows a problem for this
    /// device-bound key. Quiet when healthy; the detail screen renders a
    /// degraded row only when this is true.
    var deviceBoundAvailabilityIsDegraded: Bool {
        guard isDeviceBound else {
            return false
        }
        return Self.isDeviceBoundAvailabilityDegraded(
            fingerprint: fingerprint,
            keys: keyManagement.keys,
            report: recoveryReportProvider()
        )
    }

    /// Maps a device-bound key to its recovery assessment by ordinal among
    /// Secure Enclave custody keys in catalog order — assessments are
    /// fingerprint-free by design, so the ordinal is the only join key. A
    /// missing assessment for a device-bound key is reported as degraded
    /// (fail-visible) rather than silently healthy.
    nonisolated static func isDeviceBoundAvailabilityDegraded(
        fingerprint: String,
        keys: [PGPKeyIdentity],
        report: SecureEnclaveCustodyGenerationRecoveryReport
    ) -> Bool {
        if report.inventoryFailureCategory != nil {
            return true
        }
        let secureEnclaveKeys = keys.filter {
            $0.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations
        }
        guard let ordinal = secureEnclaveKeys.firstIndex(where: { $0.fingerprint == fingerprint }) else {
            return true
        }
        guard let assessment = report.assessments.first(where: { $0.identityOrdinal == ordinal }) else {
            return true
        }
        return assessment.publicMaterialAvailability != .available
            || assessment.revocationArtifactAvailability != .available
            || assessment.handleAvailability != .available
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

        revocationExportTask?.cancel()
        revocationExportGeneration &+= 1
        let generation = revocationExportGeneration
        isPreparingRevocationExport = true

        revocationExportTask = Task { [weak self, generation] in
            guard let self else { return }
            defer {
                if generation == self.revocationExportGeneration {
                    self.isPreparingRevocationExport = false
                    self.revocationExportTask = nil
                }
            }

            do {
                let exported = try await self.revocationExportAction(self.fingerprint)
                try Task.checkCancellation()
                guard generation == self.revocationExportGeneration else {
                    return
                }
                if try self.configuration.outputInterceptionPolicy.interceptDataExport?(
                    exported,
                    self.exportFilename(for: .revocation),
                    .revocation
                ) != true {
                    try self.exportController.prepareDataExport(
                        exported,
                        suggestedFilename: self.exportFilename(for: .revocation)
                    )
                }
            } catch {
                guard !Self.shouldIgnore(error),
                      generation == self.revocationExportGeneration else {
                    return
                }
                self.presentMappedError(error)
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

    func handleDisappear() {
        revocationExportGeneration &+= 1
        revocationExportTask?.cancel()
        revocationExportTask = nil
        isPreparingRevocationExport = false
        exportController.finish()
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

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        return false
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
