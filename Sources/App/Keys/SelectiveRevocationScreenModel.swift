import Foundation

@MainActor
@Observable
final class SelectiveRevocationScreenModel {
    typealias SelectionCatalogAction = @MainActor (String) async throws -> CertificateSelectionCatalog
    typealias SubkeyRevocationExportAction = @MainActor (String, SubkeySelectionOption) async throws -> Data
    typealias UserIdRevocationExportAction = @MainActor (String, UserIdSelectionOption) async throws -> Data

    enum LoadState {
        case idle
        case loading
        case loaded
        case failed
    }

    enum ExportOperation: Equatable {
        case subkey
        case userId
    }

    let fingerprint: String
    let configuration: SelectiveRevocationView.Configuration
    let exportController: FileExportController

    private let keyManagement: KeyManagementService
    private let selectionCatalogAction: SelectionCatalogAction
    private let subkeyRevocationExportAction: SubkeyRevocationExportAction
    private let userIdRevocationExportAction: UserIdRevocationExportAction

    private var catalogLoadTask: Task<Void, Never>?
    private var catalogLoadGeneration: UInt64 = 0
    private var exportTask: Task<Void, Never>?
    private var exportGeneration: UInt64 = 0

    private(set) var loadState: LoadState = .idle
    private(set) var catalog: CertificateSelectionCatalog?
    private(set) var loadError: CypherAirError?

    var selectedSubkey: SubkeySelectionOption?
    var selectedUserId: UserIdSelectionOption?
    var activeExportOperation: ExportOperation?
    var error: CypherAirError?
    var showError = false

    init(
        fingerprint: String,
        keyManagement: KeyManagementService,
        configuration: SelectiveRevocationView.Configuration = .default,
        exportController: FileExportController = FileExportController(),
        selectionCatalogAction: SelectionCatalogAction? = nil,
        subkeyRevocationExportAction: SubkeyRevocationExportAction? = nil,
        userIdRevocationExportAction: UserIdRevocationExportAction? = nil
    ) {
        self.fingerprint = fingerprint
        self.keyManagement = keyManagement
        self.configuration = configuration
        self.exportController = exportController
        self.selectionCatalogAction = selectionCatalogAction ?? { fingerprint in
            try await keyManagement.loadSelectionCatalog(fingerprint: fingerprint)
        }
        self.subkeyRevocationExportAction = subkeyRevocationExportAction ?? { fingerprint, selection in
            try await keyManagement.exportSubkeyRevocationCertificate(
                fingerprint: fingerprint,
                subkeySelection: selection
            )
        }
        self.userIdRevocationExportAction = userIdRevocationExportAction ?? { fingerprint, selection in
            try await keyManagement.exportUserIdRevocationCertificate(
                fingerprint: fingerprint,
                userIdSelection: selection
            )
        }
    }

    var key: PGPKeyIdentity? {
        keyManagement.keys.first { $0.fingerprint == fingerprint }
    }

    var subkeys: [SubkeySelectionOption] {
        catalog?.subkeys ?? []
    }

    var userIds: [UserIdSelectionOption] {
        catalog?.userIds ?? []
    }

    var isLoading: Bool {
        if case .loading = loadState {
            return true
        }
        return false
    }

    var isExportLocked: Bool {
        activeExportOperation != nil || exportController.isPresented
    }

    var canExportSubkey: Bool {
        selectedSubkey != nil && !isExportLocked
    }

    var canExportUserId: Bool {
        selectedUserId != nil && !isExportLocked
    }

    func loadIfNeeded() {
        guard case .idle = loadState else {
            return
        }

        loadCatalog()
    }

    func retry() {
        guard !isLoading else {
            return
        }

        catalog = nil
        loadError = nil
        selectedSubkey = nil
        selectedUserId = nil
        loadCatalog()
    }

    func selectSubkey(_ subkey: SubkeySelectionOption) {
        guard !isExportLocked else {
            return
        }

        selectedSubkey = subkey
    }

    func selectUserId(_ userId: UserIdSelectionOption) {
        guard !isExportLocked else {
            return
        }

        selectedUserId = userId
    }

    func exportSelectedSubkey() {
        guard let selectedSubkey, canExportSubkey else {
            return
        }

        startExport(
            operation: .subkey,
            filename: subkeyExportFilename(for: selectedSubkey)
        ) {
            try await self.subkeyRevocationExportAction(self.fingerprint, selectedSubkey)
        }
    }

    func exportSelectedUserId() {
        guard let selectedUserId, canExportUserId else {
            return
        }

        startExport(
            operation: .userId,
            filename: userIdExportFilename(for: selectedUserId)
        ) {
            try await self.userIdRevocationExportAction(self.fingerprint, selectedUserId)
        }
    }

    func finishExport() {
        exportController.finish()
    }

    func handleExportError(_ error: Error) {
        presentMappedError(error)
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func handleDisappear() {
        catalogLoadGeneration &+= 1
        catalogLoadTask?.cancel()
        catalogLoadTask = nil

        if isLoading {
            loadState = .idle
        }

        exportGeneration &+= 1
        exportTask?.cancel()
        exportTask = nil
        activeExportOperation = nil
        exportController.finish()
    }

    private func loadCatalog() {
        catalogLoadTask?.cancel()
        catalogLoadGeneration &+= 1
        let generation = catalogLoadGeneration
        loadState = .loading
        let fingerprint = self.fingerprint
        let selectionCatalogAction = self.selectionCatalogAction

        catalogLoadTask = Task { [weak self, generation] in
            defer {
                if let self, generation == self.catalogLoadGeneration {
                    self.catalogLoadTask = nil
                }
            }

            do {
                await Task.yield()
                let catalog = try await selectionCatalogAction(fingerprint)
                try Task.checkCancellation()

                guard let self, generation == self.catalogLoadGeneration else {
                    return
                }

                self.catalog = catalog
                self.loadError = nil
                self.loadState = .loaded
            } catch {
                guard let self else {
                    return
                }
                guard !Self.shouldIgnore(error), generation == self.catalogLoadGeneration else {
                    return
                }

                self.catalog = nil
                self.loadError = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
                self.loadState = .failed
            }
        }
    }

    private func startExport(
        operation: ExportOperation,
        filename: String,
        action: @escaping @MainActor () async throws -> Data
    ) {
        exportTask?.cancel()
        exportGeneration &+= 1
        let generation = exportGeneration
        activeExportOperation = operation

        exportTask = Task { [weak self, generation] in
            defer {
                if let self, generation == self.exportGeneration {
                    self.activeExportOperation = nil
                    self.exportTask = nil
                }
            }

            do {
                // Cancellation is best-effort here. The default export path may already
                // have entered Secure Enclave authentication and synchronous revocation
                // generation before the first suspension point, so dismissal guarantees
                // stale-result suppression rather than aborting all underlying work.
                let exported = try await action()
                try Task.checkCancellation()

                guard let self, generation == self.exportGeneration else {
                    return
                }

                try self.prepareExport(exported, filename: filename)
            } catch {
                guard let self else {
                    return
                }
                guard !Self.shouldIgnore(error), generation == self.exportGeneration else {
                    return
                }

                self.presentMappedError(error)
            }
        }
    }

    private func prepareExport(_ data: Data, filename: String) throws {
        if try configuration.outputInterceptionPolicy.interceptDataExport?(
            data,
            filename,
            .revocation
        ) != true {
            try exportController.prepareDataExport(data, suggestedFilename: filename)
        }
    }

    private func presentMappedError(_ error: Error) {
        self.error = CypherAirError.from(error) { .fileIoError(reason: $0) }
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

    private func subkeyExportFilename(for subkey: SubkeySelectionOption) -> String {
        "subkey-revocation-\(keyShortKeyId)-\(IdentityPresentation.shortKeyId(from: subkey.fingerprint)).asc"
    }

    private func userIdExportFilename(for userId: UserIdSelectionOption) -> String {
        "userid-revocation-\(keyShortKeyId)-\(userId.occurrenceIndex + 1).asc"
    }

    private var keyShortKeyId: String {
        key?.shortKeyId ?? IdentityPresentation.shortKeyId(from: fingerprint)
    }
}
