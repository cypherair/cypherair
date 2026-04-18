import Foundation

@MainActor
@Observable
final class SelectiveRevocationScreenModel {
    typealias SelectionCatalogAction = @MainActor (String) throws -> CertificateSelectionCatalog
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
            try keyManagement.selectionCatalog(fingerprint: fingerprint)
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

        activeExportOperation = .subkey

        Task {
            defer {
                activeExportOperation = nil
            }

            do {
                let exported = try await subkeyRevocationExportAction(fingerprint, selectedSubkey)
                try prepareExport(exported, filename: subkeyExportFilename(for: selectedSubkey))
            } catch {
                presentMappedError(error)
            }
        }
    }

    func exportSelectedUserId() {
        guard let selectedUserId, canExportUserId else {
            return
        }

        activeExportOperation = .userId

        Task {
            defer {
                activeExportOperation = nil
            }

            do {
                let exported = try await userIdRevocationExportAction(fingerprint, selectedUserId)
                try prepareExport(exported, filename: userIdExportFilename(for: selectedUserId))
            } catch {
                presentMappedError(error)
            }
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

    private func loadCatalog() {
        loadState = .loading

        do {
            catalog = try selectionCatalogAction(fingerprint)
            loadError = nil
            loadState = .loaded
        } catch {
            catalog = nil
            loadError = CypherAirError.from(error) { .invalidKeyData(reason: $0) }
            loadState = .failed
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
