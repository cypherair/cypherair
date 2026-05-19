import Foundation

struct AddContactQRPhotoSelection {
    let identifier: String?

    private let loadKeyDataAction: @MainActor () async throws -> Data

    init(
        identifier: String?,
        loadKeyData: @escaping @MainActor () async throws -> Data
    ) {
        self.identifier = identifier
        self.loadKeyDataAction = loadKeyData
    }

    @MainActor
    func loadKeyData() async throws -> Data {
        try await loadKeyDataAction()
    }
}
