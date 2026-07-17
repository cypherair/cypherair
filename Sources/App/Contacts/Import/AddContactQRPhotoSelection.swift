import Foundation

struct AddContactQRPhotoSelection {
    private let loadKeyDataAction: @MainActor () async throws -> Data

    init(
        loadKeyData: @escaping @MainActor () async throws -> Data
    ) {
        self.loadKeyDataAction = loadKeyData
    }

    @MainActor
    func loadKeyData() async throws -> Data {
        try await loadKeyDataAction()
    }
}
