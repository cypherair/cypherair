import Foundation

@MainActor
@Observable
final class ModifyExpiryScreenModel {
    typealias ModifyExpiryAction = @MainActor (String, UInt64?) async throws -> PGPKeyIdentity

    let request: ModifyExpiryRequest

    private let modifyExpiryAction: ModifyExpiryAction
    private let dismissAction: @MainActor () -> Void
    private var modifyTask: Task<Void, Never>?
    private var modifyToken: UInt64 = 0

    var newExpiryDate: Date
    var isModifyingExpiry = false
    var error: CypherAirError?
    var showError = false

    init(
        request: ModifyExpiryRequest,
        keyManagement: KeyManagementService,
        dismissAction: @escaping @MainActor () -> Void,
        modifyExpiryAction: ModifyExpiryAction? = nil
    ) {
        self.request = request
        self.newExpiryDate = request.initialDate
        self.dismissAction = dismissAction
        self.modifyExpiryAction = modifyExpiryAction ?? { fingerprint, seconds in
            try await keyManagement.modifyExpiry(
                fingerprint: fingerprint,
                newExpirySeconds: seconds
            )
        }
    }

    func saveSelectedExpiryDate() {
        let seconds = UInt64(max(0, newExpiryDate.timeIntervalSinceNow))
        performModifyExpiry(seconds: seconds)
    }

    func removeExpiry() {
        performModifyExpiry(seconds: nil)
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func handleDisappear() {
        modifyTask?.cancel()
        modifyToken &+= 1
        modifyTask = nil
        isModifyingExpiry = false
    }

    private func performModifyExpiry(seconds: UInt64?) {
        modifyTask?.cancel()
        modifyToken &+= 1
        let token = modifyToken
        isModifyingExpiry = true
        error = nil
        showError = false

        let fingerprint = request.fingerprint
        modifyTask = Task { @MainActor [weak self, token] in
            guard let self else { return }
            defer {
                if token == self.modifyToken {
                    self.isModifyingExpiry = false
                    self.modifyTask = nil
                }
            }

            do {
                _ = try await self.modifyExpiryAction(fingerprint, seconds)
                try Task.checkCancellation()
                guard token == self.modifyToken else {
                    return
                }
                self.request.onComplete()
                self.dismissAction()
            } catch {
                guard !Self.shouldIgnore(error), token == self.modifyToken else {
                    return
                }
                self.error = CypherAirError.from(error) { .keychainError($0) }
                self.showError = true
            }
        }
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
}
