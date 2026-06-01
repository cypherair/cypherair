import SwiftUI

@MainActor
struct ImportConfirmationRequest: Identifiable {
    let id = UUID()
    let keyData: Data
    let metadata: PGPKeyMetadata
    let candidateMatch: ContactCandidateMatch?
    let allowsUnverifiedImport: Bool
    let onImportVerified: @MainActor () -> Void
    let onImportUnverified: @MainActor () -> Void
    let onCancel: @MainActor () -> Void

    init(
        keyData: Data,
        metadata: PGPKeyMetadata,
        candidateMatch: ContactCandidateMatch? = nil,
        allowsUnverifiedImport: Bool,
        onImportVerified: @escaping @MainActor () -> Void,
        onImportUnverified: @escaping @MainActor () -> Void,
        onCancel: @escaping @MainActor () -> Void
    ) {
        self.keyData = keyData
        self.metadata = metadata
        self.candidateMatch = candidateMatch
        self.allowsUnverifiedImport = allowsUnverifiedImport
        self.onImportVerified = onImportVerified
        self.onImportUnverified = onImportUnverified
        self.onCancel = onCancel
    }
}

@MainActor
@Observable
final class ImportConfirmationCoordinator {
    var request: ImportConfirmationRequest?

    @discardableResult
    func present(_ request: ImportConfirmationRequest) -> Bool {
        guard self.request == nil else {
            return false
        }
        self.request = request
        return true
    }

    func dismiss(_ displayedRequest: ImportConfirmationRequest? = nil) {
        if let displayedRequest,
           request?.id != displayedRequest.id {
            return
        }
        request = nil
    }

    func confirmVerified(_ displayedRequest: ImportConfirmationRequest? = nil) {
        guard let request = displayedRequest ?? request,
              self.request?.id == request.id else { return }
        dismiss(request)
        request.onImportVerified()
    }

    func confirmUnverified(_ displayedRequest: ImportConfirmationRequest? = nil) {
        guard let request = displayedRequest ?? request,
              self.request?.id == request.id else { return }
        dismiss(request)
        request.onImportUnverified()
    }
}

private struct ImportConfirmationCoordinatorKey: EnvironmentKey {
    static let defaultValue: ImportConfirmationCoordinator?
        = nil
}

extension EnvironmentValues {
    var importConfirmationCoordinator: ImportConfirmationCoordinator? {
        get { self[ImportConfirmationCoordinatorKey.self] }
        set { self[ImportConfirmationCoordinatorKey.self] = newValue }
    }
}

struct ImportConfirmationSheetHost<Content: View>: View {
    let coordinator: ImportConfirmationCoordinator
    @ViewBuilder let content: () -> Content

    var body: some View {
        @Bindable var bindableCoordinator = coordinator

        content()
            .environment(\.importConfirmationCoordinator, coordinator)
            .sheet(item: $bindableCoordinator.request) { request in
                ImportConfirmView(
                    metadata: request.metadata,
                    candidateMatch: request.candidateMatch,
                    onImportVerified: {
                        coordinator.confirmVerified(request)
                    },
                    onImportUnverified: request.allowsUnverifiedImport ? {
                        coordinator.confirmUnverified(request)
                    } : nil,
                    onCancel: {
                        let onCancel = request.onCancel
                        coordinator.dismiss(request)
                        onCancel()
                    }
                )
            }
    }
}
