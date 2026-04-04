import SwiftUI

@MainActor
struct ImportConfirmationRequest: Identifiable {
    let id = UUID()
    let keyData: Data
    let keyInfo: KeyInfo
    let profile: KeyProfile
    let allowsUnverifiedImport: Bool
    let onImportVerified: @MainActor () -> Void
    let onImportUnverified: @MainActor () -> Void
    let onCancel: @MainActor () -> Void
}

@MainActor
@Observable
final class ImportConfirmationCoordinator {
    var request: ImportConfirmationRequest?

    func present(_ request: ImportConfirmationRequest) {
        self.request = request
    }

    func dismiss() {
        request = nil
    }

    func confirmVerified() {
        guard let request else { return }
        dismiss()
        request.onImportVerified()
    }

    func confirmUnverified() {
        guard let request else { return }
        dismiss()
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
                    keyInfo: request.keyInfo,
                    detectedProfile: request.profile,
                    onImportVerified: {
                        coordinator.confirmVerified()
                    },
                    onImportUnverified: request.allowsUnverifiedImport ? {
                        coordinator.confirmUnverified()
                    } : nil,
                    onCancel: {
                        let onCancel = request.onCancel
                        coordinator.dismiss()
                        onCancel()
                    }
                )
            }
    }
}
