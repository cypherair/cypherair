import SwiftUI

/// The Reset All Local Data flow: the warning, the typed phrase, the reset,
/// and the restart gate. Hosted by Settings and by the lock surface alike.
@MainActor
@Observable
final class LocalDataResetFlow {
    private let service: LocalDataResetService?
    private let restartCoordinator: LocalDataResetRestartCoordinator?

    var showWarning = false
    var showPhraseSheet = false
    var showFailureAlert = false
    var confirmationPhrase = ""
    private(set) var isResetting = false
    private var errorMessage: String?

    init(service: LocalDataResetService?, restartCoordinator: LocalDataResetRestartCoordinator?) {
        self.service = service
        self.restartCoordinator = restartCoordinator
    }

    var isAvailable: Bool {
        service != nil && !isResetting
    }

    var canConfirm: Bool {
        confirmationPhrase == "RESET"
    }

    var failureMessage: String {
        errorMessage ?? String(
            localized: "settings.resetAll.error.message",
            defaultValue: "CypherAir X could not reset all local data."
        )
    }

    func request() {
        guard isAvailable else { return }
        showWarning = true
    }

    func dismissWarning() {
        showWarning = false
    }

    func continueToPhrase() {
        guard isAvailable else { return }
        showWarning = false
        confirmationPhrase = ""
        showPhraseSheet = true
    }

    func dismissPhraseSheet() {
        guard !isResetting else { return }
        showPhraseSheet = false
        confirmationPhrase = ""
    }

    func clearTransientInput() {
        confirmationPhrase = ""
    }

    func confirm() {
        guard isAvailable, canConfirm, let service else { return }
        showPhraseSheet = false
        isResetting = true
        errorMessage = nil
        Task {
            do {
                try await service.resetAllLocalData()
                restartCoordinator?.markRestartRequired()
            } catch {
                errorMessage = error.localizedDescription
            }
            isResetting = false
            showFailureAlert = errorMessage != nil
            confirmationPhrase = ""
        }
    }

    func dismissFailureAlert() {
        showFailureAlert = false
        errorMessage = nil
    }
}

extension View {
    func localDataResetPresentations(flow: LocalDataResetFlow) -> some View {
        modifier(LocalDataResetPresentations(flow: flow))
    }
}

private struct LocalDataResetPresentations: ViewModifier {
    let flow: LocalDataResetFlow

    func body(content: Content) -> some View {
        content
            .confirmationDialog(
                String(localized: "settings.resetAll.title", defaultValue: "Reset All Local Data?"),
                isPresented: Binding(
                    get: { flow.showWarning },
                    set: { if !$0 { flow.dismissWarning() } }
                ),
                titleVisibility: .visible
            ) {
                Button(
                    String(localized: "settings.resetAll.continue", defaultValue: "Continue"),
                    role: .destructive
                ) {
                    flow.continueToPhrase()
                }
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
            } message: {
                Text(
                    String(
                        localized: "settings.resetAll.warning",
                        defaultValue: "This permanently deletes CypherAir X keys, contacts, preferences, app settings, and temporary files on this device."
                    )
                )
            }
            .sheet(isPresented: Binding(
                get: { flow.showPhraseSheet },
                set: { if !$0 { flow.dismissPhraseSheet() } }
            )) {
                NavigationStack {
                    SettingsLocalDataResetPhraseView(flow: flow)
                }
                #if os(macOS)
                .frame(minWidth: 500, idealWidth: 540, minHeight: 320, idealHeight: 360)
                #endif
            }
            .alert(
                String(localized: "settings.resetAll.error.title", defaultValue: "Reset Failed"),
                isPresented: Binding(
                    get: { flow.showFailureAlert },
                    set: { if !$0 { flow.dismissFailureAlert() } }
                )
            ) {
                Button(String(localized: "error.ok", defaultValue: "OK")) {
                    flow.dismissFailureAlert()
                }
            } message: {
                Text(flow.failureMessage)
            }
    }
}
