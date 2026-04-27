import SwiftUI

@MainActor
@Observable
final class LocalDataResetRestartCoordinator {
    private(set) var restartRequiredAfterLocalDataReset = false
    private(set) var resetSummary: LocalDataResetSummary?

    func markRestartRequired(summary: LocalDataResetSummary) {
        resetSummary = summary
        restartRequiredAfterLocalDataReset = true
    }
}

struct LocalDataResetRestartGate<Content: View>: View {
    let coordinator: LocalDataResetRestartCoordinator
    let terminateAction: () -> Void
    let content: Content

    init(
        coordinator: LocalDataResetRestartCoordinator,
        terminateAction: @escaping () -> Void,
        @ViewBuilder content: () -> Content
    ) {
        self.coordinator = coordinator
        self.terminateAction = terminateAction
        self.content = content()
    }

    var body: some View {
        ZStack {
            content
                .disabled(coordinator.restartRequiredAfterLocalDataReset)
                .allowsHitTesting(!coordinator.restartRequiredAfterLocalDataReset)
                .accessibilityHidden(coordinator.restartRequiredAfterLocalDataReset)

            if coordinator.restartRequiredAfterLocalDataReset {
                LocalDataResetRestartRequiredView(
                    terminateAction: terminateAction
                )
                .transition(.opacity)
            }
        }
    }
}

struct LocalDataResetRestartRequiredView: View {
    let terminateAction: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 48, weight: .semibold))
                .foregroundStyle(.green)
                .accessibilityHidden(true)

            Text(
                String(
                    localized: "settings.resetAll.restartRequired.title",
                    defaultValue: "Restart Required"
                )
            )
            .font(.title2.weight(.semibold))
            .multilineTextAlignment(.center)

            Text(message)
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)

            #if os(macOS)
            Button {
                terminateAction()
            } label: {
                Label(
                    String(
                        localized: "settings.resetAll.restartRequired.quit",
                        defaultValue: "Quit CypherAir"
                    ),
                    systemImage: "power"
                )
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            #endif
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.regularMaterial)
        .accessibilityIdentifier("settings.resetAll.restartRequired")
    }

    private var message: String {
        #if os(macOS)
        String(
            localized: "settings.resetAll.restartRequired.message.mac",
            defaultValue: "All local CypherAir data was deleted and verified. Quit and reopen CypherAir to complete a clean restart."
        )
        #else
        String(
            localized: "settings.resetAll.restartRequired.message",
            defaultValue: "All local CypherAir data was deleted and verified. Close CypherAir from the app switcher, then open it again to complete a clean restart."
        )
        #endif
    }
}

private struct LocalDataResetRestartCoordinatorKey: EnvironmentKey {
    static let defaultValue: LocalDataResetRestartCoordinator? = nil
}

extension EnvironmentValues {
    var localDataResetRestartCoordinator: LocalDataResetRestartCoordinator? {
        get { self[LocalDataResetRestartCoordinatorKey.self] }
        set { self[LocalDataResetRestartCoordinatorKey.self] = newValue }
    }
}
