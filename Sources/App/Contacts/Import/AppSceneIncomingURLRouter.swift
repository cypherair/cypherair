import Foundation

@MainActor
struct AppSceneIncomingURLRouter {
    let incomingURLImportCoordinator: IncomingURLImportCoordinator
    let tutorialStore: TutorialSessionStore
    let localDataResetRestartCoordinator: LocalDataResetRestartCoordinator

    func handle(_ url: URL) {
        guard !localDataResetRestartCoordinator.restartRequiredAfterLocalDataReset else { return }
        incomingURLImportCoordinator.handleIncomingURL(
            url,
            isTutorialPresentationActive: tutorialStore.isTutorialPresentationActive
        )
    }
}
