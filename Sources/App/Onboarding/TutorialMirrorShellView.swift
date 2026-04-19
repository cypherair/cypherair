import SwiftUI

@MainActor
struct TutorialMirrorShellView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(\.horizontalSizeClass) private var sizeClass

    var body: some View {
        if let container = tutorialStore.container {
            TutorialShellTabsView(
                selectedTab: selectedTabBinding,
                sizeClass: sizeClass
            )
            .environment(tutorialStore)
            .environment(container.config)
            .environment(container.keyManagement)
            .environment(container.contactService)
            .environment(container.encryptionService)
            .environment(container.decryptionService)
            .environment(container.signingService)
            .environment(container.certificateSignatureService)
            .environment(container.qrService)
            .environment(container.selfTestService)
            .environment(container.authManager)
            .screenReady(tutorialStore.currentModule?.readyMarker ?? "tutorial.workspace.ready")
            .onAppear {
                tutorialStore.noteVisibleSurface(
                    tab: tutorialStore.selectedTab,
                    route: tutorialStore.routePath.last
                )
            }
        } else {
            ContentUnavailableView {
                Label(
                    String(localized: "guidedTutorial.title", defaultValue: "Guided Tutorial"),
                    systemImage: "testtube.2"
                )
            } description: {
                Text(tutorialStore.errorMessage ?? String(localized: "guidedTutorial.error.defaults", defaultValue: "Could not prepare the sandbox tutorial environment."))
            } actions: {
                Button(String(localized: "common.done", defaultValue: "Done")) {
                    tutorialStore.returnToOverview()
                }
            }
        }
    }

    private var selectedTabBinding: Binding<AppShellTab> {
        Binding(
            get: { tutorialStore.selectedTab },
            set: { tutorialStore.selectTab($0) }
        )
    }
}
