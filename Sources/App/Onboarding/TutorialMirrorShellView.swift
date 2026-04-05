import SwiftUI

@MainActor
struct TutorialMirrorShellView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(\.horizontalSizeClass) private var sizeClass

    var body: some View {
        if let container = tutorialStore.container {
            TutorialShellTabsView(
                selectedTab: selectedTabBinding,
                routePath: routePathBinding,
                sizeClass: sizeClass
            )
            .environment(tutorialStore)
            .environment(container.config)
            .environment(container.keyManagement)
            .environment(container.contactService)
            .environment(container.encryptionService)
            .environment(container.decryptionService)
            .environment(container.signingService)
            .environment(container.qrService)
            .environment(container.selfTestService)
            .environment(container.authManager)
            .onAppear {
                tutorialStore.noteVisibleSurface(
                    tab: tutorialStore.selectedTab,
                    route: tutorialStore.routePath.last
                )
            }
            .sheet(item: activeModalBinding) { modal in
                switch modal {
                case .importConfirmation(let request):
                    ImportConfirmView(
                        keyInfo: request.keyInfo,
                        detectedProfile: request.profile,
                        onImportVerified: {
                            let action = request.onImportVerified
                            tutorialStore.dismissModal()
                            action()
                        },
                        onImportUnverified: request.allowsUnverifiedImport ? {
                            let action = request.onImportUnverified
                            tutorialStore.dismissModal()
                            action()
                        } : nil,
                        onCancel: {
                            let action = request.onCancel
                            tutorialStore.dismissModal()
                            action()
                        }
                    )
                case .authModeConfirmation(let request):
                    NavigationStack {
                        TutorialAuthModeConfirmationView(request: request)
                    }
                    #if os(macOS)
                    .frame(minWidth: 500, idealWidth: 540, minHeight: 360, idealHeight: 420)
                    #endif
                    #if canImport(UIKit)
                    .presentationDetents([.medium, .large])
                    #endif
                }
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
                    tutorialStore.dismissShell()
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

    private var routePathBinding: Binding<[AppRoute]> {
        Binding(
            get: { tutorialStore.routePath },
            set: { tutorialStore.setRoutePath($0) }
        )
    }

    private var activeModalBinding: Binding<TutorialModal?> {
        Binding(
            get: { tutorialStore.activeModal },
            set: { if $0 == nil { tutorialStore.dismissModal() } }
        )
    }
}
