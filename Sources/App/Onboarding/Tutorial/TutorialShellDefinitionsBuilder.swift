import SwiftUI

@MainActor
struct TutorialShellDefinitionsBuilder {
    let store: TutorialSessionStore
    let sizeClass: UserInterfaceSizeClass?

    func definitions() -> [AppShellTabDefinition] {
        AppShellTab.allCases.map { tab in
            AppShellComposition.definition(
                for: tab,
                content: root(for: tab)
            )
        }
    }

    private func root(for tab: AppShellTab) -> AnyView {
        if let blockedSurface = store.blocklist.blockedRoot(for: tab) {
            return tutorialHostedRoot(resolver: routeResolver(for: tab), path: store.routePathBinding(for: tab), tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    TutorialBlockedRouteView(surface: blockedSurface)
                }
            }
        }

        let routeResolver = routeResolver(for: tab)
        let pathBinding = store.routePathBinding(for: tab)

        switch tab {
        case .home:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    HomeView()
                }
            }
        case .keys:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    MyKeysView()
                }
            }
        case .contacts:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    ContactsView()
                }
            }
        case .settings:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    TutorialSettingsTaskView()
                }
            }
        case .encrypt:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    EncryptView(configuration: store.configurationFactory.encryptConfiguration(isActiveModule: store.currentModule == .encryptDemoMessage))
                }
            }
        case .decrypt:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    DecryptView(configuration: store.configurationFactory.decryptConfiguration(isActiveModule: store.currentModule == .decryptAndVerify))
                }
            }
        case .sign, .verify:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    TutorialBlockedRouteView(
                        surface: store.blocklist.blockedRoot(for: tab) ?? TutorialBlockedSurface(
                            title: String(localized: "guidedTutorial.blocked.title", defaultValue: "Unavailable in Tutorial"),
                            message: String(localized: "guidedTutorial.blocked.body", defaultValue: "This action is unavailable inside the guided tutorial sandbox."),
                            systemImage: "hand.raised"
                        )
                    )
                }
            }
        }
    }

    private func tutorialHostedRoot<Root: View>(
        resolver: AppRouteDestinationResolver,
        path: Binding<[AppRoute]>,
        tab: AppShellTab,
        @ViewBuilder root: @escaping () -> Root
    ) -> AnyView {
        AnyView(
            AppRouteHost(resolver: resolver, path: path) {
                root()
            }
            .tutorialSandboxChrome(tab: tab, sizeClass: sizeClass)
        )
    }

    private func routeResolver(for tab: AppShellTab) -> AppRouteDestinationResolver {
        AppRouteDestinationResolver { route in
            AnyView(
                TutorialRouteDestinationView(
                    route: route,
                    definitionTab: tab,
                    sizeClass: sizeClass
                )
            )
        }
    }
}
