import SwiftUI

@MainActor
struct TutorialShellDefinitionsBuilder {
    let store: TutorialSessionStore
    let sizeClass: UserInterfaceSizeClass?

    func definitions() -> [AppShellTabDefinition] {
        AppShellTab.allCases.map { tab in
            AppShellTabDefinition(tab: tab, content: root(for: tab))
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
                    definitionTab: tab
                )
            )
        }
    }
}
