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
        let factory = store.configurationFactory
        let routeResolver = routeResolver(for: tab)
        let pathBinding = store.routePathBinding(for: tab)
        switch (store.session.activeTask, tab) {
        case (.composeAndEncryptMessage?, .encrypt) where sizeClass != .compact:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    TutorialTaskHostView(task: .composeAndEncryptMessage) {
                        EncryptView(configuration: factory.encryptConfiguration())
                    }
                }
            }
        case (.parseRecipients?, .decrypt) where sizeClass != .compact:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    TutorialTaskHostView(task: .parseRecipients) {
                        DecryptView(configuration: factory.decryptConfiguration(for: .parseRecipients))
                    }
                }
            }
        case (.decryptMessage?, .decrypt) where sizeClass != .compact:
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    TutorialTaskHostView(task: .decryptMessage) {
                        DecryptView(configuration: factory.decryptConfiguration(for: .decryptMessage))
                    }
                }
            }
        case (.enableHighSecurity?, .settings):
            return tutorialHostedRoot(resolver: routeResolver, path: pathBinding, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    TutorialSettingsTaskView()
                }
            }
        default:
            return defaultRoot(for: tab, resolver: routeResolver, path: pathBinding)
        }
    }

    private func defaultRoot(
        for tab: AppShellTab,
        resolver: AppRouteDestinationResolver,
        path: Binding<[AppRoute]>
    ) -> AnyView {
        switch tab {
        case .home:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    HomeView()
                }
            }
        case .keys:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    MyKeysView()
                }
            }
        case .contacts:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    ContactsView()
                }
            }
        case .settings:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    SettingsView(configuration: store.configurationFactory.settingsConfiguration())
                }
            }
        case .encrypt:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    EncryptView()
                }
            }
        case .decrypt:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    DecryptView()
                }
            }
        case .sign:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    SignView()
                }
            }
        case .verify:
            return tutorialHostedRoot(resolver: resolver, path: path, tab: tab) {
                TutorialSurfaceView(tab: tab, route: nil) {
                    VerifyView()
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
