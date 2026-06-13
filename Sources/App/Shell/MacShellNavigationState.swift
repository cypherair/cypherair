import SwiftUI

@MainActor
@Observable
final class MacShellNavigationState {
    var selectedTab: AppShellTab = .home
    var pathsByTab: [AppShellTab: [AppRoute]] = Dictionary(
        uniqueKeysWithValues: AppShellTab.allCases.map { ($0, []) }
    )
    var activePresentation: MacPresentation?
    var visibleRouteByTab: [AppShellTab: AppRoute?] = Dictionary(
        uniqueKeysWithValues: AppShellTab.allCases.map { ($0, nil) }
    )
    var columnVisibility: NavigationSplitViewVisibility = .automatic
    var preferredCompactColumn: NavigationSplitViewColumn = .detail

    func path(for tab: AppShellTab) -> [AppRoute] {
        pathsByTab[tab] ?? []
    }

    func setPath(_ path: [AppRoute], for tab: AppShellTab) {
        pathsByTab[tab] = path
        visibleRouteByTab[tab] = path.last
    }

    func push(_ route: AppRoute, for tab: AppShellTab) {
        var path = path(for: tab)
        path.append(route)
        setPath(path, for: tab)
    }
}
