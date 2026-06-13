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
        if path.count < (pathsByTab[tab]?.count ?? 0) {
            // FB23066215 (issue #499): a pop is about to tear down the top screen. If it
            // holds a focused text field, resign the field editor *before* SwiftUI sees
            // the shorter path, so the backing NSTextField deallocates here rather than in
            // the deferred display-cycle flush that faults under MIE v2 on macOS 27. This
            // setter is the only provably pre-pop hook (the system Back button drives it).
            MIEWeakTeardownMitigation.resignActiveTextEditing()
        }
        pathsByTab[tab] = path
        visibleRouteByTab[tab] = path.last
    }

    func push(_ route: AppRoute, for tab: AppShellTab) {
        var path = path(for: tab)
        path.append(route)
        setPath(path, for: tab)
    }
}
