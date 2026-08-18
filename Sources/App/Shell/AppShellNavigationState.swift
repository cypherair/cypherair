import SwiftUI

/// Where the app's shell is: which tab is forward, and what is stacked on each.
///
/// Held above the shell rather than inside it, because the things that move it
/// are outside it — a keyboard command, and a document the system asked the app
/// to open, which has to arrive at the screen that handles it rather than
/// wherever the reader happened to be.
@MainActor
@Observable
final class AppShellNavigationState {
    var selectedTab: AppShellTab = .home
    var pathsByTab: [AppShellTab: [AppRoute]] = Dictionary(
        uniqueKeysWithValues: AppShellTab.allCases.map { ($0, []) }
    )
    #if os(macOS)
    var activePresentation: MacPresentation?
    var columnVisibility: NavigationSplitViewVisibility = .automatic
    var preferredCompactColumn: NavigationSplitViewColumn = .detail
    #endif

    func path(for tab: AppShellTab) -> [AppRoute] {
        pathsByTab[tab] ?? []
    }

    func setPath(_ path: [AppRoute], for tab: AppShellTab) {
        pathsByTab[tab] = path
    }

    func push(_ route: AppRoute, for tab: AppShellTab) {
        var path = path(for: tab)
        path.append(route)
        setPath(path, for: tab)
    }

    /// Show `route` on `tab` as the only thing stacked there, and bring the tab
    /// forward.
    ///
    /// Tools are reached through Home on every platform: the tool tabs are
    /// hidden at compact width, so pushing onto Home is the one destination that
    /// exists everywhere, and it is the same screen the Home buttons open.
    func present(_ route: AppRoute, on tab: AppShellTab) {
        selectedTab = tab
        setPath([route], for: tab)
    }

    /// The stack binding for one tab's navigation host.
    ///
    /// Writes from a tab that is no longer forward are ignored: an outgoing
    /// stack clears its path while it tears down, which would otherwise erase
    /// what was stored for it.
    func pathBinding(for tab: AppShellTab) -> Binding<[AppRoute]> {
        Binding(
            get: { self.path(for: tab) },
            set: { newPath in
                guard self.selectedTab == tab else { return }
                self.setPath(newPath, for: tab)
            }
        )
    }
}
