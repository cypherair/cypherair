import SwiftUI

/// The macOS sidebar's destinations: the app's four sections, then the four
/// tools.
enum MacSidebarItem: Hashable, CaseIterable {
    case tab(AppShellTab)
    case tool(AppTool)

    static var allCases: [MacSidebarItem] {
        AppShellTab.allCases.map(MacSidebarItem.tab) + AppTool.allCases.map(MacSidebarItem.tool)
    }

    var title: String {
        switch self {
        case .tab(let tab):
            tab.title
        case .tool(let tool):
            tool.title
        }
    }

    var systemImage: String {
        switch self {
        case .tab(let tab):
            tab.systemImage
        case .tool(let tool):
            tool.systemImage
        }
    }

    var identifier: String {
        switch self {
        case .tab(let tab):
            tab.rawValue
        case .tool(let tool):
            tool.rawValue
        }
    }
}

@MainActor
@Observable
final class MacShellNavigationState {
    var selection: MacSidebarItem = .tab(.home)
    var pathsByItem: [MacSidebarItem: [AppRoute]] = [:]
    var activePresentation: MacPresentation?
    var columnVisibility: NavigationSplitViewVisibility = .automatic
    var preferredCompactColumn: NavigationSplitViewColumn = .detail

    func path(for item: MacSidebarItem) -> [AppRoute] {
        pathsByItem[item] ?? []
    }

    func setPath(_ path: [AppRoute], for item: MacSidebarItem) {
        pathsByItem[item] = path
    }

    func push(_ route: AppRoute, for item: MacSidebarItem) {
        var path = path(for: item)
        path.append(route)
        setPath(path, for: item)
    }
}
