import SwiftUI

@MainActor
struct AppRouteDestinationResolver {
    let build: (AppRoute) -> AnyView

    func destination(for route: AppRoute) -> AnyView {
        build(route)
    }

    static let production = AppRouteDestinationResolver { route in
        AnyView(AppRouteDestinationView(route: route))
    }
}

struct AppRouteNavigator {
    let push: @MainActor (AppRoute) -> Void

    @MainActor
    func open(_ route: AppRoute) {
        push(route)
    }
}

private struct AppRouteNavigatorKey: EnvironmentKey {
    static let defaultValue = AppRouteNavigator { _ in }
}

extension EnvironmentValues {
    var appRouteNavigator: AppRouteNavigator {
        get { self[AppRouteNavigatorKey.self] }
        set { self[AppRouteNavigatorKey.self] = newValue }
    }
}

struct AppRouteHost<Root: View>: View {
    struct MacSheetSizing {
        let minWidth: CGFloat
        let idealWidth: CGFloat
        let minHeight: CGFloat
        let idealHeight: CGFloat

        static var routedModal: MacSheetSizing {
            MacSheetSizing(
                minWidth: 640,
                idealWidth: 720,
                minHeight: 500,
                idealHeight: 560
            )
        }
    }

    let resolver: AppRouteDestinationResolver
    private let externalPath: Binding<[AppRoute]>?
    private let macSheetSizing: MacSheetSizing?
    @ViewBuilder let root: () -> Root
    @State private var path: [AppRoute] = []

    init(
        resolver: AppRouteDestinationResolver,
        path: Binding<[AppRoute]>? = nil,
        macSheetSizing: MacSheetSizing? = nil,
        @ViewBuilder root: @escaping () -> Root
    ) {
        self.resolver = resolver
        self.externalPath = path
        self.macSheetSizing = macSheetSizing
        self.root = root
    }

    var body: some View {
        let pathBinding = externalPath ?? $path

        return NavigationStack(path: pathBinding) {
            root()
                .navigationDestination(for: AppRoute.self) { route in
                    resolver.destination(for: route)
                }
        }
        #if os(macOS)
        .frame(
            minWidth: macSheetSizing?.minWidth,
            idealWidth: macSheetSizing?.idealWidth,
            minHeight: macSheetSizing?.minHeight,
            idealHeight: macSheetSizing?.idealHeight
        )
        #endif
        .environment(
            \.appRouteNavigator,
            AppRouteNavigator { route in
                pathBinding.wrappedValue.append(route)
            }
        )
    }
}
