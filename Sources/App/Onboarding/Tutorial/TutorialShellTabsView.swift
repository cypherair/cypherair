import SwiftUI

@MainActor
struct TutorialShellTabsView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    @Binding var selectedTab: AppShellTab
    let sizeClass: UserInterfaceSizeClass?

    var body: some View {
        #if os(macOS)
        macOSLayout
        #else
        iOSLayout
        #endif
    }

    private var currentGuidance: TutorialGuidancePayload? {
        if tutorialStore.activeModal != nil {
            return nil
        }
        guard tutorialStore.currentModule != nil else { return nil }

        let guidance = TutorialGuidanceResolver().guidance(
            session: tutorialStore.session,
            navigation: tutorialStore.navigation,
            sizeClass: sizeClass,
            selectedTab: selectedTab
        )
        return guidance
    }

    private var iOSLayout: some View {
        Group {
            if sizeClass == .regular {
                HStack(spacing: 0) {
                    SharedIOSTabShellView(
                        selectedTab: $selectedTab,
                        definitions: TutorialShellDefinitionsBuilder(
                            store: tutorialStore,
                            sizeClass: sizeClass
                        ).definitions()
                    )

                    if let currentGuidance {
                        guidanceRail(currentGuidance)
                            .frame(width: 300)
                            .background(.background)
                    }
                }
            } else {
                SharedIOSTabShellView(
                    selectedTab: $selectedTab,
                    definitions: TutorialShellDefinitionsBuilder(
                        store: tutorialStore,
                        sizeClass: sizeClass
                    ).definitions()
                )
            }
        }
    }

    #if os(macOS)
    private var macOSLayout: some View {
        HStack(spacing: 0) {
            moduleNavigator
                .frame(minWidth: 240, idealWidth: 260, maxWidth: 280)

            Divider()

            ZStack(alignment: .topTrailing) {
                tabRoot(for: selectedTab)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                if !tutorialStore.isInspectorPresented,
                   currentGuidance != nil {
                    Button(String(localized: "guidedTutorial.showGuidance", defaultValue: "Show Guidance")) {
                        tutorialStore.setInspectorPresented(true)
                    }
                    .buttonStyle(.bordered)
                    .padding(16)
                }
            }

            if tutorialStore.isInspectorPresented,
               let currentGuidance {
                Divider()
                guidanceRail(currentGuidance)
                    .frame(minWidth: 280, idealWidth: 300, maxWidth: 340)
                    .background(.background)
            }
        }
    }
    #endif

    #if os(macOS)
    private var moduleNavigator: some View {
        List {
            Section {
                ForEach(TutorialModuleID.allCases) { module in
                    Button {
                        Task {
                            await tutorialStore.openModule(module)
                        }
                    } label: {
                        HStack(alignment: .top, spacing: 10) {
                            completionIndicator(for: module)

                            VStack(alignment: .leading, spacing: 4) {
                                Text(module.title)
                                    .font(.headline)
                                if let location = module.realAppLocation {
                                    Text(location)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }

                            Spacer()
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(!tutorialStore.canOpen(module))
                    .accessibilityIdentifier(module.launchControlIdentifier)
                }
            } header: {
                Text(String(localized: "guidedTutorial.modules", defaultValue: "Tutorial Modules"))
            }
        }
        .listStyle(.sidebar)
    }
    #endif

    #if os(macOS)
    private func tabRoot(for tab: AppShellTab) -> AnyView {
        TutorialShellDefinitionsBuilder(
            store: tutorialStore,
            sizeClass: sizeClass
        ).definitions().first(where: { $0.tab == tab })?.content ?? AnyView(EmptyView())
    }
    #endif

    private func guidanceRail(_ guidance: TutorialGuidancePayload) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Tutorial Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.caption.weight(.bold))
            .foregroundStyle(.orange)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Color.orange.opacity(0.14), in: Capsule())
            .overlay {
                Capsule()
                    .strokeBorder(Color.orange.opacity(0.35), lineWidth: 1)
            }

            Text(guidance.title)
                .font(.headline)

            if let location = guidance.realAppLocation {
                Text(location)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }

            Text(guidance.body)
                .font(.callout)
                .foregroundStyle(.secondary)

            Button(String(localized: "guidedTutorial.returnToOverview", defaultValue: "Return to Tutorial Overview")) {
                tutorialStore.returnToOverview()
            }
            .buttonStyle(.bordered)
            .tint(.orange)

            Spacer(minLength: 0)
        }
        .padding(20)
    }

    private func completionIndicator(for module: TutorialModuleID) -> some View {
        Group {
            if tutorialStore.isCompleted(module) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            } else if tutorialStore.canOpen(module) {
                Image(systemName: "circle")
                    .foregroundStyle(.secondary)
            } else {
                Image(systemName: "lock.fill")
                    .foregroundStyle(.secondary)
            }
        }
    }
}
