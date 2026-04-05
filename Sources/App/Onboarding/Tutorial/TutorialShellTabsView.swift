import SwiftUI

@MainActor
struct TutorialShellTabsView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore

    @Binding var selectedTab: AppShellTab
    let sizeClass: UserInterfaceSizeClass?

    var body: some View {
        #if os(macOS)
        AnyView(macOSLayout)
        #else
        AnyView(iOSLayout)
        #endif
    }

    private var currentGuidance: TutorialGuidance? {
        if tutorialStore.activeModal != nil {
            return nil
        }
        if let activeTask = tutorialStore.session.activeTask,
           tutorialStore.isCompleted(activeTask) {
            return nil
        }

        return TutorialGuidanceResolver().guidance(
            session: tutorialStore.session,
            navigation: tutorialStore.navigation,
            sizeClass: sizeClass,
            selectedTab: selectedTab
        )
    }

    private var iOSLayout: some View {
        SharedIOSTabShellView(
            selectedTab: $selectedTab,
            definitions: TutorialShellDefinitionsBuilder(
                store: tutorialStore,
                sizeClass: sizeClass
            ).definitions()
        )
    }

    #if os(macOS)
    private var macOSLayout: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            tabRoot(for: selectedTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .inspector(isPresented: inspectorBinding) {
            if let currentGuidance {
                guidanceInspector(currentGuidance)
                    .inspectorColumnWidth(min: 260, ideal: 300, max: 360)
            }
        }
    }
    #endif

    #if os(macOS)
    private var sidebar: some View {
        List(selection: $selectedTab) {
            Section {
                sidebarSelectionRow(.home)
                sidebarSelectionRow(.keys)
                sidebarSelectionRow(.contacts)
                sidebarSelectionRow(.settings)
            }

            Section(String(localized: "tab.section.tools", defaultValue: "Tools")) {
                sidebarSelectionRow(.encrypt)
                sidebarSelectionRow(.decrypt)
                sidebarSelectionRow(.sign)
                sidebarSelectionRow(.verify)
            }
        }
        .frame(minWidth: 220, idealWidth: 240, maxWidth: 260)
    }
    #endif

    #if os(macOS)
    private func sidebarSelectionRow(_ tab: AppShellTab) -> some View {
        Label(
            AppShellComposition.title(for: tab),
            systemImage: AppShellComposition.systemImage(for: tab)
        )
        .tag(tab)
        .accessibilityIdentifier("tutorial.sidebar.\(tab.rawValue)")
    }

    private func tabRoot(for tab: AppShellTab) -> AnyView {
        TutorialShellDefinitionsBuilder(
            store: tutorialStore,
            sizeClass: sizeClass
        ).definitions().first(where: { $0.tab == tab })?.content ?? AnyView(EmptyView())
    }
    #endif
    private func guidanceCard(_ guidance: TutorialGuidance) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(
                    String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                    systemImage: "testtube.2"
                )
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)

                Spacer()

                Button(String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial")) {
                    tutorialStore.returnToOverview()
                }
                .buttonStyle(.bordered)
            }

            Text(guidance.title)
                .font(.headline)
            Text(guidance.body)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: sizeClass == .compact ? .infinity : 280, alignment: .leading)
        .padding(16)
        .tutorialCardChrome(.overlay)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    #if os(macOS)
    private var inspectorBinding: Binding<Bool> {
        Binding(
            get: { tutorialStore.isInspectorPresented && currentGuidance != nil },
            set: { tutorialStore.setInspectorPresented($0) }
        )
    }

    private func guidanceInspector(_ guidance: TutorialGuidance) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.caption.weight(.semibold))
            .foregroundStyle(.orange)

            Text(guidance.title)
                .font(.headline)

            Text(guidance.body)
                .font(.callout)
                .foregroundStyle(.secondary)

            Spacer(minLength: 0)
        }
        .padding(20)
    }
    #endif

    private func compactGuidanceBanner(_ guidance: TutorialGuidance) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(
                String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
                systemImage: "testtube.2"
            )
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.orange)

            Text(guidance.title)
                .font(.subheadline.weight(.semibold))

            Text(guidance.body)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .tutorialBannerChrome()
    }

    private var compactReturnBar: some View {
        HStack {
            Button {
                tutorialStore.returnToOverview()
            } label: {
                Label(
                    String(localized: "guidedTutorial.return", defaultValue: "Return to Tutorial"),
                    systemImage: "chevron.left"
                )
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
                .minimumScaleFactor(0.85)
            }
            .buttonStyle(.plain)

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.bar)
    }
}
