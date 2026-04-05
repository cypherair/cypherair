import SwiftUI

struct TutorialInlineHeaderContext {
    let onReturn: @MainActor () -> Void
    let sandboxLabel: String
    let taskTitle: String
    let guidanceBody: String
}

private struct TutorialInlineHeaderContextKey: EnvironmentKey {
    static let defaultValue: TutorialInlineHeaderContext? = nil
}

extension EnvironmentValues {
    var tutorialInlineHeaderContext: TutorialInlineHeaderContext? {
        get { self[TutorialInlineHeaderContextKey.self] }
        set { self[TutorialInlineHeaderContextKey.self] = newValue }
    }
}

struct TutorialInlineHeaderView: View {
    let context: TutorialInlineHeaderContext

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Button {
                    context.onReturn()
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

                Spacer(minLength: 12)

                Text(context.sandboxLabel)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Text(context.taskTitle)
                .font(.headline)

            Text(context.guidanceBody)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("tutorial.inlineHeader")
    }
}

@MainActor
struct TutorialSurfaceView<Content: View>: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(\.horizontalSizeClass) private var sizeClass

    let tab: AppShellTab
    let route: AppRoute?
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .environment(\.tutorialInlineHeaderContext, inlineHeaderContext)
            .onAppear {
                tutorialStore.noteVisibleSurface(tab: tab, route: route)
            }
            .onChange(of: route) { _, newRoute in
                tutorialStore.noteVisibleSurface(tab: tab, route: newRoute)
            }
            .onChange(of: tutorialStore.selectedTab) { _, newTab in
                if newTab == tab {
                    tutorialStore.noteVisibleSurface(tab: tab, route: route)
                }
            }
    }

    private var inlineHeaderContext: TutorialInlineHeaderContext? {
        guard tutorialStore.selectedTab == tab else { return nil }
        guard tutorialStore.activeModal == nil else { return nil }
        guard let activeTask = tutorialStore.session.activeTask else { return nil }
        guard !tutorialStore.isCompleted(activeTask) else { return nil }
        guard let guidance = TutorialGuidanceResolver().guidance(
            session: tutorialStore.session,
            navigation: tutorialStore.navigation,
            sizeClass: sizeClass,
            selectedTab: tutorialStore.selectedTab
        ) else {
            return nil
        }

        return TutorialInlineHeaderContext(
            onReturn: { tutorialStore.returnToOverview() },
            sandboxLabel: String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Sandbox"),
            taskTitle: guidance.title,
            guidanceBody: guidance.body
        )
    }
}

@MainActor
struct TutorialSettingsTaskView: View {
    @Environment(TutorialSessionStore.self) private var tutorialStore
    @Environment(AppConfiguration.self) private var config

    var body: some View {
        TutorialTaskHostView(task: .enableHighSecurity) {
            SettingsView(configuration: tutorialStore.configurationFactory.settingsConfiguration())
                .onChange(of: config.authMode) { _, newMode in
                    if newMode == .highSecurity {
                        tutorialStore.noteHighSecurityEnabled(newMode)
                    }
                }
        }
    }
}

struct TutorialDisabledSettingView: View {
    @Environment(\.tutorialInlineHeaderContext) private var tutorialInlineHeaderContext

    let title: String
    let message: String
    let systemImage: String

    var body: some View {
        Group {
            if let tutorialInlineHeaderContext {
                ScrollView {
                    VStack(spacing: 20) {
                        TutorialInlineHeaderView(context: tutorialInlineHeaderContext)
                        unavailableContent
                    }
                    .padding()
                }
            } else {
                unavailableContent
            }
        }
        .navigationTitle(title)
    }

    private var unavailableContent: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(message)
        }
    }
}
