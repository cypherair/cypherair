import SwiftUI

struct TutorialInlineHeaderContext {
    let onReturn: @MainActor () -> Void
    let sandboxLabel: String
    let taskTitle: String
    let guidanceBody: String
}

struct TutorialInlineHeaderView: View {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    let context: TutorialInlineHeaderContext

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            topRow

            Text(context.taskTitle)
                .font(.headline)

            Text(context.guidanceBody)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(headerBackgroundColor, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(Color.orange.opacity(0.25), lineWidth: 1.5)
        }
        .shadow(color: .black.opacity(0.06), radius: 10, y: 4)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("tutorial.inlineHeader")
    }

    @ViewBuilder
    private var topRow: some View {
        if dynamicTypeSize.isAccessibilitySize {
            VStack(alignment: .leading, spacing: 10) {
                returnButton
                sandboxBadge
            }
        } else {
            HStack(alignment: .center, spacing: 12) {
                returnButton
                Spacer(minLength: 12)
                sandboxBadge
            }
        }
    }

    private var returnButton: some View {
        Button {
            context.onReturn()
        } label: {
            Label(
                String(localized: "guidedTutorial.returnToOverview", defaultValue: "Return to Tutorial Overview"),
                systemImage: "chevron.left.circle.fill"
            )
            .font(.subheadline.weight(.semibold))
            .padding(.horizontal, 12)
            .frame(minHeight: 44)
        }
        .buttonStyle(.bordered)
        .tint(.orange)
        .accessibilityIdentifier(TutorialAutomationContract.returnToOverviewIdentifier)
        .accessibilityHint(
            String(localized: "guidedTutorial.returnToOverview.hint", defaultValue: "Return to the guided tutorial overview.")
        )
    }

    private var sandboxBadge: some View {
        Label(context.sandboxLabel, systemImage: "testtube.2")
            .font(.caption.weight(.bold))
            .foregroundStyle(.orange)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Color.orange.opacity(0.14), in: Capsule())
            .overlay {
                Capsule()
                    .strokeBorder(Color.orange.opacity(0.35), lineWidth: 1)
            }
    }

    private var headerBackgroundColor: Color {
        #if canImport(UIKit)
        Color(uiColor: .systemBackground)
        #elseif canImport(AppKit)
        Color(nsColor: .windowBackgroundColor)
        #else
        .clear
        #endif
    }
}

private struct TutorialInlineHeaderHeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}

private struct TutorialInlineHeaderHostModifier: ViewModifier {
    let context: TutorialInlineHeaderContext?

    @State private var headerHeight: CGFloat = 0
    @State private var scrollOffset: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .contentMargins(.top, topInset, for: .scrollContent)
            .onScrollGeometryChange(
                for: CGFloat.self,
                of: { geometry in
                    geometry.contentOffset.y + geometry.contentInsets.top
                },
                action: { _, newValue in
                    scrollOffset = newValue
                }
            )
            .overlay(alignment: .top) {
                if let context {
                    TutorialInlineHeaderView(context: context)
                        .background {
                            GeometryReader { proxy in
                                Color.clear.preference(
                                    key: TutorialInlineHeaderHeightKey.self,
                                    value: proxy.size.height
                                )
                            }
                        }
                        .padding(.horizontal, 16)
                        .padding(.top, 12)
                        .offset(y: -scrollOffset)
                }
            }
            .onPreferenceChange(TutorialInlineHeaderHeightKey.self) { newValue in
                headerHeight = newValue
            }
    }

    private var topInset: CGFloat {
        guard context != nil else { return 0 }
        return headerHeight > 0 ? headerHeight + 24 : 160
    }
}

extension View {
    fileprivate func tutorialInlineHeaderHost(
        context: TutorialInlineHeaderContext?
    ) -> some View {
        modifier(TutorialInlineHeaderHostModifier(context: context))
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
            #if canImport(UIKit)
            .tutorialInlineHeaderHost(context: inlineHeaderContext)
            #endif
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
            sandboxLabel: String(localized: "guidedTutorial.sandbox.badge", defaultValue: "Tutorial Sandbox"),
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
        TutorialTaskHostView(module: .enableHighSecurity) {
            SettingsView(configuration: tutorialStore.configurationFactory.settingsConfiguration())
                .onChange(of: config.authModeIfUnlocked) { _, newMode in
                    if let newMode, newMode == .highSecurity {
                        tutorialStore.noteHighSecurityEnabled(newMode)
                    }
                }
        }
    }
}

struct TutorialDisabledSettingView: View {
    let title: String
    let message: String
    let systemImage: String

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            Text(message)
        }
        .navigationTitle(title)
    }
}
