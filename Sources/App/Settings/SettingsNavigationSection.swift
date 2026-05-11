import SwiftUI

struct SettingsNavigationSection: View {
    let model: SettingsScreenModel

    var body: some View {
        Section {
            NavigationLink(value: AppRoute.selfTest) {
                Label(
                    String(localized: "settings.selfTest", defaultValue: "Self-Test"),
                    systemImage: "checkmark.circle"
                )
            }
            .accessibilityIdentifier("settings.selfTest")

            Button {
                model.presentOnboarding()
            } label: {
                SettingsActionRow(
                    title: String(localized: "settings.viewOnboarding", defaultValue: "View Onboarding"),
                    systemImage: "book"
                )
            }
            .accessibilityIdentifier("settings.onboarding")
            .buttonStyle(.plain)
            .disabled(!model.configuration.isOnboardingEntryEnabled)

            Button {
                model.presentTutorial()
            } label: {
                SettingsActionRow(
                    title: model.guidedTutorialEntryTitle,
                    systemImage: "testtube.2"
                )
            }
            .accessibilityIdentifier("settings.tutorial")
            .buttonStyle(.plain)
            .disabled(
                !model.configuration.isGuidedTutorialEntryEnabled
                    || !model.isProtectedOrdinarySettingsEditable
            )

            NavigationLink(value: AppRoute.license) {
                Label(
                    String(localized: "settings.license", defaultValue: "Licenses"),
                    systemImage: "doc.text"
                )
            }
            .accessibilityIdentifier("settings.license")

            NavigationLink(value: AppRoute.about) {
                Label(
                    String(localized: "settings.about", defaultValue: "About"),
                    systemImage: "info.circle"
                )
            }
            .accessibilityIdentifier("settings.about")
        } footer: {
            if let navigationEducationFooter = model.configuration.navigationEducationFooter {
                Text(navigationEducationFooter)
            }
        }
    }
}

private struct SettingsActionRow: View {
    let title: String
    let systemImage: String

    var body: some View {
        HStack {
            Label(title, systemImage: systemImage)
            Spacer()
            Image(systemName: "chevron.right")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }
}
