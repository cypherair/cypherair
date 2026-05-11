import SwiftUI

struct SettingsProtectedClipboardNoticeRow: View {
    let model: SettingsScreenModel

    var body: some View {
        switch model.protectedSettingsSectionState {
        case .loading:
            HStack {
                ProgressView()
                Text(
                    String(
                        localized: "protectedSettings.loading",
                        defaultValue: "Loading preferences..."
                    )
                )
                .foregroundStyle(.secondary)
            }
        case .locked:
            LabeledContent {
                Button(
                    String(
                        localized: "protectedSettings.unlock",
                        defaultValue: "Unlock"
                    )
                ) {
                    model.requestProtectedSettingsUnlock()
                }
            } label: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(
                        String(
                            localized: "settings.clipboardNotice",
                            defaultValue: "Clipboard Safety Notice"
                        )
                    )
                    Text(
                        String(
                            localized: "protectedSettings.locked.message",
                            defaultValue: "Authenticate to view and change this preference."
                        )
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
        case .available:
            Toggle(
                String(
                    localized: "settings.clipboardNotice",
                    defaultValue: "Clipboard Safety Notice"
                ),
                isOn: Binding(
                    get: { model.isProtectedClipboardNoticeEnabled },
                    set: { model.setProtectedClipboardNoticeEnabled($0) }
                )
            )
            .accessibilityIdentifier("settings.clipboardNotice")
        case .recoveryNeeded:
            VStack(alignment: .leading, spacing: 10) {
                Text(
                    String(
                        localized: "protectedSettings.recovery.message",
                        defaultValue: "Preferences could not be opened safely and may need recovery."
                    )
                )
                .foregroundStyle(.secondary)

                Button(
                    String(
                        localized: "protectedSettings.reset.action",
                        defaultValue: "Reset Preferences"
                    ),
                    role: .destructive
                ) {
                    model.requestProtectedSettingsReset()
                }
            }
        case .pendingRetryRequired:
            Text(
                String(
                    localized: "protectedSettings.pending.message",
                    defaultValue: "Preferences have pending recovery work and are temporarily unavailable."
                )
            )
            .foregroundStyle(.secondary)
            Button(
                String(
                    localized: "protectedSettings.retry.action",
                    defaultValue: "Retry Recovery"
                )
            ) {
                model.requestProtectedSettingsRetry()
            }
        case .pendingResetRequired:
            VStack(alignment: .leading, spacing: 10) {
                Text(
                    String(
                        localized: "protectedSettings.pendingReset.message",
                        defaultValue: "Preferences have unfinished setup work that cannot continue automatically."
                    )
                )
                .foregroundStyle(.secondary)

                Button(
                    String(
                        localized: "protectedSettings.reset.action",
                        defaultValue: "Reset Preferences"
                    ),
                    role: .destructive
                ) {
                    model.requestProtectedSettingsReset()
                }
            }
        case .frameworkUnavailable:
            Text(
                String(
                    localized: "protectedSettings.frameworkUnavailable.message",
                    defaultValue: "Preferences are unavailable because the protected-data framework is not ready."
                )
            )
            .foregroundStyle(.secondary)
        case .settingsSceneProxy:
            VStack(alignment: .leading, spacing: 10) {
                Text(
                    String(
                        localized: "protectedSettings.proxy.message",
                        defaultValue: "Clipboard Safety Notice can only be viewed and changed from the main window."
                    )
                )
                .foregroundStyle(.secondary)

                Button(
                    String(
                        localized: "protectedSettings.proxy.openMainWindow",
                        defaultValue: "Open Main Window"
                    )
                ) {
                    model.openProtectedSettingsInMainWindow()
                }
            }
        case .tutorialSandbox:
            Text(
                String(
                    localized: "protectedSettings.tutorial.message",
                    defaultValue: "The tutorial sandbox never reads or writes your real Clipboard Safety Notice."
                )
            )
            .foregroundStyle(.secondary)
        }
    }
}
