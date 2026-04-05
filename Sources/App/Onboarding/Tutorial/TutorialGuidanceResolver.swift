import SwiftUI

struct TutorialGuidanceResolver {
    func guidance(
        session: TutorialSessionState,
        navigation: TutorialNavigationState,
        sizeClass: UserInterfaceSizeClass?,
        selectedTab: AppShellTab
    ) -> TutorialGuidance? {
        guard navigation.activeModal == nil else { return nil }
        guard let task = session.activeTask else { return nil }

        let visibleRoute = navigation.visibleSurface.route

        switch task {
        case .generateAliceKey:
            if selectedTab != .keys {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.keys", defaultValue: "Open the Keys tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.keys.entry", defaultValue: "Tap the real Generate Key entry to open the key form."),
                    target: .keysGenerateButton
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.keys.form", defaultValue: "Review the prefilled Alice identity and generate the key."),
                target: nil
            )

        case .importBobKey:
            if selectedTab != .contacts {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.contacts", defaultValue: "Open the Contacts tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.contacts.entry", defaultValue: "Tap Add Contact to import Bob's sandbox public key."),
                    target: .contactsAddButton
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.contacts.form", defaultValue: "Confirm Bob's key details and add the contact."),
                target: nil
            )

        case .composeAndEncryptMessage:
            if sizeClass == .compact {
                if selectedTab != .home {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.nav.homeEncrypt", defaultValue: "Open the Home tab to reach the Encrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.home.encrypt", defaultValue: "Use the real Encrypt shortcut to open the message form."),
                        target: .homeEncryptAction
                    )
                }
            } else if selectedTab != .encrypt {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.encrypt", defaultValue: "Open Encrypt from the Tools section to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.encrypt.form", defaultValue: "Bob is preselected. Review the draft and encrypt the message."),
                target: nil
            )

        case .parseRecipients:
            if sizeClass == .compact {
                if selectedTab != .home {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.nav.homeDecrypt", defaultValue: "Open the Home tab to reach the Decrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message."),
                        target: .homeDecryptAction
                    )
                }
            } else if selectedTab != .decrypt {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.decrypt", defaultValue: "Open Decrypt from the Tools section to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.decrypt.parse", defaultValue: "Check the recipients first. The task completes once the sandbox key matches."),
                target: nil
            )

        case .decryptMessage:
            if sizeClass == .compact {
                if selectedTab != .home {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.nav.homeDecrypt", defaultValue: "Open the Home tab to reach the Decrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return TutorialGuidance(
                        title: task.title,
                        body: String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message."),
                        target: .homeDecryptAction
                    )
                }
            } else if selectedTab != .decrypt {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.decrypt", defaultValue: "Open Decrypt from the Tools section to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.decrypt.form", defaultValue: "Decrypt the sandbox message and review the signature result."),
                target: nil
            )

        case .exportBackup:
            if selectedTab != .keys {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.keys", defaultValue: "Open the Keys tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil, let fingerprint = session.artifacts.aliceIdentity?.fingerprint {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.keys.alice", defaultValue: "Open Alice's key from My Keys to continue."),
                    target: .keyRow(fingerprint: fingerprint)
                )
            }
            if case .keyDetail(let fingerprint)? = visibleRoute,
               fingerprint == session.artifacts.aliceIdentity?.fingerprint {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.backup.entry", defaultValue: "Use the real Export Backup action from Alice's key detail page."),
                    target: .keyDetailBackupButton
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.backup.form", defaultValue: "Enter a passphrase and generate the sandbox backup."),
                target: nil
            )

        case .enableHighSecurity:
            if selectedTab != .settings {
                return TutorialGuidance(
                    title: task.title,
                    body: String(localized: "guidedTutorial.nav.settings", defaultValue: "Open the Settings tab to continue."),
                    target: nil
                )
            }
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.settings.auth", defaultValue: "Switch the authentication mode to High Security and confirm the warning."),
                target: .settingsAuthModePicker
            )

        case .understandSandbox:
            return TutorialGuidance(
                title: task.title,
                body: String(localized: "guidedTutorial.intro.body", defaultValue: "This walkthrough runs entirely in a sandbox. Your real keys, contacts, settings, files, and exports are never touched."),
                target: nil
            )
        }
    }
}
