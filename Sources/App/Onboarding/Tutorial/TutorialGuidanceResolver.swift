import SwiftUI

struct TutorialGuidanceResolver {
    func guidance(
        session: TutorialSessionState,
        navigation: TutorialNavigationState,
        sizeClass: UserInterfaceSizeClass?,
        selectedTab: AppShellTab
    ) -> TutorialGuidancePayload? {
        guard navigation.activeModal == nil else { return nil }
        guard let module = session.activeModule else { return nil }
        if session.moduleStates[module]?.isCompleted == true {
            return completionPayload(module)
        }

        let visibleRoute = navigation.visibleSurface.route

        switch module {
        case .createDemoIdentity:
            if selectedTab != .keys {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.nav.keys", defaultValue: "Open the Keys tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.keys.entry", defaultValue: "Tap the real Generate Key entry to open the key form."),
                    target: .keysGenerateButton
                )
            }
            return payload(
                module,
                body: String(localized: "guidedTutorial.keys.form", defaultValue: "Review the prefilled Alice identity and generate the key."),
                target: nil
            )

        case .addDemoContact:
            if selectedTab != .contacts {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.nav.contacts", defaultValue: "Open the Contacts tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.contacts.entry", defaultValue: "Tap Add Contact to import Bob's sandbox public key."),
                    target: .contactsAddButton
                )
            }
            return payload(
                module,
                body: String(localized: "guidedTutorial.contacts.form", defaultValue: "Confirm Bob's key details and add the contact."),
                target: nil
            )

        case .encryptDemoMessage:
            if visibleRoute == .encrypt {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.encrypt.form", defaultValue: "Bob is preselected. Review the draft and encrypt the message."),
                    target: nil
                )
            }
            if selectedTab == .home, visibleRoute == nil {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.home.encrypt", defaultValue: "Use the real Encrypt shortcut to open the message form."),
                    target: .homeEncryptAction
                )
            }
            if sizeClass == .compact {
                if selectedTab != .home {
                    return payload(
                        module,
                        body: String(localized: "guidedTutorial.nav.homeEncrypt", defaultValue: "Open the Home tab to reach the Encrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return payload(
                        module,
                        body: String(localized: "guidedTutorial.home.encrypt", defaultValue: "Use the real Encrypt shortcut to open the message form."),
                        target: .homeEncryptAction
                    )
                }
            } else if selectedTab != .encrypt {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.nav.encrypt", defaultValue: "Open Encrypt from the Tools section to continue."),
                    target: nil
                )
            }
            return payload(
                module,
                body: String(localized: "guidedTutorial.encrypt.form", defaultValue: "Bob is preselected. Review the draft and encrypt the message."),
                target: nil
            )

        case .decryptAndVerify:
            if visibleRoute == .decrypt {
                if session.artifacts.parseResult == nil {
                    return payload(
                        module,
                        body: String(localized: "guidedTutorial.decrypt.parse", defaultValue: "Check the recipients first and make sure the message matches your sandbox key."),
                        target: nil
                    )
                }
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.decrypt.form", defaultValue: "Decrypt the sandbox message and review the signature result."),
                    target: nil
                )
            }
            if selectedTab == .home, visibleRoute == nil {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message."),
                    target: .homeDecryptAction
                )
            }
            if sizeClass == .compact {
                if selectedTab != .home {
                    return payload(
                        module,
                        body: String(localized: "guidedTutorial.nav.homeDecrypt", defaultValue: "Open the Home tab to reach the Decrypt shortcut."),
                        target: nil
                    )
                }
                if visibleRoute == nil {
                    return payload(
                        module,
                        body: String(localized: "guidedTutorial.home.decrypt", defaultValue: "Use the real Decrypt shortcut to inspect the encrypted message."),
                        target: .homeDecryptAction
                    )
                }
            } else if selectedTab != .decrypt {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.nav.decrypt", defaultValue: "Open Decrypt from the Tools section to continue."),
                    target: nil
                )
            }
            if session.artifacts.parseResult == nil {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.decrypt.parse", defaultValue: "Check the recipients first and make sure the message matches your sandbox key."),
                    target: nil
                )
            }
            return payload(
                module,
                body: String(localized: "guidedTutorial.decrypt.form", defaultValue: "Decrypt the sandbox message and review the signature result."),
                target: nil
            )

        case .backupKey:
            if selectedTab != .keys {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.nav.keys", defaultValue: "Open the Keys tab to continue."),
                    target: nil
                )
            }
            if visibleRoute == nil, let fingerprint = session.artifacts.aliceIdentity?.fingerprint {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.keys.alice", defaultValue: "Open Alice's key from My Keys to continue."),
                    target: .keyRow(fingerprint: fingerprint)
                )
            }
            if case .keyDetail(let fingerprint)? = visibleRoute,
               fingerprint == session.artifacts.aliceIdentity?.fingerprint {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.backup.entry", defaultValue: "Use the real Export Backup action from Alice's key detail page."),
                    target: .keyDetailBackupButton
                )
            }
            return payload(
                module,
                body: String(localized: "guidedTutorial.backup.form", defaultValue: "Enter a passphrase and generate the sandbox backup."),
                target: nil
            )

        case .enableHighSecurity:
            if selectedTab != .settings {
                return payload(
                    module,
                    body: String(localized: "guidedTutorial.nav.settings", defaultValue: "Open the Settings tab to continue."),
                    target: nil
                )
            }
            return payload(
                module,
                body: String(localized: "guidedTutorial.settings.auth", defaultValue: "Switch the authentication mode to High Security and confirm the warning."),
                target: .settingsAuthModePicker
            )

        case .sandbox:
            return payload(
                module,
                body: String(localized: "guidedTutorial.intro.body", defaultValue: "This walkthrough runs entirely in a sandbox. Your real keys, contacts, settings, files, and exports are never touched."),
                target: nil
            )
        }
    }

    func modalGuidance(
        session: TutorialSessionState,
        navigation _: TutorialNavigationState,
        sizeClass _: UserInterfaceSizeClass?,
        selectedTab _: AppShellTab,
        modal: TutorialModal
    ) -> TutorialGuidancePayload? {
        guard let module = modalModule(for: session) else { return nil }

        return TutorialGuidancePayload(
            module: module,
            state: .inProgress,
            title: module.title,
            body: modalBody(for: modal),
            realAppLocation: module.realAppLocation,
            target: modalTarget(for: modal)
        )
    }

    private func payload(
        _ module: TutorialModuleID,
        body: String,
        target: TutorialAnchorID?
    ) -> TutorialGuidancePayload {
        TutorialGuidancePayload(
            module: module,
            state: .inProgress,
            title: module.title,
            body: body,
            realAppLocation: module.realAppLocation,
            target: target
        )
    }

    private func modalModule(for session: TutorialSessionState) -> TutorialModuleID? {
        session.activeModule
            ?? session.nextIncompleteModule
            ?? (session.hasCompletedAllModules ? .enableHighSecurity : nil)
    }

    private func modalBody(for modal: TutorialModal) -> String {
        switch modal {
        case .importConfirmation:
            String(localized: "guidedTutorial.contacts.form", defaultValue: "Confirm Bob's key details and add the contact.")
        case .authModeConfirmation:
            String(localized: "guidedTutorial.settings.auth", defaultValue: "Switch the authentication mode to High Security and confirm the warning.")
        case .leaveConfirmation:
            String(
                localized: "guidedTutorial.leave.body",
                defaultValue: "Leave the guided tutorial now? Your progress will stay available until this app run ends, but the tutorial will close."
            )
        }
    }

    private func modalTarget(for modal: TutorialModal) -> TutorialAnchorID? {
        switch modal {
        case .authModeConfirmation:
            .settingsModeConfirmButton
        case .importConfirmation, .leaveConfirmation:
            nil
        }
    }

    private func completionPayload(_ module: TutorialModuleID) -> TutorialGuidancePayload {
        TutorialGuidancePayload(
            module: module,
            state: .completed,
            title: module.title,
            body: completionMessage(for: module),
            realAppLocation: module.realAppLocation,
            target: nil
        )
    }

    private func completionMessage(for module: TutorialModuleID) -> String {
        if module == .enableHighSecurity {
            return String(
                localized: "guidedTutorial.task.complete.final",
                defaultValue: "This task is complete. Return to the tutorial overview to review completion and finish the tutorial."
            )
        }

        return String(
            localized: "guidedTutorial.task.complete",
            defaultValue: "This task is complete. Return to the tutorial overview to continue."
        )
    }
}
