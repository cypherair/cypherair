import Foundation
#if canImport(XCTest) && canImport(CypherAir)
@testable import CypherAir
#endif

struct TutorialGuidanceModel {
    func payload(
        for module: TutorialModuleID,
        session: TutorialRuntimeSession?,
        pendingAuthContinuation: TutorialLifecycleModel.AuthContinuation?
    ) -> TutorialGuidancePayload {
        let detail: String
        let target: TutorialAnchorID?

        switch module {
        case .sandbox:
            detail = String(localized: "tutorial.guidance.sandbox", defaultValue: "Confirm that this tutorial uses isolated demo data before you enter the workspace.")
            target = .tutorialPrimaryAction
        case .demoIdentity:
            if session?.artifacts.aliceIdentity == nil {
                detail = String(localized: "tutorial.guidance.identity.create", defaultValue: "Generate the demo key that represents you in this safe practice space.")
                target = .tutorialPrimaryAction
            } else {
                detail = String(localized: "tutorial.guidance.identity.done", defaultValue: "Your demo identity is ready. Return to the hub to continue to Contacts.")
                target = .tutorialReturnButton
            }
        case .demoContact:
            if session?.artifacts.bobContact == nil {
                detail = String(localized: "tutorial.guidance.contact.add", defaultValue: "Add the tutorial-provided Bob contact. No real importers or pickers are used here.")
                target = .tutorialPrimaryAction
            } else {
                detail = String(localized: "tutorial.guidance.contact.done", defaultValue: "Bob is available for encryption. Return to the hub to continue to Encrypt.")
                target = .tutorialReturnButton
            }
        case .encryptMessage:
            if session?.artifacts.encryptedMessage == nil {
                detail = String(localized: "tutorial.guidance.encrypt.create", defaultValue: "Write a short message for Bob and encrypt it. The tutorial keeps the protected output local to this demo session.")
                target = .tutorialPrimaryAction
            } else {
                detail = String(localized: "tutorial.guidance.encrypt.done", defaultValue: "The encrypted output is ready for the Decrypt module. Return to the hub to continue.")
                target = .tutorialReturnButton
            }
        case .decryptAndVerify:
            if session?.artifacts.parseResult == nil {
                detail = String(localized: "tutorial.guidance.decrypt.parse", defaultValue: "Start by checking which local key matches this ciphertext before decryption happens.")
                target = .tutorialPrimaryAction
            } else if session?.artifacts.decryptedMessage == nil {
                detail = String(localized: "tutorial.guidance.decrypt.auth", defaultValue: "Continue to the simulated authentication explanation, then decrypt the message and review the signature result.")
                target = pendingAuthContinuation == .decryptMessage ? .tutorialModalConfirmButton : .tutorialPrimaryAction
            } else {
                detail = String(localized: "tutorial.guidance.decrypt.done", defaultValue: "You have now seen the two-step decrypt flow. Return to the hub to finish the core tutorial.")
                target = .tutorialReturnButton
            }
        case .backupKey:
            if session?.artifacts.backupArmoredKey == nil {
                detail = String(localized: "tutorial.guidance.backup.create", defaultValue: "Enter a backup passphrase to generate a tutorial-only backup preview instead of a real exported file.")
                target = .tutorialPrimaryAction
            } else {
                detail = String(localized: "tutorial.guidance.backup.done", defaultValue: "The demo backup status is complete. Finish this module when you are ready.")
                target = .tutorialFinishButton
            }
        case .enableHighSecurity:
            if session?.artifacts.authMode == .highSecurity {
                detail = String(localized: "tutorial.guidance.highSecurity.done", defaultValue: "The tutorial-only High Security state is enabled. Finish this module to return to the app.")
                target = .tutorialFinishButton
            } else {
                detail = String(localized: "tutorial.guidance.highSecurity.start", defaultValue: "Review the consequences, then continue to the confirmation modal before switching the tutorial-only setting.")
                target = pendingAuthContinuation == .enableHighSecurity ? .tutorialModalConfirmButton : .tutorialPrimaryAction
            }
        }

        return TutorialGuidancePayload(
            module: module,
            title: module.title,
            goal: module.summary,
            realAppLocationLabel: module.realAppLocationLabel,
            detail: detail,
            target: target,
            modalGuidance: modalGuidance(for: module, continuation: pendingAuthContinuation)
        )
    }

    private func modalGuidance(
        for module: TutorialModuleID,
        continuation: TutorialLifecycleModel.AuthContinuation?
    ) -> TutorialModalGuidance? {
        guard continuation != nil else { return nil }

        switch module {
        case .decryptAndVerify:
            return TutorialModalGuidance(
                whyThisExists: String(localized: "tutorial.modal.decrypt.why", defaultValue: "In the real app, this is where device authentication would protect access to your private key."),
                expectedAction: String(localized: "tutorial.modal.decrypt.action", defaultValue: "Confirm the tutorial explanation, then continue to decrypt the demo message."),
                nextStep: String(localized: "tutorial.modal.decrypt.next", defaultValue: "After this, the plaintext and signature result will appear inside the tutorial workspace.")
            )
        case .enableHighSecurity:
            return TutorialModalGuidance(
                whyThisExists: String(localized: "tutorial.modal.highSecurity.why", defaultValue: "High Security is a meaningful decision because it removes passcode fallback in the real app."),
                expectedAction: String(localized: "tutorial.modal.highSecurity.action", defaultValue: "Confirm that you understand the tutorial warning, then switch the tutorial-only setting."),
                nextStep: String(localized: "tutorial.modal.highSecurity.next", defaultValue: "After this, the module will show the new tutorial-only auth mode and explain the real-world impact.")
            )
        default:
            return nil
        }
    }
}
