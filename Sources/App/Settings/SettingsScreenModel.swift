import Foundation
import SwiftUI

@MainActor
@Observable
final class SettingsScreenModel {
    let configuration: SettingsView.Configuration
    let appSettings: AppSettingsCoordinator
    let localDataReset: LocalDataResetFlow

    private let iosPresentationController: IOSPresentationController?
    private let macPresentationController: MacPresentationController?

    var showOnboarding = false
    var showTutorialOnboarding = false
    var showChangePassphrase = false

    init(
        appSettings: AppSettingsCoordinator,
        iosPresentationController: IOSPresentationController?,
        macPresentationController: MacPresentationController?,
        configuration: SettingsView.Configuration,
        localDataResetService: LocalDataResetService? = nil,
        localDataResetRestartCoordinator: LocalDataResetRestartCoordinator? = nil
    ) {
        self.configuration = configuration
        self.appSettings = appSettings
        self.iosPresentationController = iosPresentationController
        self.macPresentationController = macPresentationController
        let resetAvailable: Bool
        switch configuration.localDataResetAvailability {
        case .enabled: resetAvailable = true
        case .disabled: resetAvailable = false
        }
        localDataReset = LocalDataResetFlow(
            service: resetAvailable ? localDataResetService : nil,
            restartCoordinator: localDataResetRestartCoordinator
        )
    }

    var guidedTutorialEntryTitle: String {
        if appSettings.hasCompletedGuidedTutorial ?? false {
            String(localized: "guidedTutorial.replay", defaultValue: "Replay Guided Tutorial")
        } else {
            String(localized: "guidedTutorial.settings.entry", defaultValue: "Guided Tutorial")
        }
    }

    var isSettingsEditable: Bool {
        appSettings.isLoaded
    }

    var gracePeriodSelection: Int {
        appSettings.gracePeriodForSession ?? AppSettingsSnapshot.defaultGracePeriod
    }

    var encryptToSelfSelection: Bool {
        appSettings.encryptToSelf ?? AppSettingsSnapshot.firstRun.encryptToSelf
    }

    var signMessagesSelection: Bool {
        appSettings.signMessages ?? AppSettingsSnapshot.firstRun.signMessages
    }

    var isClipboardNoticeEnabled: Bool {
        appSettings.clipboardNotice ?? AppSettingsSnapshot.firstRun.clipboardNotice
    }

    func setGracePeriod(_ gracePeriod: Int) {
        appSettings.setGracePeriod(gracePeriod)
    }

    func setEncryptToSelf(_ encryptToSelf: Bool) {
        appSettings.setEncryptToSelf(encryptToSelf)
    }

    func setSignMessages(_ signMessages: Bool) {
        appSettings.setSignMessages(signMessages)
    }

    func setClipboardNoticeEnabled(_ enabled: Bool) {
        appSettings.setClipboardNotice(enabled)
    }

    var shouldShowLocalDataResetSection: Bool {
        switch configuration.localDataResetAvailability {
        case .enabled:
            localDataReset.isAvailable || localDataReset.isResetting
        case .disabled:
            true
        }
    }

    var isLocalDataResetControlEnabled: Bool {
        localDataReset.isAvailable
    }

    var localDataResetFooter: String {
        switch configuration.localDataResetAvailability {
        case .enabled:
            String(
                localized: "settings.resetAll.footer",
                defaultValue: "Use this only when you want this device to behave like a fresh CypherAir X install."
            )
        case .disabled(let footer):
            footer
        }
    }

    func presentChangePassphrase() {
        guard !configuration.isSandbox else { return }
        showChangePassphrase = true
    }

    func presentOnboarding() {
        guard configuration.isOnboardingEntryEnabled else { return }
        if let macPresentationController {
            macPresentationController.present(.onboarding(initialPage: 0))
        } else if let iosPresentationController {
            iosPresentationController.present(.onboarding(initialPage: 0, context: .inApp))
        } else {
            showOnboarding = true
        }
    }

    func presentTutorial() {
        guard configuration.isGuidedTutorialEntryEnabled else { return }
        if let macPresentationController {
            macPresentationController.present(.tutorial(presentationContext: .inApp))
        } else if let iosPresentationController {
            iosPresentationController.present(.tutorial(presentationContext: .inApp))
        } else {
            showTutorialOnboarding = true
        }
    }

    func clearTransientInput() {
        localDataReset.clearTransientInput()
    }
}
