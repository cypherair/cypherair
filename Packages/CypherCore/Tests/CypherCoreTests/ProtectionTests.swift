import Foundation
import Stores
import Testing
import Vault
import VaultTestSupport
@testable import CypherCore

@MainActor
@Suite struct ProtectionTests {
    @Test func firstRun_createsTheVaultBehindOnePrompt_andUnlocks() async throws {
        let harness = Harness()
        await harness.core.start()
        _ = try harness.firstRun()

        let workspace = try await harness.created()

        #expect(harness.authenticator.prompts == 1)
        #expect(workspace.settings.values == SettingsValues(SettingsPayload.firstValue))
        #expect(harness.keychain.contents.map(\.service) == [Vault.sealedRootService])
        for file in ["keys", "contacts", "settings"] {
            #expect(try harness.files.read(file) != nil)
        }
    }

    @Test func aPassphraseWithAProblem_isRefusedBeforeAnyPrompt() async throws {
        let harness = Harness()
        await harness.core.start()

        await #expect(throws: CoreError.passphraseTooWeak) {
            try await harness.firstRun().create(passphrase: "too short")
        }

        #expect(harness.authenticator.prompts == 0)
        #expect(harness.keychain.contents.isEmpty)
        _ = try harness.firstRun()
    }

    @Test func aFirstRunThatCannotWriteItsFiles_leavesNoVault() async throws {
        let harness = Harness()
        await harness.core.start()
        harness.files.failsWrites = true

        await #expect(throws: CoreError.storageFailed) {
            try await harness.firstRun().create(passphrase: Harness.passphrase)
        }

        #expect(harness.keychain.contents.isEmpty)
        _ = try harness.firstRun()
        let next = harness.relaunched()
        await next.start()
        guard case .firstRun = next.phase else { throw UnexpectedPhase(description: "\(next.phase)") }
    }

    @Test func aRelaunch_findsTheVault_andStartsLocked() async throws {
        let harness = Harness()
        _ = try await harness.created()

        let next = harness.relaunched()
        await next.start()

        guard case .locked = next.phase else { throw UnexpectedPhase(description: "\(next.phase)") }
    }

    @Test func lockThenUnlock_opensWhatWasSaved() async throws {
        let harness = Harness()
        let workspace = try await harness.created()
        try await workspace.settings.update { $0.signByDefault = false }
        workspace.lock()

        try await harness.unlock().submit(passphrase: Harness.passphrase)

        #expect(try harness.workspace().settings.values.signByDefault == false)
    }

    @Test func aWrongPassphrase_keepsTheAppLocked_andTheRetryShowsNoSecondPrompt() async throws {
        let harness = Harness()
        try await harness.created().lock()
        let unlock = try harness.unlock()
        let prompts = harness.authenticator.prompts

        await #expect(throws: CoreError.wrongPassphrase) {
            try await unlock.submit(passphrase: "not the passphrase")
        }
        #expect(try harness.unlock() === unlock)

        try await unlock.submit(passphrase: Harness.passphrase)
        _ = try harness.workspace()
        #expect(harness.authenticator.prompts == prompts + 1)
    }

    @Test func aDeviceLockDuringAnUnlock_keepsTheAppLocked_andTheNextSubmissionPromptsAgain() async throws {
        let harness = Harness()
        try await harness.created().lock()
        let core = harness.core
        harness.authenticator.duringPrompt = { core.report(.deviceLocked) }

        await #expect(throws: CoreError.cancelled) {
            try await harness.unlock().submit(passphrase: Harness.passphrase)
        }
        _ = try harness.unlock()

        harness.authenticator.duringPrompt = nil
        let prompts = harness.authenticator.prompts
        try await harness.unlock().submit(passphrase: Harness.passphrase)
        _ = try harness.workspace()
        #expect(harness.authenticator.prompts == prompts + 1)
    }

    @Test func aDeviceLockDuringAFirstRun_leavesTheNewVaultLocked() async throws {
        let harness = Harness()
        await harness.core.start()
        let core = harness.core
        harness.authenticator.duringPrompt = { core.report(.deviceLocked) }

        await #expect(throws: CoreError.cancelled) {
            try await harness.firstRun().create(passphrase: Harness.passphrase)
        }

        harness.authenticator.duringPrompt = nil
        try await harness.unlock().submit(passphrase: Harness.passphrase)
        _ = try harness.workspace()
    }

    @Test func anEmptyPassphrase_isWrong_beforeAnyPrompt() async throws {
        let harness = Harness()
        try await harness.created().lock()
        let prompts = harness.authenticator.prompts

        await #expect(throws: CoreError.wrongPassphrase) {
            try await harness.unlock().submit(passphrase: "")
        }

        #expect(harness.authenticator.prompts == prompts)
    }

    @Test(arguments: [(VaultError.authenticationCancelled, CoreError.cancelled), (.authenticationFailed, .authenticationFailed), (.authenticationUnavailable, .authenticationUnavailable)])
    func aFailedPrompt_keepsTheAppLocked(failure: VaultError, expected: CoreError) async throws {
        let harness = Harness()
        try await harness.created().lock()
        harness.authenticator.failure = failure

        await #expect(throws: expected) {
            try await harness.unlock().submit(passphrase: Harness.passphrase)
        }

        _ = try harness.unlock()
    }

    @Test func concurrentChanges_eachApplyToTheValueBeforeThem() async throws {
        let harness = Harness()
        let workspace = try await harness.created()

        async let first: Void = workspace.settings.update { $0.signByDefault = false }
        async let second: Void = workspace.settings.update { $0.clipboardNotice = false }
        _ = try await (first, second)
        workspace.lock()
        try await harness.unlock().submit(passphrase: Harness.passphrase)

        let values = try harness.workspace().settings.values
        #expect(values.signByDefault == false)
        #expect(values.clipboardNotice == false)
    }

    @Test func thePreview_isUnlocked() throws {
        guard case .unlocked = AppCore.preview().phase else { throw UnexpectedPhase(description: "not unlocked") }
    }
}
