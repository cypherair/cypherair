import Foundation
import Stores
import Testing
import Vault
import VaultTestSupport
@testable import CypherCore

@MainActor
@Suite struct ProtectionTests {
    @Test func `A first run creates the vault behind one prompt and unlocks`() async throws {
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

    @Test func `A passphrase with a problem is refused before any prompt`() async throws {
        let harness = Harness()
        await harness.core.start()

        await #expect(throws: CoreError.passphraseTooWeak) {
            try await harness.firstRun().create(passphrase: "too short")
        }

        #expect(harness.authenticator.prompts == 0)
        #expect(harness.keychain.contents.isEmpty)
        _ = try harness.firstRun()
    }

    @Test func `A first run that cannot write its files leaves no vault`() async throws {
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

    @Test func `A relaunch finds the vault and starts locked`() async throws {
        let harness = Harness()
        _ = try await harness.created()

        let next = harness.relaunched()
        await next.start()

        guard case .locked = next.phase else { throw UnexpectedPhase(description: "\(next.phase)") }
    }

    @Test func `Lock then unlock opens what was saved`() async throws {
        let harness = Harness()
        let workspace = try await harness.created()
        try await workspace.settings.update { $0.signByDefault = false }
        workspace.lock()

        try await harness.unlock().submit(passphrase: Harness.passphrase)

        #expect(try harness.workspace().settings.values.signByDefault == false)
    }

    @Test func `A wrong passphrase keeps the app locked, and the retry shows no second prompt`() async throws {
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

    @Test func `A device lock during an unlock keeps the app locked, and the next submission prompts again`() async throws {
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

    @Test func `A device lock during a first run leaves the new vault locked`() async throws {
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

    @Test(arguments: [PresenceEvent.wentAway, .deviceLocked])
    func `After a wrong passphrase, going away or a device lock brings the prompt back`(event: PresenceEvent) async throws {
        let harness = Harness()
        try await harness.created().lock()
        await #expect(throws: CoreError.wrongPassphrase) {
            try await harness.unlock().submit(passphrase: "not the passphrase")
        }
        let prompts = harness.authenticator.prompts

        harness.core.report(event)
        try await harness.unlock().submit(passphrase: Harness.passphrase)

        _ = try harness.workspace()
        #expect(harness.authenticator.prompts == prompts + 1)
    }

    enum OpenPhase: Sendable {
        case unlocked, damaged
    }

    @Test(arguments: [(OpenPhase.damaged, PresenceEvent.wentAway), (.damaged, .deviceLocked), (.unlocked, .deviceLocked)])
    func `A reported event locks an open session`(phase: OpenPhase, event: PresenceEvent) async throws {
        let harness = Harness()
        try await harness.created().lock()
        if phase == .damaged {
            harness.files.files.corrupt("contacts")
        }
        try await harness.unlock().submit(passphrase: Harness.passphrase)
        let session = switch phase {
        case .unlocked: try harness.workspace().session
        case .damaged: try harness.recovery().session
        }

        harness.core.report(event)

        _ = try harness.unlock()
        #expect(session.vaultSession.isLocked)
    }

    @Test func `A file that cannot be read keeps the app locked and is not damage`() async throws {
        let harness = Harness()
        try await harness.created().lock()
        harness.files.failsReads = true

        await #expect(throws: CoreError.storageFailed) {
            try await harness.unlock().submit(passphrase: Harness.passphrase)
        }
        _ = try harness.unlock()

        harness.files.failsReads = false
        try await harness.unlock().submit(passphrase: Harness.passphrase)
        _ = try harness.workspace()
    }

    @Test func `An empty passphrase is wrong before any prompt`() async throws {
        let harness = Harness()
        try await harness.created().lock()
        let prompts = harness.authenticator.prompts

        await #expect(throws: CoreError.wrongPassphrase) {
            try await harness.unlock().submit(passphrase: "")
        }

        #expect(harness.authenticator.prompts == prompts)
    }

    @Test(arguments: [(VaultError.authenticationCancelled, CoreError.cancelled), (.authenticationFailed, .authenticationFailed), (.authenticationUnavailable, .authenticationUnavailable)])
    func `A failed prompt keeps the app locked`(failure: VaultError, expected: CoreError) async throws {
        let harness = Harness()
        try await harness.created().lock()
        harness.authenticator.failure = failure

        await #expect(throws: expected) {
            try await harness.unlock().submit(passphrase: Harness.passphrase)
        }

        _ = try harness.unlock()
    }

    @Test func `Concurrent changes each apply to the value before them`() async throws {
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

    @Test func `The preview is unlocked`() throws {
        guard case .unlocked = AppCore.preview().phase else { throw UnexpectedPhase(description: "not unlocked") }
    }
}
