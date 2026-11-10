import CryptoKit
import Foundation
import Stores
import Testing
import Vault
import VaultTestSupport
@testable import CypherCore

/// The core rules of the architecture's section 6 that belong to this piece.
/// Each has exactly one allowed outcome.
@MainActor
@Suite struct RuleTests {
    @Test("C1: while locked, no workspace exists, and an old reference throws locked")
    func lockedMeansNoWorkspace() async throws {
        let harness = Harness()
        let workspace = try await harness.created()

        workspace.lock()

        _ = try harness.unlock()
        #expect(workspace.session.vaultSession.isLocked)
        await #expect(throws: CoreError.locked) {
            try await workspace.settings.update { $0.clipboardNotice = false }
        }
    }

    enum Condition: CaseIterable, Sendable {
        case missing, damaged, madeByAnotherVersion
    }

    enum File: String, CaseIterable, Sendable {
        case keys, contacts, settings
    }

    @Test("C2: a file that is missing, damaged or from another version leads to the damaged phase", arguments: File.allCases, Condition.allCases)
    func unusableFileMeansDamagedPhase(file: File, condition: Condition) async throws {
        let harness = Harness()
        let workspace = try await harness.created()
        let key = try workspace.session.domainKey(file.rawValue)
        workspace.lock()

        switch condition {
        case .missing:
            harness.files.files.delete(file.rawValue)
        case .damaged:
            harness.files.files.corrupt(file.rawValue)
        case .madeByAnotherVersion:
            try SealedDomain<SettingsPayload>(domain: file.rawValue, schemaVersion: 2, files: harness.files)
                .save(.firstValue, key: key)
        }
        try await harness.unlock().submit(passphrase: Harness.passphrase)

        let state: FileState = switch condition {
        case .missing: .missing
        case .damaged: .damaged
        case .madeByAnotherVersion: .madeByAnotherVersion
        }
        let expected = DamageReport(
            keys: file == .keys ? state : .intact,
            contacts: file == .contacts ? state : .intact,
            settings: file == .settings ? state : .intact
        )
        let recovery = try harness.recovery()
        #expect(recovery.report == expected)
        #expect((recovery.keys != nil) == (file != .keys), "an intact key list stays for the backup")
    }

    @Test("C3: a save that fails changes nothing in memory")
    func failedSaveChangesNothing() async throws {
        let harness = Harness()
        let workspace = try await harness.created()
        let before = workspace.settings.values

        harness.files.failsWrites = true
        await #expect(throws: CoreError.storageFailed) {
            try await workspace.settings.update { $0.relockAfter = .fiveMinutes }
        }
        #expect(workspace.settings.values == before)

        harness.files.failsWrites = false
        try await workspace.settings.update { $0.clipboardNotice = false }
        var expected = before
        expected.clipboardNotice = false
        #expect(workspace.settings.values == expected)
    }
}
