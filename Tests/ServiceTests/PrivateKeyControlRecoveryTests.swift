import Foundation
import XCTest
@testable import CypherAir

private enum CommonHelpersTestError: Error {
    case delayedFailure
}

private final class FailingCompleteRewrapPrivateKeyControlStore: PrivateKeyControlStoreProtocol, @unchecked Sendable {
    private var mode: AuthenticationMode?
    private var journal: PrivateKeyControlRecoveryJournal
    var failNextCompleteRewrap = false

    init(
        mode: AuthenticationMode?,
        journal: PrivateKeyControlRecoveryJournal
    ) {
        self.mode = mode
        self.journal = journal
    }

    var privateKeyControlState: PrivateKeyControlState {
        guard let mode else {
            return .locked
        }
        return .unlocked(mode)
    }

    func requireUnlockedAuthMode() throws -> AuthenticationMode {
        guard let mode else {
            throw PrivateKeyControlError.locked
        }
        if journal.rewrapPhase == .commitRequired,
           let targetMode = journal.rewrapTargetMode,
           targetMode != mode {
            throw PrivateKeyControlError.recoveryNeeded
        }
        return mode
    }

    func recoveryJournal() throws -> PrivateKeyControlRecoveryJournal {
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        return journal
    }

    func beginRewrap(targetMode: AuthenticationMode) throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = targetMode
        journal.rewrapPhase = .preparing
    }

    func markRewrapCommitRequired() throws {
        _ = try requireUnlockedAuthMode()
        guard journal.rewrapTargetMode != nil else {
            throw PrivateKeyControlError.recoveryNeeded
        }
        journal.rewrapPhase = .commitRequired
    }

    func completeRewrap(targetMode: AuthenticationMode) throws {
        guard mode != nil else {
            throw PrivateKeyControlError.locked
        }
        if failNextCompleteRewrap {
            failNextCompleteRewrap = false
            mode = targetMode
            journal.rewrapTargetMode = targetMode
            journal.rewrapPhase = .commitRequired
            throw CommonHelpersTestError.delayedFailure
        }
        mode = targetMode
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func clearRewrapJournal() throws {
        _ = try requireUnlockedAuthMode()
        journal.rewrapTargetMode = nil
        journal.rewrapPhase = nil
    }

    func beginModifyExpiry(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        journal.modifyExpiry = ModifyExpiryRecoveryEntry(fingerprint: fingerprint)
    }

    func clearModifyExpiryJournal() throws {
        _ = try requireUnlockedAuthMode()
        journal.modifyExpiry = nil
    }

    func clearModifyExpiryJournalIfMatches(fingerprint: String) throws {
        _ = try requireUnlockedAuthMode()
        if journal.modifyExpiry?.fingerprint == fingerprint {
            journal.modifyExpiry = nil
        }
    }
}

@MainActor
final class PrivateKeyControlRecoveryTests: XCTestCase {
    func test_rewrapRecovery_commitRequiredNoPending_retriesTargetModePersistence() throws {
        let keychain = MockKeychain()
        let fingerprint = "commit-required-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = FailingCompleteRewrapPrivateKeyControlStore(
            mode: .standard,
            journal: PrivateKeyControlRecoveryJournal(
                rewrapTargetMode: .highSecurity,
                rewrapPhase: .commitRequired
            )
        )
        privateKeyControlStore.failNextCompleteRewrap = true
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let firstSummary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(firstSummary?.outcomes, [.noActionSafe, .retryableFailure])
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapTargetMode, .highSecurity)
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapPhase, .commitRequired)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
        XCTAssertFalse(firstSummary?.startupDiagnostics.isEmpty ?? true)

        let secondSummary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(secondSummary?.outcomes, [.noActionSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
    }

    func test_rewrapRecovery_preparingPendingOnlyCommitFailureKeepsCommitJournal() throws {
        let keychain = MockKeychain()
        let fingerprint = "preparing-pending-\(UUID().uuidString)"
        try savePendingRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = FailingCompleteRewrapPrivateKeyControlStore(
            mode: .standard,
            journal: PrivateKeyControlRecoveryJournal(
                rewrapTargetMode: .highSecurity,
                rewrapPhase: .preparing
            )
        )
        privateKeyControlStore.failNextCompleteRewrap = true
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let firstSummary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(firstSummary?.outcomes, [.promotedPendingSafe, .retryableFailure])
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapTargetMode, .highSecurity)
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapPhase, .commitRequired)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Data("pending-se-key".utf8)
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))

        let secondSummary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(secondSummary?.outcomes, [.noActionSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
    }

    func test_rewrapRecovery_preparingNoPending_clearsJournalWithoutChangingMode() throws {
        let keychain = MockKeychain()
        let fingerprint = "preparing-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.noActionSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .standard)
    }

    func test_rewrapRecovery_preparingOldAndPending_cleansPendingKeepsOldMode() throws {
        let keychain = MockKeychain()
        let fingerprint = "preparing-clean-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)
        try savePendingRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.cleanedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .standard)
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Data("permanent-se-key".utf8)
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_rewrapRecovery_commitRequiredOldAndPending_replacesPermanentWithPending() throws {
        let keychain = MockKeychain()
        let fingerprint = "commit-replace-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)
        try savePendingRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Data("pending-se-key".utf8)
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_rewrapRecovery_commitRequiredMixedPhaseB_promotesAllTargetBundles() throws {
        let keychain = MockKeychain()
        let pendingOnlyFingerprint = "commit-pending-\(UUID().uuidString)"
        let oldAndPendingFingerprint = "commit-mixed-\(UUID().uuidString)"
        try savePendingRecoveryBundle(in: keychain, fingerprint: pendingOnlyFingerprint)
        try savePermanentRecoveryBundle(in: keychain, fingerprint: oldAndPendingFingerprint)
        try savePendingRecoveryBundle(in: keychain, fingerprint: oldAndPendingFingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: [pendingOnlyFingerprint, oldAndPendingFingerprint]
        )

        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe, .promotedPendingSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
        for fingerprint in [pendingOnlyFingerprint, oldAndPendingFingerprint] {
            XCTAssertEqual(
                try keychain.load(
                    service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                ),
                Data("pending-se-key".utf8)
            )
            XCTAssertFalse(keychain.exists(
                service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ))
        }
    }

    func test_rewrapRecovery_commitRequiredPartialPending_keepsJournalAndFailsClosed() throws {
        let keychain = MockKeychain()
        let fingerprint = "commit-partial-\(UUID().uuidString)"
        try savePermanentRecoveryBundle(in: keychain, fingerprint: fingerprint)
        try savePartialPendingRecoveryBundle(in: keychain, fingerprint: fingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(summary?.outcomes, [.retryableFailure])
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapTargetMode, .highSecurity)
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapPhase, .commitRequired)
        XCTAssertNil(authManager.currentMode)
        XCTAssertThrowsError(try privateKeyControlStore.beginModifyExpiry(fingerprint: "blocked-\(fingerprint)")) { error in
            XCTAssertEqual(error as? PrivateKeyControlError, .recoveryNeeded)
        }
        XCTAssertEqual(
            try keychain.load(
                service: KeychainConstants.seKeyService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Data("permanent-se-key".utf8)
        )
        XCTAssertTrue(keychain.exists(
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))
    }

    func test_postUnlockRecoveryWarningBuilder_surfacesOnlyUnsafeOutcomes() {
        let retryableWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.noActionSafe, .retryableFailure]),
            modifyExpiryOutcome: nil
        )
        XCTAssertNotNil(retryableWarning)
        XCTAssertTrue(retryableWarning?.contains("retry") == true)

        let duplicateWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.retryableFailure]),
            modifyExpiryOutcome: .retryableFailure
        )
        XCTAssertEqual(duplicateWarning?.components(separatedBy: "\n").count, 1)

        let unrecoverableWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: nil,
            modifyExpiryOutcome: .unrecoverable
        )
        XCTAssertNotNil(unrecoverableWarning)
        XCTAssertTrue(unrecoverableWarning?.contains("Restore from backup") == true)

        XCTAssertNil(AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.noActionSafe, .cleanedPendingSafe]),
            modifyExpiryOutcome: .cleanedPendingSafe
        ))
    }

    func test_postUnlockRecoveryWarningAppend_surfacesCustomWarningAndClears() {
        let suiteName = "com.cypherair.postUnlockContactsWarning.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let config = AppConfiguration(defaults: defaults)
        let customWarning = "Retry loading protected data after unlocking again."

        config.appendPostUnlockRecoveryLoadWarning(customWarning)

        XCTAssertEqual(config.postUnlockRecoveryLoadWarning, customWarning)
        config.clearPostUnlockRecoveryLoadWarning()
        XCTAssertNil(config.postUnlockRecoveryLoadWarning)
    }

    func test_postUnlockRecoveryWarningAppend_preservesDistinctWarningsWithoutDuplicates() throws {
        let suiteName = "com.cypherair.postUnlockCombinedWarning.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let config = AppConfiguration(defaults: defaults)
        let customWarning = "Retry loading protected data after unlocking again."
        let keyWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.retryableFailure]),
            modifyExpiryOutcome: nil
        )

        config.appendPostUnlockRecoveryLoadWarning(customWarning)
        config.appendPostUnlockRecoveryLoadWarning(keyWarning)
        config.appendPostUnlockRecoveryLoadWarning(customWarning)

        let warning = try XCTUnwrap(config.postUnlockRecoveryLoadWarning)
        XCTAssertTrue(warning.contains(customWarning))
        XCTAssertTrue(warning.contains("retry"))
        XCTAssertEqual(warning.components(separatedBy: "\n").count, 2)
    }

    func test_postUnlockRecovery_resyncsConfigAfterRewrapCompletes() async throws {
        let suiteName = "com.cypherair.postUnlockSync.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let keychain = MockKeychain()
        let secureEnclave = MockSecureEnclave()
        let privateKeyControlStore = InMemoryPrivateKeyControlStore(mode: .standard)
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
        let engine = PgpEngine()
        let keyManagement = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: secureEnclave,
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: InMemoryKeyMetadataStore()
        )
        _ = try await keyManagement.generateKey(
            name: "Post Unlock",
            email: "post-unlock@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()

        let config = AppConfiguration(defaults: defaults)
        config.privateKeyControlState = .unlocked(.standard)

        AppContainer.recoverPrivateKeyControlJournalsAfterPostUnlock(
            authManager: authManager,
            keyManagement: keyManagement,
            config: config,
            privateKeyControlStore: privateKeyControlStore
        )

        XCTAssertEqual(config.authModeIfUnlocked, .highSecurity)
        XCTAssertNil(config.postUnlockRecoveryLoadWarning)
    }

    func test_postUnlockRecovery_warningPathStillResyncsConfig() async throws {
        let suiteName = "com.cypherair.postUnlockWarningSync.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let keychain = MockKeychain()
        let privateKeyControlStore = FailingCompleteRewrapPrivateKeyControlStore(
            mode: .standard,
            journal: .empty
        )
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
        let engine = PgpEngine()
        let keyManagement = KeyManagementService(
            keyAdapter: PGPKeyOperationAdapter(engine: engine),
            certificateAdapter: PGPCertificateOperationAdapter(engine: engine),
            secureEnclave: MockSecureEnclave(),
            keychain: keychain,
            authenticator: authManager,
            defaults: defaults,
            privateKeyControlStore: privateKeyControlStore,
            metadataPersistence: InMemoryKeyMetadataStore()
        )
        _ = try await keyManagement.generateKey(
            name: "Post Unlock Warning",
            email: "post-unlock-warning@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )
        try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
        try privateKeyControlStore.markRewrapCommitRequired()
        privateKeyControlStore.failNextCompleteRewrap = true

        let config = AppConfiguration(defaults: defaults)
        config.privateKeyControlState = .unlocked(.highSecurity)

        AppContainer.recoverPrivateKeyControlJournalsAfterPostUnlock(
            authManager: authManager,
            keyManagement: keyManagement,
            config: config,
            privateKeyControlStore: privateKeyControlStore
        )

        XCTAssertEqual(config.authModeIfUnlocked, .highSecurity)
        XCTAssertTrue(config.postUnlockRecoveryLoadWarning?.contains("retry") == true)
        XCTAssertEqual(try privateKeyControlStore.recoveryJournal().rewrapTargetMode, .highSecurity)
    }

    private func makeRecoveryAuthenticationManager(
        keychain: MockKeychain,
        privateKeyControlStore: any PrivateKeyControlStoreProtocol
    ) -> AuthenticationManager {
        AuthenticationManager(
            secureEnclave: MockSecureEnclave(),
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )
    }

    private func savePermanentRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        let account = KeychainConstants.defaultAccount
        try keychain.save(
            Data("permanent-se-key".utf8),
            service: KeychainConstants.seKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("permanent-salt".utf8),
            service: KeychainConstants.saltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("permanent-sealed".utf8),
            service: KeychainConstants.sealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
    }

    private func savePendingRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        let account = KeychainConstants.defaultAccount
        try keychain.save(
            Data("pending-se-key".utf8),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("pending-salt".utf8),
            service: KeychainConstants.pendingSaltService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
        try keychain.save(
            Data("pending-sealed".utf8),
            service: KeychainConstants.pendingSealedKeyService(fingerprint: fingerprint),
            account: account,
            accessControl: nil
        )
    }

    private func savePartialPendingRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        try keychain.save(
            Data("partial-pending-se-key".utf8),
            service: KeychainConstants.pendingSeKeyService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }
}
