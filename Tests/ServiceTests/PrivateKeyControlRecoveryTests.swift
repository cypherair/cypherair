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
                service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Self.pendingEnvelopeSeed
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount
        ))

        let secondSummary = authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: [fingerprint])

        XCTAssertEqual(secondSummary?.outcomes, [.noActionSafe])
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
        XCTAssertEqual(authManager.currentMode, .highSecurity)
    }

    func test_rewrapRecovery_commitRequired_softwareOnlyEnumerationPersistsTargetMode() throws {
        // Regression pin (P7D): the post-unlock recovery call site passes
        // software-custody fingerprints only. With that contract honored, an
        // interrupted commit-required switch on a mixed population (the
        // device-bound key is simply absent from the list) must complete:
        // target mode persisted, journal cleared.
        let keychain = MockKeychain()
        let softwareFingerprint = "mixed-software-\(UUID().uuidString)"
        try savePendingRecoveryBundle(in: keychain, fingerprint: softwareFingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(
            mode: .standard,
            journal: PrivateKeyControlRecoveryJournal(
                rewrapTargetMode: .highSecurity,
                rewrapPhase: .commitRequired
            )
        )
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: [softwareFingerprint]
        )

        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe])
        XCTAssertEqual(authManager.currentMode, .highSecurity)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
        XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapPhase)
    }

    func test_rewrapRecovery_bundlelessFingerprintBlocksTargetModePersistence() throws {
        // Contract pin (P7D): a fingerprint with no SE-wrapped bundles — the
        // shape of a device-bound Secure Enclave custody key — classifies as
        // unrecoverable and blocks target-mode persistence. This is WHY every
        // caller must pre-filter to software custody; if this behavior ever
        // changes, revisit the call-site filters.
        let keychain = MockKeychain()
        let softwareFingerprint = "mixed-software-\(UUID().uuidString)"
        let bundlelessFingerprint = "mixed-device-bound-\(UUID().uuidString)"
        try savePendingRecoveryBundle(in: keychain, fingerprint: softwareFingerprint)

        let privateKeyControlStore = InMemoryPrivateKeyControlStore(
            mode: .standard,
            journal: PrivateKeyControlRecoveryJournal(
                rewrapTargetMode: .highSecurity,
                rewrapPhase: .commitRequired
            )
        )
        let authManager = makeRecoveryAuthenticationManager(
            keychain: keychain,
            privateKeyControlStore: privateKeyControlStore
        )

        let summary = authManager.checkAndRecoverFromInterruptedRewrap(
            fingerprints: [softwareFingerprint, bundlelessFingerprint]
        )

        XCTAssertEqual(summary?.outcomes, [.promotedPendingSafe, .unrecoverable])
        XCTAssertEqual(
            authManager.currentMode,
            .standard,
            "An unrecoverable entry must block target-mode persistence — the failure mode the custody filter prevents."
        )
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
                service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Self.permanentEnvelopeSeed
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint),
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
                service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ),
            Self.pendingEnvelopeSeed
        )
        XCTAssertFalse(keychain.exists(
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint),
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
                    service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
                    account: KeychainConstants.defaultAccount
                ),
                Self.pendingEnvelopeSeed
            )
            XCTAssertFalse(keychain.exists(
                service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint),
                account: KeychainConstants.defaultAccount
            ))
        }
    }

    // The former `test_rewrapRecovery_commitRequiredPartialPending_keepsJournalAndFailsClosed`
    // was removed: the single-row private-key envelope makes a partially-written pending
    // bundle structurally impossible (a row is atomically present or absent), so the
    // `(.complete, .partial)` commit-required arm it exercised is now unreachable.
    // Decode-time fail-closed behavior for a corrupt/undecodable envelope row is covered
    // by `PrivateKeyEnvelopeTests`.

    func test_postUnlockRecoveryWarningBuilder_surfacesOnlyUnsafeOutcomes() {
        // The builder surfaces a warning only for unsafe outcomes, and maps
        // distinct unsafe outcomes to distinct user-facing text. Guarded through
        // nil-ness and outcome differentiation, not the exact localized copy.
        let retryableWarning = AppContainer.postUnlockRecoveryLoadWarning(
            rewrapSummary: KeyMigrationRecoverySummary(outcomes: [.noActionSafe, .retryableFailure]),
            modifyExpiryOutcome: nil
        )
        XCTAssertNotNil(retryableWarning)

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
        XCTAssertNotEqual(
            retryableWarning, unrecoverableWarning,
            "Retryable and unrecoverable outcomes must surface distinct warnings."
        )

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
        // Assert the actual produced key warning survived — not a prose substring.
        XCTAssertTrue(warning.contains(try XCTUnwrap(keyWarning)))
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
        // The warning path surfaced a recovery warning (non-nil) while still
        // resyncing config — the exact copy is not the contract here.
        XCTAssertNotNil(config.postUnlockRecoveryLoadWarning)
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

    private static let permanentEnvelopeSeed = Data("permanent-envelope".utf8)
    private static let pendingEnvelopeSeed = Data("pending-envelope".utf8)

    private func savePermanentRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        try keychain.save(
            Self.permanentEnvelopeSeed,
            service: KeychainConstants.privateKeyEnvelopeService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }

    private func savePendingRecoveryBundle(
        in keychain: MockKeychain,
        fingerprint: String
    ) throws {
        try keychain.save(
            Self.pendingEnvelopeSeed,
            service: KeychainConstants.pendingPrivateKeyEnvelopeService(fingerprint: fingerprint),
            account: KeychainConstants.defaultAccount,
            accessControl: nil
        )
    }
}
