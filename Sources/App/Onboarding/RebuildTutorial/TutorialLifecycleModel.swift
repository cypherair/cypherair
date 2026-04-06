import Foundation
#if canImport(XCTest) && canImport(CypherAir)
@testable import CypherAir
#endif

struct TutorialRuntimeArtifacts {
    var aliceIdentity: PGPKeyIdentity?
    var bobIdentity: PGPKeyIdentity?
    var bobArmoredPublicKey: String?
    var bobContact: Contact?
    var encryptedMessage: String?
    var parseResult: DecryptionService.Phase1Result?
    var decryptedMessage: String?
    var decryptedVerification: SignatureVerification?
    var backupArmoredKey: String?
    var authMode: AuthenticationMode = .standard
}

struct TutorialRuntimeSession {
    let id = TutorialSessionID()
    let layer: TutorialLayerID
    var seededModule: TutorialModuleID?
    let container: TutorialSandboxContainer
    var artifacts = TutorialRuntimeArtifacts()
}

@MainActor
@Observable
final class TutorialLifecycleModel {
    enum AuthContinuation {
        case decryptMessage
        case enableHighSecurity
    }

    weak var appConfiguration: AppConfiguration?

    let launchOrigin: TutorialLaunchOrigin
    let capabilityPolicy = TutorialCapabilityPolicy()
    private let guidanceModel = TutorialGuidanceModel()

    private(set) var surface: TutorialSurface = .hub
    private(set) var lifecycleState: TutorialLifecycleState = .notStarted
    private(set) var activeLayer: TutorialLayerID?
    private(set) var activeModule: TutorialModuleID?
    private(set) var activeSession: TutorialRuntimeSession?
    private(set) var coreCompletedModules: Set<TutorialModuleID> = []
    private(set) var currentGuidance: TutorialGuidancePayload?

    var pendingAuthContinuation: AuthContinuation?
    var isLeaveConfirmationPresented = false
    var isGuidanceRailVisible = true
    var errorMessage: String?

    init(launchOrigin: TutorialLaunchOrigin) {
        self.launchOrigin = launchOrigin
    }

    func configure(appConfiguration: AppConfiguration) {
        self.appConfiguration = appConfiguration
        appConfiguration.normalizeGuidedTutorialModulePersistence()
    }

    var canShowAdvancedModules: Bool {
        hasCompletedCurrentCoreTutorial
    }

    var hasCompletedCurrentCoreTutorial: Bool {
        appConfiguration?.hasCompletedCurrentGuidedTutorialVersion == true
    }

    var completedAdvancedModules: Set<TutorialModuleID> {
        guard let appConfiguration else { return [] }
        return appConfiguration.completedGuidedTutorialModulesCurrentVersion
    }

    var nextCoreModule: TutorialModuleID? {
        TutorialModuleID.coreModules.first { !coreCompletedModules.contains($0) }
    }

    func isModuleUnlocked(_ module: TutorialModuleID) -> Bool {
        switch module.layer {
        case .core:
            if hasCompletedCurrentCoreTutorial {
                return true
            }
            guard let index = TutorialModuleID.coreModules.firstIndex(of: module) else { return false }
            if index == 0 {
                return true
            }
            return TutorialModuleID.coreModules[..<index].allSatisfy { coreCompletedModules.contains($0) }
        case .advanced:
            guard hasCompletedCurrentCoreTutorial else { return false }
            return module.prerequisiteModules.allSatisfy { completedAdvancedModules.contains($0) }
        }
    }

    func isModuleCompleted(_ module: TutorialModuleID) -> Bool {
        switch module.layer {
        case .core:
            if hasCompletedCurrentCoreTutorial {
                return true
            }
            return coreCompletedModules.contains(module)
        case .advanced:
            return completedAdvancedModules.contains(module)
        }
    }

    func resetCurrentTutorialSession() {
        activeSession?.container.cleanup()
        activeSession = nil
        activeLayer = nil
        activeModule = nil
        surface = .hub
        lifecycleState = hasCompletedCurrentCoreTutorial ? .coreFinished : .notStarted
        coreCompletedModules = []
        errorMessage = nil
        pendingAuthContinuation = nil
        currentGuidance = nil
        isLeaveConfirmationPresented = false
        isGuidanceRailVisible = true
    }

    func startCoreTutorial() async {
        do {
            var session = try TutorialRuntimeSession(layer: .core, seededModule: .sandbox, container: TutorialSandboxContainer())
            try await seedCoreSessionIfNeeded(&session)
            activeSession?.container.cleanup()
            activeSession = session
            activeLayer = .core
            activeModule = .sandbox
            surface = .workspace(.sandbox)
            lifecycleState = .coreInProgress
            errorMessage = nil
            currentGuidance = guidanceModel.payload(for: .sandbox, session: activeSession, pendingAuthContinuation: pendingAuthContinuation)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func openModule(_ module: TutorialModuleID) async {
        guard isModuleUnlocked(module) else { return }

        switch module.layer {
        case .core:
            if activeSession?.layer != .core {
                await startCoreTutorial()
            }
            guard activeSession != nil else { return }
            activeLayer = .core
            activeModule = module
            surface = .workspace(module)
            lifecycleState = coreCompletedModules.count == TutorialModuleID.coreModules.count ? .coreStepsCompleted : .coreInProgress
            currentGuidance = guidanceModel.payload(for: module, session: activeSession, pendingAuthContinuation: pendingAuthContinuation)
        case .advanced:
            do {
                var session = try TutorialRuntimeSession(layer: .advanced, seededModule: module, container: TutorialSandboxContainer())
                try await seedAdvancedSessionIfNeeded(&session, for: module)
                activeSession?.container.cleanup()
                activeSession = session
                activeLayer = .advanced
                activeModule = module
                surface = .workspace(module)
                lifecycleState = .moduleInProgress(module)
                errorMessage = nil
                currentGuidance = guidanceModel.payload(for: module, session: activeSession, pendingAuthContinuation: pendingAuthContinuation)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    func returnToHub() {
        pendingAuthContinuation = nil
        surface = .hub
        activeModule = nil
        isLeaveConfirmationPresented = false
        currentGuidance = nil

        if hasCompletedCurrentCoreTutorial {
            lifecycleState = .coreFinished
        } else if activeSession?.layer == .core {
            lifecycleState = coreCompletedModules.count == TutorialModuleID.coreModules.count ? .coreStepsCompleted : .coreInProgress
        } else {
            lifecycleState = .notStarted
        }
    }

    func requestLeaveTutorial() {
        guard activeSession != nil || !coreCompletedModules.isEmpty else {
            isLeaveConfirmationPresented = false
            return
        }
        isLeaveConfirmationPresented = true
    }

    func dismissLeaveConfirmation() {
        isLeaveConfirmationPresented = false
    }

    func acknowledgeSandbox() {
        completeCoreModule(.sandbox)
    }

    func createDemoIdentity(name: String, email: String) async {
        guard var session = activeSession else { return }

        do {
            let identity = try await session.container.keyManagement.generateKey(
                name: name,
                email: email,
                expirySeconds: nil,
                profile: .universal,
                authMode: .standard
            )
            session.artifacts.aliceIdentity = identity
            activeSession = session
            completeCoreModule(.demoIdentity)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func addDemoContact() throws {
        guard var session = activeSession,
              let bobArmoredPublicKey = session.artifacts.bobArmoredPublicKey else { return }

        let result = try session.container.contactService.addContact(publicKeyData: Data(bobArmoredPublicKey.utf8))
        switch result {
        case .added(let contact), .duplicate(let contact):
            session.artifacts.bobContact = contact
            activeSession = session
            completeCoreModule(.demoContact)
        case .keyUpdateDetected(let newContact, _, let keyData):
            try session.container.contactService.confirmKeyUpdate(
                existingFingerprint: newContact.fingerprint,
                newContact: newContact,
                keyData: keyData
            )
            session.artifacts.bobContact = newContact
            activeSession = session
            completeCoreModule(.demoContact)
        }
    }

    func encryptDemoMessage(_ plaintext: String) async {
        guard var session = activeSession,
              let aliceIdentity = session.artifacts.aliceIdentity,
              let bobContact = session.artifacts.bobContact else { return }

        do {
            let ciphertext = try await session.container.encryptionService.encryptText(
                plaintext,
                recipientFingerprints: [bobContact.fingerprint],
                signWithFingerprint: aliceIdentity.fingerprint,
                encryptToSelf: true,
                encryptToSelfFingerprint: aliceIdentity.fingerprint
            )
            session.artifacts.encryptedMessage = String(data: ciphertext, encoding: .utf8)
            activeSession = session
            completeCoreModule(.encryptMessage)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func inspectRecipients() async {
        guard var session = activeSession,
              let encryptedMessage = session.artifacts.encryptedMessage else { return }

        do {
            let parseResult = try await session.container.decryptionService.parseRecipients(
                ciphertext: Data(encryptedMessage.utf8)
            )
            session.artifacts.parseResult = parseResult
            activeSession = session
            refreshGuidance()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func beginDecryptContinuation() {
        pendingAuthContinuation = .decryptMessage
        refreshGuidance()
    }

    func beginHighSecurityContinuation() {
        pendingAuthContinuation = .enableHighSecurity
        refreshGuidance()
    }

    func cancelAuthContinuation() {
        pendingAuthContinuation = nil
        refreshGuidance()
    }

    func confirmAuthContinuation() async {
        switch pendingAuthContinuation {
        case .decryptMessage:
            await decryptMessage()
        case .enableHighSecurity:
            await enableHighSecurity()
        case nil:
            break
        }
    }

    func createTutorialBackup(passphrase: String) async {
        guard var session = activeSession,
              let fingerprint = session.artifacts.aliceIdentity?.fingerprint else { return }

        do {
            let backup = try await session.container.keyManagement.exportKey(
                fingerprint: fingerprint,
                passphrase: passphrase
            )
            session.artifacts.backupArmoredKey = String(data: backup, encoding: .utf8)
            activeSession = session
            completeAdvancedModule(.backupKey)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func completeCoreFinish(stayInTutorial: Bool) {
        guard let appConfiguration else { return }

        appConfiguration.markGuidedTutorialCompletedCurrentVersion()
        activeSession?.container.cleanup()
        activeSession = nil
        activeLayer = nil
        activeModule = nil
        currentGuidance = nil
        pendingAuthContinuation = nil
        lifecycleState = .coreFinished

        if stayInTutorial {
            surface = .hub
        } else {
            surface = .completion(.core)
        }
    }

    func finishAdvancedModule() {
        activeSession?.container.cleanup()
        activeSession = nil
        activeLayer = nil
        activeModule = nil
        currentGuidance = nil
        pendingAuthContinuation = nil
        surface = .hub
        lifecycleState = hasCompletedCurrentCoreTutorial ? .coreFinished : .notStarted
    }

    private func decryptMessage() async {
        guard var session = activeSession,
              let parseResult = session.artifacts.parseResult else { return }

        do {
            let decryptResult = try await session.container.decryptionService.decrypt(phase1: parseResult)
            session.artifacts.decryptedMessage = String(data: decryptResult.plaintext, encoding: .utf8)
            session.artifacts.decryptedVerification = decryptResult.signature
            activeSession = session
            pendingAuthContinuation = nil
            completeCoreModule(.decryptAndVerify)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func enableHighSecurity() async {
        guard var session = activeSession,
              let fingerprint = session.artifacts.aliceIdentity?.fingerprint else { return }

        do {
            try await session.container.authManager.switchMode(
                to: .highSecurity,
                fingerprints: [fingerprint],
                hasBackup: true,
                authenticator: session.container.mockAuthenticator
            )
            session.container.config.authMode = .highSecurity
            session.artifacts.authMode = .highSecurity
            activeSession = session
            pendingAuthContinuation = nil
            completeAdvancedModule(.enableHighSecurity)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func completeCoreModule(_ module: TutorialModuleID) {
        coreCompletedModules.insert(module)
        pendingAuthContinuation = nil

        if module == .decryptAndVerify {
            lifecycleState = .coreStepsCompleted
            surface = .completion(.core)
        } else {
            lifecycleState = .coreInProgress
            refreshGuidance(for: module)
        }
    }

    private func completeAdvancedModule(_ module: TutorialModuleID) {
        appConfiguration?.markGuidedTutorialModuleCompleted(module.rawValue)
        lifecycleState = .moduleCompleted(module)
        surface = .completion(.module(module))
        refreshGuidance(for: module)
    }

    private func refreshGuidance(for module: TutorialModuleID? = nil) {
        guard let active = module ?? activeModule else {
            currentGuidance = nil
            return
        }
        currentGuidance = guidanceModel.payload(for: active, session: activeSession, pendingAuthContinuation: pendingAuthContinuation)
    }

    private func seedCoreSessionIfNeeded(_ session: inout TutorialRuntimeSession) async throws {
        guard session.artifacts.bobIdentity == nil else { return }

        let bob = try await session.container.keyManagement.generateKey(
            name: "Bob Demo",
            email: "bob@demo.invalid",
            expirySeconds: nil,
            profile: .universal,
            authMode: .standard
        )
        session.artifacts.bobIdentity = bob
        let armored = try session.container.keyManagement.exportPublicKey(fingerprint: bob.fingerprint)
        session.artifacts.bobArmoredPublicKey = String(data: armored, encoding: .utf8)
    }

    private func seedAdvancedSessionIfNeeded(
        _ session: inout TutorialRuntimeSession,
        for module: TutorialModuleID
    ) async throws {
        switch module {
        case .backupKey:
            let alice = try await session.container.keyManagement.generateKey(
                name: "Alice Demo",
                email: "alice@demo.invalid",
                expirySeconds: nil,
                profile: .universal,
                authMode: .standard
            )
            session.artifacts.aliceIdentity = alice
        case .enableHighSecurity:
            let alice = try await session.container.keyManagement.generateKey(
                name: "Alice Demo",
                email: "alice@demo.invalid",
                expirySeconds: nil,
                profile: .universal,
                authMode: .standard
            )
            session.artifacts.aliceIdentity = alice
            let backup = try await session.container.keyManagement.exportKey(
                fingerprint: alice.fingerprint,
                passphrase: "tutorial-backup-passphrase"
            )
            session.artifacts.backupArmoredKey = String(data: backup, encoding: .utf8)
        default:
            break
        }
    }
}
