import Foundation

@MainActor
@Observable
final class KeyGenerationScreenModel {
    typealias GenerateKeyAction = @MainActor (String, String?, UInt64?, PGPKeyConfiguration.Identity) async throws -> PGPKeyIdentity
    typealias PostGenerationPromptAction = @MainActor (PGPKeyIdentity) -> Void

    let configuration: KeyGenerationView.Configuration
    let expiryOptions = [12, 24, 36, 48, 60]

    private let generateKeyAction: GenerateKeyAction
    private let postGenerationPromptAction: PostGenerationPromptAction?
    private let capabilityResolver: PGPKeyCapabilityResolver
    private let isSecureEnclaveGenerationAvailable: Bool
    private var generationTask: Task<Void, Never>?
    private var generationToken: UInt64 = 0

    var name = ""
    var email = ""
    var selectedFamily: PGPKeyConfiguration.Identity = .compatibleSoftwareV4
    var expiryMonths = 24
    var isGenerating = false
    var deviceBoundCommitmentPending = false
    var presentedFamilyDetail: PGPKeyConfiguration.Identity?
    var error: CypherAirError?
    var showError = false
    var generatedIdentity: PGPKeyIdentity?

    init(
        keyManagement: KeyManagementService,
        configuration: KeyGenerationView.Configuration,
        postGenerationPromptAction: PostGenerationPromptAction? = nil,
        generateKeyAction: GenerateKeyAction? = nil,
        capabilityResolver: PGPKeyCapabilityResolver = PGPKeyCapabilityResolver(),
        isSecureEnclaveGenerationAvailable: Bool? = nil
    ) {
        self.configuration = configuration
        self.postGenerationPromptAction = postGenerationPromptAction
        self.capabilityResolver = capabilityResolver
        self.isSecureEnclaveGenerationAvailable = isSecureEnclaveGenerationAvailable
            ?? keyManagement.isSecureEnclaveCustodyGenerationAvailable
        self.generateKeyAction = generateKeyAction ?? { name, email, expirySeconds, family in
            if let profile = family.equivalentSoftwareProfile {
                return try await keyManagement.generateKey(
                    name: name,
                    email: email,
                    expirySeconds: expirySeconds,
                    profile: profile
                )
            }
            return try await keyManagement.generateSecureEnclaveCustodyKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                configurationIdentity: family
            )
        }
    }

    /// Families the generation form offers, in stable presentation order.
    /// Software families are always offered; device-bound families require both a
    /// wired Secure Enclave generation service and the capability resolver's policy.
    var availableFamilies: [PGPKeyConfiguration.Identity] {
        PGPKeyConfiguration.Identity.orderedFamilies.filter { family in
            // Portable Post-Quantum is implemented but not yet product-exposed;
            // the campaign #567 Phase 4 exposure decision flips this.
            guard family != .postQuantumSoftwareV6 else {
                return false
            }
            guard family.isDeviceBoundFamily else {
                return true
            }
            guard isSecureEnclaveGenerationAvailable else {
                return false
            }
            return capabilityResolver.support(
                for: .generate,
                configuration: family.configuration,
                custody: .appleSecureEnclavePrivateOperations
            ) == .supported
        }
    }

    var generateButtonDisabled: Bool {
        name.trimmingCharacters(in: .whitespaces).isEmpty || isGenerating
    }

    func handleAppear() {
        if name.isEmpty, let prefilledName = configuration.prefilledName {
            name = prefilledName
        }
        if email.isEmpty, let prefilledEmail = configuration.prefilledEmail {
            email = prefilledEmail
        }
        if let lockedFamily = configuration.lockedFamily {
            selectedFamily = lockedFamily
        }
        if let lockedExpiryMonths = configuration.lockedExpiryMonths {
            expiryMonths = lockedExpiryMonths
        }
    }

    func selectFamily(_ family: PGPKeyConfiguration.Identity) {
        guard configuration.lockedFamily == nil else {
            return
        }
        selectedFamily = family
    }

    func presentFamilyDetail(_ family: PGPKeyConfiguration.Identity) {
        presentedFamilyDetail = family
    }

    func dismissFamilyDetail() {
        presentedFamilyDetail = nil
    }

    /// Device-bound families never start generating here: the user must pass the
    /// commitment sheet first, every time, so the portability consequence is
    /// acknowledged before the key exists.
    func generate() {
        guard !selectedFamily.isDeviceBoundFamily else {
            deviceBoundCommitmentPending = true
            return
        }
        startGeneration()
    }

    func confirmDeviceBoundGeneration() {
        guard deviceBoundCommitmentPending else {
            return
        }
        deviceBoundCommitmentPending = false
        startGeneration()
    }

    func cancelDeviceBoundCommitment() {
        deviceBoundCommitmentPending = false
    }

    func handleContentClearGenerationChange() {
        cancelGenerationAndClearTransientInput()
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func dismissGeneratedIdentity() {
        generatedIdentity = nil
    }

    private func startGeneration() {
        generationTask?.cancel()
        generationToken &+= 1
        let token = generationToken
        isGenerating = true
        error = nil
        showError = false

        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedEmail = email.trimmingCharacters(in: .whitespaces)
        let selectedFamily = selectedFamily
        let expiryDate = Calendar.current.date(
            byAdding: .month,
            value: expiryMonths,
            to: Date()
        ) ?? Date()
        let expirySeconds = UInt64(max(0, expiryDate.timeIntervalSinceNow))

        generationTask = Task { @MainActor [weak self, token] in
            guard let self else { return }
            defer {
                if token == self.generationToken {
                    self.isGenerating = false
                    self.generationTask = nil
                }
            }

            do {
                let identity = try await self.generateKeyAction(
                    trimmedName,
                    trimmedEmail.isEmpty ? nil : trimmedEmail,
                    expirySeconds,
                    selectedFamily
                )
                try Task.checkCancellation()
                guard token == self.generationToken else {
                    return
                }

                self.configuration.onGenerated?(identity)
                self.handlePostGeneration(identity)
            } catch {
                guard !Self.shouldIgnore(error), token == self.generationToken else {
                    return
                }
                self.error = CypherAirError.from(error) { .keyGenerationFailed(reason: $0) }
                self.showError = true
            }
        }
    }

    private func handlePostGeneration(_ identity: PGPKeyIdentity) {
        switch configuration.postGenerationBehavior {
        case .showPrompt:
            if let postGenerationPromptAction {
                postGenerationPromptAction(identity)
            } else {
                generatedIdentity = identity
            }
        case .externalPrompt:
            configuration.onPostGenerationPromptRequested?(identity)
        case .suppressPrompt:
            break
        }
    }

    private func cancelGenerationAndClearTransientInput() {
        generationTask?.cancel()
        generationToken &+= 1
        generationTask = nil
        isGenerating = false
        deviceBoundCommitmentPending = false
        presentedFamilyDetail = nil
        clearTransientInput()
    }

    private func clearTransientInput() {
        name = ""
        email = ""
        generatedIdentity = nil
    }

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        return false
    }
}
