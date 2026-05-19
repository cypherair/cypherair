import Foundation

@MainActor
@Observable
final class KeyGenerationScreenModel {
    typealias GenerateKeyAction = @MainActor (String, String?, UInt64?, PGPKeyProfile) async throws -> PGPKeyIdentity
    typealias PostGenerationPromptAction = @MainActor (PGPKeyIdentity) -> Void

    let configuration: KeyGenerationView.Configuration
    let expiryOptions = [12, 24, 36, 48, 60]

    private let generateKeyAction: GenerateKeyAction
    private let postGenerationPromptAction: PostGenerationPromptAction?
    private var generationTask: Task<Void, Never>?
    private var generationToken: UInt64 = 0

    var name = ""
    var email = ""
    var profile: PGPKeyProfile = .universal
    var expiryMonths = 24
    var isGenerating = false
    var error: CypherAirError?
    var showError = false
    var generatedIdentity: PGPKeyIdentity?

    init(
        keyManagement: KeyManagementService,
        configuration: KeyGenerationView.Configuration,
        postGenerationPromptAction: PostGenerationPromptAction? = nil,
        generateKeyAction: GenerateKeyAction? = nil
    ) {
        self.configuration = configuration
        self.postGenerationPromptAction = postGenerationPromptAction
        self.generateKeyAction = generateKeyAction ?? { name, email, expirySeconds, profile in
            try await keyManagement.generateKey(
                name: name,
                email: email,
                expirySeconds: expirySeconds,
                profile: profile
            )
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
        if let lockedProfile = configuration.lockedProfile {
            profile = lockedProfile
        }
        if let lockedExpiryMonths = configuration.lockedExpiryMonths {
            expiryMonths = lockedExpiryMonths
        }
    }

    func generate() {
        generationTask?.cancel()
        generationToken &+= 1
        let token = generationToken
        isGenerating = true
        error = nil
        showError = false

        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedEmail = email.trimmingCharacters(in: .whitespaces)
        let selectedProfile = profile
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
                    selectedProfile
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
