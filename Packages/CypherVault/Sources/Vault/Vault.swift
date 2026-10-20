import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Security

/// The sealed root, the unlock chain, and the workflows around them.
///
/// One sealed root, one wrapping key, one passphrase. The wrapping key's
/// application password is the stretched passphrase; the root secret it seals
/// is random and yields the session values by derivation. Every enclave call
/// that can prompt runs off the caller's actor.
public struct Vault: Sendable {
    public let enclave: any Enclave
    public let rootRows: any RowStore
    public let stretcher: any PassphraseStretcher
    public let authenticator: any Authenticator

    public init(
        enclave: any Enclave,
        rootRows: any RowStore,
        stretcher: any PassphraseStretcher,
        authenticator: any Authenticator
    ) {
        self.enclave = enclave
        self.rootRows = rootRows
        self.stretcher = stretcher
        self.authenticator = authenticator
    }

    /// The one row that holds the sealed root.
    public static let sealedRootService = "com.cypherair.vault.sealed-root"
    public static let sealedRootAccount = "com.cypherair"

    /// Whether onboarding has completed on this device. Reads no secret and
    /// shows no prompt.
    public func sealedRootExists() throws(VaultError) -> Bool {
        try rootRows.read(account: Self.sealedRootAccount) != nil
    }

    /// Onboarding: one presence prompt, then a fresh root sealed under a new
    /// wrapping key whose password is the stretched passphrase, plus a new
    /// identity wrapping key whose password is the identity credential.
    public func bootstrap(passphrase: consuming SensitiveBuffer, reason: String) async throws(VaultError) -> UnlockedSession {
        guard enclave.isAvailable else { throw .enclaveUnavailable }
        guard try rootRows.read(account: Self.sealedRootAccount) == nil else { throw .internalFailure("a sealed root already exists") }
        let context = LAContext()
        defer { context.invalidate() }
        try await authenticator.authenticate(context: context, reason: reason)
        let result = try await Self.bootstrapWork(
            vault: self,
            passphrase: SensitiveKeyBox(passphrase),
            context: ContextCarrier(context: context)
        )
        try rootRows.write(account: Self.sealedRootAccount, data: result.encodedEnvelope)
        return result.session
    }

    /// Starts an unlock. The attempt owns one context: the first submission
    /// prompts for presence, a refused passphrase is retried on the same
    /// context without a second prompt.
    public func beginUnlock(reason: String) -> UnlockAttempt {
        UnlockAttempt(vault: self, reason: reason)
    }

    /// Proves the current passphrase, then reseals the same root under a new
    /// wrapping key whose password is the new stretched passphrase. One prompt,
    /// one atomic row update; nothing else on the device changes.
    public func changePassphrase(
        current: consuming SensitiveBuffer,
        new: consuming SensitiveBuffer,
        reason: String
    ) async throws(VaultError) {
        let sealed = try loadSealedRoot()
        let context = LAContext()
        defer { context.invalidate() }
        try await authenticator.authenticate(context: context, reason: reason)
        let encoded = try await Self.changePassphraseWork(
            vault: self,
            sealed: sealed,
            current: SensitiveKeyBox(current),
            new: SensitiveKeyBox(new),
            context: ContextCarrier(context: context)
        )
        try rootRows.write(account: Self.sealedRootAccount, data: encoded)
    }

    /// Deletes the sealed root. Every identity key on the device is unusable
    /// afterwards by construction; callers delete the rest.
    public func reset() throws(VaultError) {
        try rootRows.delete(account: Self.sealedRootAccount)
    }

    // MARK: - Chain

    struct SealedRoot: Sendable {
        let envelope: EnclaveSealedEnvelope
        let metadata: SealedRootMetadata
    }

    func loadSealedRoot() throws(VaultError) -> SealedRoot {
        guard let data = try rootRows.read(account: Self.sealedRootAccount) else { throw .noSealedRoot }
        let envelope: EnclaveSealedEnvelope
        do {
            envelope = try EnclaveSealedEnvelopeCodec.decode(data, expectedKind: .rootSecret)
        } catch {
            throw .sealedRootCorrupt
        }
        return SealedRoot(envelope: envelope, metadata: try SealedRootMetadata.decode(envelope.associatedData))
    }

    /// Stretches `passphrase`, presents it to the wrapping key, runs the
    /// agreement in the enclave, and opens the root. Blocking; off the caller's actor.
    @concurrent
    static func openRoot(
        vault: Vault,
        sealed: SealedRoot,
        passphrase: SensitiveKeyBox,
        context: ContextCarrier
    ) async throws(VaultError) -> SensitiveBuffer {
        let stretched = try vault.stretch(passphrase.buffer, salt: sealed.metadata.stretchSalt, parameters: sealed.metadata.stretchParameters)
        let shared: SharedSecret
        do {
            let key = try vault.enclave.keyAgreementKey(from: sealed.envelope.sealingKeyBlob, credential: stretched, context: context.context)
            shared = try key.sharedSecret(withEphemeralPublicKeyX963: sealed.envelope.ephemeralPublicKeyX963)
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.fromEnclaveOperation(error)
        }
        do {
            return try EnclaveSealedEnvelopeCodec.open(sealed.envelope, sharedSecret: shared, expectedKind: .rootSecret)
        } catch {
            throw .sealedRootCorrupt
        }
    }

    struct BootstrapResult: Sendable {
        let encodedEnvelope: Data
        let session: UnlockedSession
    }

    @concurrent
    static func bootstrapWork(
        vault: Vault,
        passphrase: SensitiveKeyBox,
        context: ContextCarrier
    ) async throws(VaultError) -> BootstrapResult {
        let root = try randomSecret(count: RootDerivations.rootSecretLength)
        let salt = try randomSalt()
        let stretched = try vault.stretch(passphrase.buffer, salt: salt, parameters: .current)
        let wrappingKey = try vault.makeKey(policy: .presenceAndPassword, credential: stretched, context: context.context)
        let identityCredential = RootDerivations.identityCredential(rootSecret: root)
        let identityKey = try vault.makeKey(policy: .presenceAndPassword, credential: identityCredential, context: context.context)
        let metadata = SealedRootMetadata(
            stretchSalt: salt,
            stretchParameters: .current,
            identityWrappingKeyBlob: identityKey.dataRepresentation,
            identityWrappingPublicKeyX963: identityKey.publicKeyX963
        )
        let encoded = try seal(root: root, metadata: metadata, wrappingKey: wrappingKey)
        let session = UnlockedSession(
            rootSecret: root,
            identityWrappingKeyBlob: metadata.identityWrappingKeyBlob,
            identityWrappingPublicKeyX963: metadata.identityWrappingPublicKeyX963,
            enclave: vault.enclave
        )
        return BootstrapResult(encodedEnvelope: encoded, session: session)
    }

    @concurrent
    static func changePassphraseWork(
        vault: Vault,
        sealed: SealedRoot,
        current: SensitiveKeyBox,
        new: SensitiveKeyBox,
        context: ContextCarrier
    ) async throws(VaultError) -> Data {
        let root = try await openRoot(vault: vault, sealed: sealed, passphrase: current, context: context)
        let salt = try randomSalt()
        let stretched = try vault.stretch(new.buffer, salt: salt, parameters: .current)
        let wrappingKey = try vault.makeKey(policy: .presenceAndPassword, credential: stretched, context: context.context)
        let metadata = SealedRootMetadata(
            stretchSalt: salt,
            stretchParameters: .current,
            identityWrappingKeyBlob: sealed.metadata.identityWrappingKeyBlob,
            identityWrappingPublicKeyX963: sealed.metadata.identityWrappingPublicKeyX963
        )
        return try seal(root: root, metadata: metadata, wrappingKey: wrappingKey)
    }

    static func seal(root: borrowing SensitiveBuffer, metadata: SealedRootMetadata, wrappingKey: any EnclaveKeyAgreementKey) throws(VaultError) -> Data {
        do {
            let envelope = try EnclaveSealedEnvelopeCodec.seal(
                plaintext: root,
                kind: .rootSecret,
                associatedData: try metadata.encoded(),
                sealingKeyBlob: wrappingKey.dataRepresentation,
                sealingPublicKeyX963: wrappingKey.publicKeyX963
            )
            return try EnclaveSealedEnvelopeCodec.encode(envelope)
        } catch let error as VaultError {
            throw error
        } catch {
            throw .internalFailure("root seal failed")
        }
    }

    func stretch(_ passphrase: borrowing SensitiveBuffer, salt: Data, parameters: UnlockStretchParameters) throws(VaultError) -> SensitiveBuffer {
        do {
            return try stretcher.stretch(passphrase: passphrase, salt: salt, parameters: parameters)
        } catch {
            throw .internalFailure("passphrase stretch failed")
        }
    }

    func makeKey(policy: EnclaveAccessPolicy, credential: borrowing SensitiveBuffer, context: LAContext) throws(VaultError) -> any EnclaveKeyAgreementKey {
        do {
            return try enclave.makeKeyAgreementKey(policy: policy, credential: credential, context: context)
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.fromEnclaveOperation(error)
        }
    }

    static func randomSecret(count: Int) throws(VaultError) -> SensitiveBuffer {
        try SensitiveBuffer(count: count) { (buffer) throws(VaultError) in
            guard SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!) == errSecSuccess else {
                throw .internalFailure("randomness unavailable")
            }
        }
    }

    static func randomSalt() throws(VaultError) -> Data {
        do { return try Randomness.bytes(count: UnlockStretchParameters.saltLength) } catch { throw .internalFailure("randomness unavailable") }
    }
}

/// Carries a context into work that runs off the caller's actor. The context is
/// used by exactly one chain and invalidated by its owner afterwards.
struct ContextCarrier: @unchecked Sendable {
    let context: LAContext
}

/// One unlock. Owns the context for its lifetime so a refused passphrase can be
/// retried without a second prompt.
public final class UnlockAttempt {
    private let vault: Vault
    private let reason: String
    private let context: LAContext
    private var authenticated = false
    private var finished = false

    init(vault: Vault, reason: String) {
        self.vault = vault
        self.reason = reason
        context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
    }

    /// Prompts for presence on the first call, then opens the root with
    /// `passphrase`. `.passphraseRejected` leaves the attempt open for a retry;
    /// success or `cancel()` ends it.
    public func submit(passphrase: consuming SensitiveBuffer) async throws(VaultError) -> UnlockedSession {
        guard !finished else { throw .internalFailure("unlock attempt already ended") }
        guard vault.enclave.isAvailable else { throw .enclaveUnavailable }
        let sealed = try vault.loadSealedRoot()
        if !authenticated {
            try await vault.authenticator.authenticate(context: context, reason: reason)
            authenticated = true
        }
        let root = try await Vault.openRoot(
            vault: vault,
            sealed: sealed,
            passphrase: SensitiveKeyBox(passphrase),
            context: ContextCarrier(context: context)
        )
        finished = true
        context.invalidate()
        return UnlockedSession(
            rootSecret: root,
            identityWrappingKeyBlob: sealed.metadata.identityWrappingKeyBlob,
            identityWrappingPublicKeyX963: sealed.metadata.identityWrappingPublicKeyX963,
            enclave: vault.enclave
        )
    }

    public func cancel() {
        finished = true
        context.invalidate()
    }
}
