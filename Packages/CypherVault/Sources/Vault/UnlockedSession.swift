import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import os

/// The two session values and the identity wrapping key, alive from unlock to
/// relock. Relock erases the values; every later call throws `.locked`.
public final class UnlockedSession: @unchecked Sendable {
    private struct Values {
        var wrappingRootKey: SymmetricKey
        var identityCredential: SensitiveKeyBox
    }

    public let identityWrappingKeyBlob: Data
    public let identityWrappingPublicKeyX963: Data
    private let enclave: any Enclave
    private let authenticator: any Authenticator
    private let values: OSAllocatedUnfairLock<Values?>

    init(
        rootSecret: borrowing SensitiveBuffer,
        identityWrappingKeyBlob: Data,
        identityWrappingPublicKeyX963: Data,
        enclave: any Enclave,
        authenticator: any Authenticator
    ) {
        self.identityWrappingKeyBlob = identityWrappingKeyBlob
        self.identityWrappingPublicKeyX963 = identityWrappingPublicKeyX963
        self.enclave = enclave
        self.authenticator = authenticator
        values = OSAllocatedUnfairLock(initialState: Values(
            wrappingRootKey: RootDerivations.wrappingRootKey(rootSecret: rootSecret),
            identityCredential: SensitiveKeyBox(RootDerivations.identityCredential(rootSecret: rootSecret))
        ))
    }

    public var isLocked: Bool { values.withLock { $0 == nil } }

    /// One protected-data domain's key.
    public func domainKey(_ domain: String) throws(VaultError) -> SymmetricKey {
        guard let root = values.withLock({ $0?.wrappingRootKey }) else { throw .locked }
        return RootDerivations.domainKey(wrappingRootKey: root, domain: domain)
    }

    /// Runs `body` with the identity credential, for enclave keys the stores own.
    public func withIdentityCredential<R>(_ body: (borrowing SensitiveBuffer) throws -> R) throws -> R {
        guard let box = values.withLock({ $0?.identityCredential }) else { throw VaultError.locked }
        return try body(box.buffer)
    }

    /// Asks for the one approval of one private-key operation: a fresh context
    /// with no biometric reuse, evaluated once for `kind`, then barred from
    /// interaction. Biometrics offer no passcode fallback.
    public func approve(_ kind: ApprovalKind, reason: String) async throws(VaultError) -> OperationApproval {
        guard !isLocked else { throw .locked }
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        if kind == .biometrics {
            context.localizedFallbackTitle = ""
        }
        do throws(VaultError) {
            switch kind {
            case .presence: try await authenticator.authenticate(context: context, reason: reason)
            case .biometrics: try await authenticator.authenticateBiometrics(context: context, reason: reason)
            }
            guard !isLocked else { throw .locked }
        } catch {
            context.invalidate()
            throw error
        }
        context.interactionNotAllowed = true
        return OperationApproval(kind: kind, context: context)
    }

    /// Seals `plaintext` against the identity wrapping key. Pure software, no prompt.
    public func sealForIdentity(
        plaintext: borrowing SensitiveBuffer,
        kind: SealedPayloadKind,
        associatedData: Data
    ) throws(VaultError) -> EnclaveSealedEnvelope {
        guard !isLocked else { throw .locked }
        do {
            return try EnclaveSealedEnvelopeCodec.seal(
                plaintext: plaintext,
                kind: kind,
                associatedData: associatedData,
                sealingKeyBlob: identityWrappingKeyBlob,
                sealingPublicKeyX963: identityWrappingPublicKeyX963
            )
        } catch {
            throw .internalFailure("seal failed")
        }
    }

    /// Opens an identity envelope: reconstructs the identity wrapping key with
    /// the approval's context and the identity credential, runs the agreement in
    /// the enclave, then opens in software. Blocking; call off the main actor.
    package func openIdentityEnvelope(
        _ envelope: EnclaveSealedEnvelope,
        kind: SealedPayloadKind,
        approval: OperationApproval
    ) throws(VaultError) -> SensitiveBuffer {
        guard envelope.sealingKeyBlob == identityWrappingKeyBlob else { throw .sealedRootCorrupt }
        let shared: SharedSecret
        do {
            shared = try withIdentityCredential { credential in
                let key = try enclave.keyAgreementKey(from: identityWrappingKeyBlob, credential: credential, context: approval.context)
                return try key.sharedSecret(withEphemeralPublicKeyX963: envelope.ephemeralPublicKeyX963)
            }
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.fromEnclaveOperation(error)
        }
        do {
            return try EnclaveSealedEnvelopeCodec.open(envelope, sharedSecret: shared, expectedKind: kind)
        } catch {
            throw .internalFailure("identity envelope did not open")
        }
    }

    /// Erases both session values. Idempotent.
    public func relock() {
        values.withLock { $0 = nil }
    }
}
