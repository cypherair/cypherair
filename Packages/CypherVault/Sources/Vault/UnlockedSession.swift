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
    private let values: OSAllocatedUnfairLock<Values?>

    init(
        rootSecret: borrowing SensitiveBuffer,
        identityWrappingKeyBlob: Data,
        identityWrappingPublicKeyX963: Data,
        enclave: any Enclave
    ) {
        self.identityWrappingKeyBlob = identityWrappingKeyBlob
        self.identityWrappingPublicKeyX963 = identityWrappingPublicKeyX963
        self.enclave = enclave
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

    /// A fresh context for one private operation: no biometric reuse, and the
    /// enclave prompts for the key's constraint when the operation runs.
    public func operationContext() -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        return context
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
    /// `context` and the identity credential, runs the agreement in the enclave,
    /// then opens in software. Blocking while the enclave prompts; call off the
    /// main actor.
    public func openIdentityEnvelope(
        _ envelope: EnclaveSealedEnvelope,
        kind: SealedPayloadKind,
        context: LAContext
    ) throws(VaultError) -> SensitiveBuffer {
        guard envelope.sealingKeyBlob == identityWrappingKeyBlob else { throw .sealedRootCorrupt }
        let shared: SharedSecret
        do {
            shared = try withIdentityCredential { credential in
                let key = try enclave.keyAgreementKey(from: identityWrappingKeyBlob, credential: credential, context: context)
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
