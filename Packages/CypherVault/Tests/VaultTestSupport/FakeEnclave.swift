import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Vault
import os

/// The software enclave with a record of every policy it was asked for and an
/// availability switch.
public final class FakeEnclave: Enclave, @unchecked Sendable {
    private let inner = SoftwareEnclave()
    private let state = OSAllocatedUnfairLock(initialState: (created: [EnclaveAccessPolicy](), available: true))

    public init() {}

    public var isAvailable: Bool {
        get { state.withLock { $0.available } }
        set { state.withLock { $0.available = newValue } }
    }

    public var createdPolicies: [EnclaveAccessPolicy] { state.withLock { $0.created } }

    public func makeKeyAgreementKey(policy: EnclaveAccessPolicy, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveKeyAgreementKey {
        let key = try inner.makeKeyAgreementKey(policy: policy, credential: credential, context: context)
        state.withLock { $0.created.append(policy) }
        return key
    }

    public func keyAgreementKey(from blob: Data, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveKeyAgreementKey {
        try inner.keyAgreementKey(from: blob, credential: credential, context: context)
    }

    public func makeCustodyKey(type: CustodyKeyType, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey {
        let key = try inner.makeCustodyKey(type: type, credential: credential, context: context)
        state.withLock { $0.created.append(type.policy) }
        return key
    }

    public func makeCredentialFreeCustodyKey(type: CustodyKeyType, context: LAContext) throws -> any EnclaveCustodyKey {
        let key = try inner.makeCredentialFreeCustodyKey(type: type, context: context)
        state.withLock { $0.created.append(type.policy) }
        return key
    }

    public func custodyKey(type: CustodyKeyType, from blob: Data, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey {
        try inner.custodyKey(type: type, from: blob, credential: credential, context: context)
    }

    public func credentialFreeCustodyKey(type: CustodyKeyType, from blob: Data, context: LAContext) throws -> any EnclaveCustodyKey {
        try inner.credentialFreeCustodyKey(type: type, from: blob, context: context)
    }
}

public extension InMemoryRowStore {
    /// Flips one byte in the middle of the row's value.
    func corrupt(account: String) {
        guard var data = try? read(account: account), !data.isEmpty else { return }
        let attribute = (try? accounts())?.first { $0.account == account }?.attribute
        data[data.count / 2] ^= 0xFF
        try? write(account: account, data: data, attribute: attribute)
    }
}

public typealias FakeStretcher = SandboxStretcher

/// Presence that is never shown: it records each request by its kind and
/// fails with `failure` when one is set.
public final class CountingAuthenticator: Authenticator, @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (presence: 0, biometrics: 0, failure: VaultError?.none))

    public init() {}

    public var failure: VaultError? {
        get { state.withLock { $0.failure } }
        set { state.withLock { $0.failure = newValue } }
    }

    public var prompts: Int { state.withLock { $0.presence + $0.biometrics } }
    public var biometricPrompts: Int { state.withLock { $0.biometrics } }

    public func authenticate(context: LAContext, reason: String) async throws(VaultError) {
        let failure = state.withLock { state in
            state.presence += 1
            return state.failure
        }
        if let failure { throw failure }
    }

    public func authenticateBiometrics(context: LAContext, reason: String) async throws(VaultError) {
        let failure = state.withLock { state in
            state.biometrics += 1
            return state.failure
        }
        if let failure { throw failure }
    }
}

public extension SensitiveBuffer {
    static func text(_ string: String) -> SensitiveBuffer {
        let bytes = Array(string.utf8)
        return SensitiveBuffer(count: bytes.count) { $0.copyBytes(from: bytes) }
    }
}
