import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Stores
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
        data[data.count / 2] ^= 0xFF
        try? write(account: account, data: data)
    }
}

/// Domain files in memory whose reads or writes can be made to fail.
public final class FailableDomainFiles: DomainFiles, @unchecked Sendable {
    public let files = InMemoryDomainFiles()
    private let failing = OSAllocatedUnfairLock(initialState: (reads: false, writes: false))

    public init() {}

    public var failsReads: Bool {
        get { failing.withLock { $0.reads } }
        set { failing.withLock { $0.reads = newValue } }
    }

    public var failsWrites: Bool {
        get { failing.withLock { $0.writes } }
        set { failing.withLock { $0.writes = newValue } }
    }

    public func read(_ name: String) throws(StoreError) -> Data? {
        guard !failsReads else { throw .io("read refused by the test") }
        return try files.read(name)
    }

    public func replace(_ name: String, with data: Data) throws(StoreError) {
        guard !failsWrites else { throw .io("write refused by the test") }
        try files.replace(name, with: data)
    }

    public func eraseAll() throws(StoreError) { try files.eraseAll() }
}

public extension InMemoryDomainFiles {
    /// Flips one byte in the middle of the file.
    func corrupt(_ name: String) {
        guard var data = try? read(name), !data.isEmpty else { return }
        data[data.count / 2] ^= 0xFF
        try? replace(name, with: data)
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
