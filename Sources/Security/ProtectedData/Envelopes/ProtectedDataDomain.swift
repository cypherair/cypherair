import CryptoKit
import Foundation
import Security

struct ProtectedDataDomainID: RawRepresentable, Codable, Hashable, ExpressibleByStringLiteral, Sendable {
    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(stringLiteral value: StringLiteralType) {
        self.rawValue = value
    }
}

enum ProtectedDataCommittedDomainState: String, Codable, Sendable {
    case active
    case recoveryNeeded
}

enum SharedResourceLifecycleState: String, Codable, Sendable {
    case absent
    case ready
    case cleanupPending
}

enum ProtectedDataFrameworkState: Equatable, Sendable {
    case sessionLocked
    case sessionAuthorized
    case frameworkRecoveryNeeded
    case restartRequired
}

enum ProtectedDataRecoveryDisposition: Equatable, Sendable {
    case resumeSteadyState
    case continuePendingMutation
    case frameworkRecoveryNeeded
}

enum ProtectedDataBootstrapOutcome: Equatable, Sendable {
    case emptySteadyState(registry: ProtectedDataRegistry, didBootstrap: Bool)
    case loadedRegistry(registry: ProtectedDataRegistry, recoveryDisposition: ProtectedDataRecoveryDisposition)
    case frameworkRecoveryNeeded
}

enum ProtectedDataAccessGateDecision: Equatable, Sendable {
    case frameworkRecoveryNeeded
    case pendingMutationRecoveryRequired
    case authorizationRequired(registry: ProtectedDataRegistry)
    case alreadyAuthorized(registry: ProtectedDataRegistry)
    case noProtectedDomainPresent
}

enum ProtectedDataAuthorizationResult: Equatable, Sendable {
    case authorized
    case cancelledOrDenied
    case frameworkRecoveryNeeded
}

enum ProtectedDataMutationAuthorizationRequirement: Equatable, Sendable {
    case notRequired
    case wrappingRootKeyRequired
    case frameworkRecoveryNeeded
}

enum PendingRecoveryOutcome: Equatable, Sendable {
    case resumedToSteadyState
    case retryablePending
    case resetRequired
    case frameworkRecoveryNeeded
}

enum ProtectedSettingsDomainState: Equatable {
    case locked
    case unlocked
    case recoveryNeeded
    case pendingRetryRequired
    case pendingResetRequired
    case frameworkUnavailable
}

enum ProtectedDomainGenerationSlot: String, CaseIterable, Codable, Sendable {
    case current
    case previous
    case pending
}

enum ProtectedDataError: Error, LocalizedError, Equatable {
    case invalidDomainMasterKeyLength(Int)
    case invalidNonceLength(Int)
    case invalidAuthenticationTagLength(Int)
    case invalidCiphertextLength(Int)
    case invalidRegistry(String)
    case invalidEnvelope(String)
    case registryMissingWithArtifacts
    case storageRootOutsideApplicationSupport
    case fileProtectionUnsupported
    case fileProtectionVerificationFailed
    case protectedFileWriteFailed
    case missingWrappingRootKey
    case missingWrappedDomainMasterKey(ProtectedDataDomainID)
    case internalFailure(String)
    case authorizingUnavailable
    case restartRequired

    var errorDescription: String? {
        switch self {
        case .invalidDomainMasterKeyLength(let length):
            "ProtectedData domain master key must be 32 bytes, got \(length)."
        case .invalidNonceLength(let length):
            "Wrapped DMK nonce must be 12 bytes, got \(length)."
        case .invalidAuthenticationTagLength(let length):
            "Wrapped DMK authentication tag must be 16 bytes, got \(length)."
        case .invalidCiphertextLength(let length):
            "Wrapped DMK ciphertext must be 32 bytes, got \(length)."
        case .invalidRegistry(let reason):
            "ProtectedData registry is invalid: \(reason)"
        case .invalidEnvelope(let reason):
            "ProtectedData envelope is invalid: \(reason)"
        case .registryMissingWithArtifacts:
            "ProtectedData registry is missing while protected-data artifacts still exist."
        case .storageRootOutsideApplicationSupport:
            "ProtectedData storage must remain inside Application Support."
        case .fileProtectionUnsupported:
            "ProtectedData storage is unavailable because required file protection is unsupported."
        case .fileProtectionVerificationFailed:
            "ProtectedData storage could not verify the required file protection settings."
        case .protectedFileWriteFailed:
            "ProtectedData storage could not create a protected file."
        case .missingWrappingRootKey:
            "ProtectedData wrapping root key is not available in the current session."
        case .missingWrappedDomainMasterKey(let domainID):
            "ProtectedData wrapped domain master key is missing for domain \(domainID.rawValue)."
        case .internalFailure(let reason):
            reason
        case .authorizingUnavailable:
            "ProtectedData authorization is currently unavailable."
        case .restartRequired:
            "ProtectedData access is blocked until the app restarts."
        }
    }
}

extension Data {
    mutating func protectedDataZeroize() {
        guard !isEmpty else {
            return
        }
        resetBytes(in: startIndex..<endIndex)
    }
}

func protectedDataValidateSnapshotAndZeroizeDomainMasterKey<Snapshot>(
    _ openSnapshot: () throws -> (Snapshot, Data)
) throws {
    var (_, domainMasterKey) = try openSnapshot()
    domainMasterKey.protectedDataZeroize()
}

struct SensitiveBytes: Sendable {
    private var storage: ContiguousArray<UInt8>

    init(data: Data) {
        storage = ContiguousArray(data)
    }

    func dataCopy() -> Data {
        Data(storage)
    }

    mutating func zeroize() {
        guard !storage.isEmpty else {
            return
        }
        storage.withUnsafeMutableBufferPointer { buffer in
            buffer.initialize(repeating: 0)
        }
    }
}

final class SensitiveBytesBox: @unchecked Sendable {
    private var sensitiveBytes: SensitiveBytes

    init(data: Data) {
        self.sensitiveBytes = SensitiveBytes(data: data)
    }

    func dataCopy() -> Data {
        sensitiveBytes.dataCopy()
    }

    func zeroize() {
        sensitiveBytes.zeroize()
    }
}

/// Self-describing envelope that seals a per-domain payload generation under the
/// domain master key (AES-256-GCM). Follows the same envelope discipline as the
/// other CypherAir envelopes: a magic, algorithm identifier, and AAD version are
/// stored and bound into the AES-GCM AAD alongside the domain / schema / generation
/// identity, and decoding rejects any unknown or missing field.
///
/// Domain-separated by its own magic (`CPDENV5`) and AAD prefix (`CPDENVA5`).
///
/// SECURITY-CRITICAL: Changes to this file require human review.
/// See SECURITY.md Section 3 and Section 10.
struct ProtectedDomainEnvelope: Codable, Equatable, Sendable {
    static let magic = "CPDENV5"
    static let currentFormatVersion = 5
    static let currentAADVersion = 5
    static let algorithmID = "aes-256-gcm-v5"
    static let expectedNonceLength = 12
    static let expectedAuthenticationTagLength = 16

    let magic: String
    let formatVersion: Int
    let algorithmID: String
    let aadVersion: Int
    let domainID: ProtectedDataDomainID
    let schemaVersion: Int
    let generationIdentifier: Int
    let nonce: Data
    let ciphertext: Data
    let tag: Data

    func validateContract() throws {
        guard magic == Self.magic else {
            throw ProtectedDataError.invalidEnvelope("Unsupported protected-domain envelope magic.")
        }
        guard formatVersion == Self.currentFormatVersion else {
            throw ProtectedDataError.invalidEnvelope(
                "Unsupported envelope format version \(formatVersion)."
            )
        }
        guard algorithmID == Self.algorithmID else {
            throw ProtectedDataError.invalidEnvelope("Unsupported protected-domain envelope algorithm.")
        }
        guard aadVersion == Self.currentAADVersion else {
            throw ProtectedDataError.invalidEnvelope("Unsupported protected-domain envelope AAD version \(aadVersion).")
        }
        guard schemaVersion > 0 else {
            throw ProtectedDataError.invalidEnvelope("Schema version must be positive.")
        }
        guard generationIdentifier > 0 else {
            throw ProtectedDataError.invalidEnvelope("Generation identifier must be positive.")
        }
        guard nonce.count == Self.expectedNonceLength else {
            throw ProtectedDataError.invalidNonceLength(nonce.count)
        }
        guard tag.count == Self.expectedAuthenticationTagLength else {
            throw ProtectedDataError.invalidAuthenticationTagLength(tag.count)
        }
        guard !ciphertext.isEmpty else {
            throw ProtectedDataError.invalidEnvelope("Ciphertext must not be empty.")
        }
    }
}

enum ProtectedDomainEnvelopeCodec {
    private static let allowedKeys: Set<String> = [
        "magic",
        "formatVersion",
        "algorithmID",
        "aadVersion",
        "domainID",
        "schemaVersion",
        "generationIdentifier",
        "nonce",
        "ciphertext",
        "tag"
    ]

    static func encode(_ envelope: ProtectedDomainEnvelope) throws -> Data {
        try envelope.validateContract()
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(envelope)
    }

    static func decode(_ data: Data) throws -> ProtectedDomainEnvelope {
        try validateNoUnsupportedKeys(in: data)
        let envelope = try PropertyListDecoder().decode(ProtectedDomainEnvelope.self, from: data)
        try envelope.validateContract()
        return envelope
    }

    static func seal(
        plaintext: Data,
        domainID: ProtectedDataDomainID,
        schemaVersion: Int,
        generationIdentifier: Int,
        domainMasterKey: Data
    ) throws -> ProtectedDomainEnvelope {
        let nonce = try randomData(count: ProtectedDomainEnvelope.expectedNonceLength)
        let aad = try envelopeAAD(
            domainID: domainID,
            schemaVersion: schemaVersion,
            generationIdentifier: generationIdentifier
        )
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: domainMasterKey),
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )

        return ProtectedDomainEnvelope(
            magic: ProtectedDomainEnvelope.magic,
            formatVersion: ProtectedDomainEnvelope.currentFormatVersion,
            algorithmID: ProtectedDomainEnvelope.algorithmID,
            aadVersion: ProtectedDomainEnvelope.currentAADVersion,
            domainID: domainID,
            schemaVersion: schemaVersion,
            generationIdentifier: generationIdentifier,
            nonce: nonce,
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
    }

    static func open(
        envelope: ProtectedDomainEnvelope,
        domainMasterKey: Data
    ) throws -> Data {
        try envelope.validateContract()
        let aad = try envelopeAAD(
            domainID: envelope.domainID,
            schemaVersion: envelope.schemaVersion,
            generationIdentifier: envelope.generationIdentifier
        )
        let sealedBox = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: envelope.nonce),
            ciphertext: envelope.ciphertext,
            tag: envelope.tag
        )
        return try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: domainMasterKey),
            authenticating: aad
        )
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }

        guard status == errSecSuccess else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.randomFailure",
                    defaultValue: "A secure random-number operation failed while preparing protected app data."
                )
            )
        }

        return data
    }

    private static func envelopeAAD(
        domainID: ProtectedDataDomainID,
        schemaVersion: Int,
        generationIdentifier: Int
    ) throws -> Data {
        guard let magicData = ProtectedDomainEnvelope.magic.data(using: .utf8),
              let algorithmData = ProtectedDomainEnvelope.algorithmID.data(using: .utf8),
              let domainIDData = domainID.rawValue.data(using: .utf8) else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.domainIdentifierEncoding",
                    defaultValue: "A ProtectedData domain identifier could not be encoded."
                )
            )
        }

        var aad = Data("CPDENVA5".utf8)
        aad.append(UInt8(ProtectedDomainEnvelope.currentFormatVersion))
        aad.append(UInt8(ProtectedDomainEnvelope.currentAADVersion))
        aad.append(UInt16(magicData.count).bigEndianData)
        aad.append(magicData)
        aad.append(UInt16(algorithmData.count).bigEndianData)
        aad.append(algorithmData)
        aad.append(UInt16(domainIDData.count).bigEndianData)
        aad.append(domainIDData)
        aad.append(UInt16(schemaVersion).bigEndianData)
        aad.append(UInt32(generationIdentifier).bigEndianData)
        return aad
    }

    private static func validateNoUnsupportedKeys(in data: Data) throws {
        guard let keys = try EnvelopePlistInspector.topLevelKeys(in: data) else {
            throw ProtectedDataError.invalidEnvelope("Protected-domain envelope is not a dictionary.")
        }
        guard keys == allowedKeys else {
            throw ProtectedDataError.invalidEnvelope("Protected-domain envelope contains unsupported or missing fields.")
        }
    }
}
