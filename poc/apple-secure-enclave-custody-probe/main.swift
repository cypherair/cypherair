import Darwin
import Foundation
import Security

private let stateSchema = "cypherair.se-custody.phase3.signing-state.v1"
private let requestSchema = "cypherair.se-custody.phase3.signing-request.v1"
private let responseSchema = "cypherair.se-custody.phase3.signing-response.v1"
private let bundleIdentifier = "com.chentianren.cypherair.poc.secureenclavecustody.probe"
private let keychainAccessGroupSuffix = "com.chentianren.cypherair.poc.secureenclavecustody.probe"
private let applicationTagPrefix = "com.cypherair.poc.secure-enclave-custody.probe.phase3"

private enum Mode: String {
    case createState = "create-state"
    case signDigest = "sign-digest"
    case failure
    case cleanup
}

private struct Arguments {
    let mode: Mode
    let out: String?
    let request: String?
}

private struct StateFile: Codable {
    let schema: String
    let phase: String
    let createdAt: String
    let secureEnclaveAvailable: Bool
    let environment: Environment
    let instanceId: String
    let implementation: String
    let secKeyCreateRandomKeyAvailable: Bool
    let keychainAccessGroupSuffix: String
    let applicationTagPrefix: String
    let keys: [StateKey]
    let notes: [String]
}

private struct StateKey: Codable {
    let role: String
    let applicationTagHex: String
    let label: String
    let publicKeyX963Hex: String
    let publicKeyX963Length: Int
    let keyType: String
    let keyClass: String
    let keySizeBits: Int
    let tokenID: String
    let accessControl: String
}

private struct Environment: Codable {
    let osVersion: String
    let architecture: String
    let swiftVersion: String
    let bundleIdentifier: String
}

private struct SigningRequest: Codable {
    let schema: String?
    let statePath: String
    let hashAlgorithm: String?
    let digestHex: String?
    let responsePath: String?
    let cleanupPaths: [String]?
}

private struct SigningResponse: Codable {
    let schema: String
    let status: String
    let hashAlgorithm: String
    let digestByteLength: Int
    let derSignatureByteLength: Int
    let rHex: String
    let sHex: String
    let rByteLength: Int
    let sByteLength: Int
    let publicKeyRevalidated: Bool
    let signingKeychainRowReloaded: Bool
    let agreementKeychainRowRevalidated: Bool
    let keyTypeValidated: Bool
    let keySizeValidated: Bool
    let secureEnclaveTokenValidated: Bool
    let materialsPrinted: Bool
}

private struct SummaryReport: Codable {
    let phase: String
    let mode: String
    let status: String
    let secureEnclaveAvailable: Bool?
    let checksPassed: Int
    let checksFailed: Int
    let materialsPrinted: Bool
    let summary: String
}

private enum ProbeError: Error, CustomStringConvertible {
    case invalidArguments
    case insecurePath
    case invalidState
    case invalidRequest
    case missingEntitlement
    case secureEnclaveUnavailable
    case accessControlFailed
    case keyGenerationFailed(String)
    case keychainLookupFailed(String)
    case keyValidationFailed
    case unsupportedHash
    case wrongDigestLength
    case signatureFailed(String)
    case derParseFailed
    case fileIOFailed

    var description: String {
        switch self {
        case .invalidArguments: "invalidArguments"
        case .insecurePath: "insecurePath"
        case .invalidState: "invalidState"
        case .invalidRequest: "invalidRequest"
        case .missingEntitlement: "missingEntitlement"
        case .secureEnclaveUnavailable: "secureEnclaveUnavailable"
        case .accessControlFailed: "accessControlFailed"
        case .keyGenerationFailed(let reason): "keyGenerationFailed:\(reason)"
        case .keychainLookupFailed(let reason): "keychainLookupFailed:\(reason)"
        case .keyValidationFailed: "keyValidationFailed"
        case .unsupportedHash: "unsupportedHash"
        case .wrongDigestLength: "wrongDigestLength"
        case .signatureFailed(let reason): "signatureFailed:\(reason)"
        case .derParseFailed: "derParseFailed"
        case .fileIOFailed: "fileIOFailed"
        }
    }
}

private enum HashChoice: String {
    case sha256
    case sha384
    case sha512

    var digestByteLength: Int {
        switch self {
        case .sha256: 32
        case .sha384: 48
        case .sha512: 64
        }
    }

    var algorithm: SecKeyAlgorithm {
        switch self {
        case .sha256: .ecdsaSignatureDigestX962SHA256
        case .sha384: .ecdsaSignatureDigestX962SHA384
        case .sha512: .ecdsaSignatureDigestX962SHA512
        }
    }
}

private struct ValidatedKey {
    let key: SecKey
    let publicX963: Data
}

private func parseArguments() throws -> Arguments {
    var mode: Mode?
    var out: String?
    var request: String?
    var iterator = CommandLine.arguments.dropFirst().makeIterator()

    while let arg = iterator.next() {
        switch arg {
        case "--":
            continue
        case "--mode":
            guard let value = iterator.next(), let parsed = Mode(rawValue: value) else {
                throw ProbeError.invalidArguments
            }
            mode = parsed
        case "--out":
            guard let value = iterator.next(), !value.isEmpty else {
                throw ProbeError.invalidArguments
            }
            out = value
        case "--request":
            guard let value = iterator.next(), !value.isEmpty else {
                throw ProbeError.invalidArguments
            }
            request = value
        default:
            throw ProbeError.invalidArguments
        }
    }

    guard let mode else { throw ProbeError.invalidArguments }
    switch mode {
    case .createState:
        guard out != nil, request == nil else { throw ProbeError.invalidArguments }
    case .signDigest, .failure, .cleanup:
        guard request != nil, out == nil else { throw ProbeError.invalidArguments }
    }
    return Arguments(mode: mode, out: out, request: request)
}

private func run() throws -> SummaryReport {
    let args = try parseArguments()
    switch args.mode {
    case .createState:
        return try createState(outPath: args.out!)
    case .signDigest:
        return try signDigest(requestPath: args.request!)
    case .failure:
        return try runFailure(requestPath: args.request!)
    case .cleanup:
        return try cleanup(requestPath: args.request!)
    }
}

private func createState(outPath: String) throws -> SummaryReport {
    try validatePrivateParentDirectory(for: outPath)
    let accessGroup = try resolvedKeychainAccessGroup()
    let instanceId = UUID().uuidString.lowercased()

    let signing = try createSecureEnclaveKey(role: "signing", instanceId: instanceId, accessGroup: accessGroup)
    let agreement = try createSecureEnclaveKey(role: "keyAgreement", instanceId: instanceId, accessGroup: accessGroup)
    guard signing.publicKeyX963Hex != agreement.publicKeyX963Hex else {
        throw ProbeError.keyValidationFailed
    }

    let state = StateFile(
        schema: stateSchema,
        phase: "phase3",
        createdAt: isoNow(),
        secureEnclaveAvailable: true,
        environment: environment(),
        instanceId: instanceId,
        implementation: "Security SecKey Secure Enclave permanent key",
        secKeyCreateRandomKeyAvailable: true,
        keychainAccessGroupSuffix: keychainAccessGroupSuffix,
        applicationTagPrefix: applicationTagPrefix,
        keys: [signing, agreement],
        notes: [
            "State is local capability material and must remain 0600 in a 0700 directory.",
            "Keychain application tags and labels are intentionally confined to the state file.",
            "Stdout intentionally omits key labels, application tags, paths, digests, signatures, certificates, and stable fingerprints."
        ]
    )
    try writeJSONExclusive(state, to: outPath)

    return SummaryReport(
        phase: "phase3",
        mode: "create-state",
        status: "passed",
        secureEnclaveAvailable: true,
        checksPassed: 7,
        checksFailed: 0,
        materialsPrinted: false,
        summary: "Secure Enclave SecKey rows created; sensitive state written with restricted permissions."
    )
}

private func createSecureEnclaveKey(role: String, instanceId: String, accessGroup: String) throws -> StateKey {
    let tagString = "\(applicationTagPrefix).\(instanceId).\(role)"
    let label = "CypherAir Secure Enclave Custody Probe \(role) \(instanceId)"
    let tag = Data(tagString.utf8)
    try deleteKey(applicationTag: tag, accessGroup: accessGroup)

    let key = try createPrivateKey(
        applicationTag: tag,
        label: label,
        accessGroup: accessGroup,
        keySizeBits: 256,
        tokenID: kSecAttrTokenIDSecureEnclave
    )
    let publicX963 = try publicX963Representation(for: key)
    try validateSecKey(
        key,
        expectedPublicX963: publicX963,
        expectedRole: role,
        expectedApplicationTag: tag,
        accessGroup: accessGroup
    )

    return StateKey(
        role: role,
        applicationTagHex: tag.hexEncodedString(),
        label: label,
        publicKeyX963Hex: publicX963.hexEncodedString(),
        publicKeyX963Length: publicX963.count,
        keyType: "SecKey.ECSECPrimeRandom.PrivateKey",
        keyClass: "private",
        keySizeBits: 256,
        tokenID: "SecureEnclave",
        accessControl: "privateKeyUsage"
    )
}

private func signDigest(requestPath: String) throws -> SummaryReport {
    let request: SigningRequest = try readJSONSecurely(from: requestPath)
    let response = try performSignDigest(request: request)
    guard let responsePath = request.responsePath else { throw ProbeError.invalidRequest }
    try writeJSONExclusive(response, to: responsePath)
    return SummaryReport(
        phase: "phase3",
        mode: "sign-digest",
        status: "passed",
        secureEnclaveAvailable: true,
        checksPassed: 8,
        checksFailed: 0,
        materialsPrinted: false,
        summary: "Digest signed through a reloaded and revalidated Secure Enclave SecKey row."
    )
}

private func performSignDigest(request: SigningRequest) throws -> SigningResponse {
    guard request.schema == nil || request.schema == requestSchema else { throw ProbeError.invalidRequest }
    guard let hashName = request.hashAlgorithm,
          let hash = HashChoice(rawValue: hashName),
          let digestHex = request.digestHex,
          let responsePath = request.responsePath,
          !responsePath.isEmpty else {
        throw ProbeError.invalidRequest
    }
    try validatePrivateParentDirectory(for: responsePath)
    let digest = try hexDecode(digestHex)
    guard digest.count == hash.digestByteLength else { throw ProbeError.wrongDigestLength }

    let state: StateFile = try readJSONSecurely(from: request.statePath)
    let (signing, agreement) = try loadAndValidateKeyPair(state: state)
    guard signing.publicX963 != agreement.publicX963 else { throw ProbeError.keyValidationFailed }
    guard SecKeyIsAlgorithmSupported(signing.key, .sign, hash.algorithm) else {
        throw ProbeError.unsupportedHash
    }

    var error: Unmanaged<CFError>?
    guard let der = SecKeyCreateSignature(
        signing.key,
        hash.algorithm,
        digest as CFData,
        &error
    ) as Data? else {
        throw ProbeError.signatureFailed(cfErrorClass(error?.takeRetainedValue()))
    }

    let (r, s) = try parseECDSADER(der)
    return SigningResponse(
        schema: responseSchema,
        status: "passed",
        hashAlgorithm: hash.rawValue,
        digestByteLength: digest.count,
        derSignatureByteLength: der.count,
        rHex: r.hexEncodedString(),
        sHex: s.hexEncodedString(),
        rByteLength: r.count,
        sByteLength: s.count,
        publicKeyRevalidated: true,
        signingKeychainRowReloaded: true,
        agreementKeychainRowRevalidated: true,
        keyTypeValidated: true,
        keySizeValidated: true,
        secureEnclaveTokenValidated: true,
        materialsPrinted: false
    )
}

private func runFailure(requestPath: String) throws -> SummaryReport {
    let request: SigningRequest = try readJSONSecurely(from: requestPath)
    let state: StateFile = try readJSONSecurely(from: request.statePath)
    let scratchDir = URL(fileURLWithPath: requestPath).deletingLastPathComponent().path
    let accessGroup = try resolvedKeychainAccessGroup()
    var passed = 0
    var failed = 0

    func expectFailure(_ body: () throws -> Void) {
        do {
            try body()
            failed += 1
        } catch {
            passed += 1
        }
    }

    let goodDigest = String(repeating: "11", count: 32)
    expectFailure {
        let bad = SigningRequest(
            schema: requestSchema,
            statePath: request.statePath,
            hashAlgorithm: "sha999",
            digestHex: goodDigest,
            responsePath: "\(scratchDir)/phase3-bad-response-unsupported.json",
            cleanupPaths: nil
        )
        _ = try performSignDigest(request: bad)
    }
    expectFailure {
        let bad = SigningRequest(
            schema: requestSchema,
            statePath: request.statePath,
            hashAlgorithm: "sha256",
            digestHex: "abcd",
            responsePath: "\(scratchDir)/phase3-bad-response-length.json",
            cleanupPaths: nil
        )
        _ = try performSignDigest(request: bad)
    }
    expectFailure {
        let corrupted = replacing(state: state, schema: "corrupted")
        _ = try loadAndValidateKeyPair(state: corrupted)
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let agreement = try stateKey(state, role: "keyAgreement")
        let swapped = replacing(state: state, signing: replacing(signing, applicationTagHex: agreement.applicationTagHex))
        _ = try loadAndValidateKeyPair(state: swapped)
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let agreement = try stateKey(state, role: "keyAgreement")
        let mismatched = replacing(state: state, signing: replacing(signing, publicKeyX963Hex: agreement.publicKeyX963Hex))
        _ = try loadAndValidateKeyPair(state: mismatched)
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let missing = replacing(state: state, signing: replacing(signing, applicationTagHex: Data("missing-row".utf8).hexEncodedString()))
        _ = try loadAndValidateKeyPair(state: missing)
    }
    expectFailure {
        let software = try createSoftwareFailureKey(instanceId: state.instanceId, accessGroup: accessGroup, keySizeBits: 256)
        defer { try? deleteKey(applicationTag: try? hexDecode(software.applicationTagHex), accessGroup: accessGroup) }
        let substituted = replacing(state: state, signing: software)
        _ = try loadAndValidateKeyPair(state: substituted)
    }
    expectFailure {
        let software = try createSoftwareFailureKey(instanceId: state.instanceId, accessGroup: accessGroup, keySizeBits: 384)
        defer { try? deleteKey(applicationTag: try? hexDecode(software.applicationTagHex), accessGroup: accessGroup) }
        let substituted = replacing(state: state, signing: software)
        _ = try loadAndValidateKeyPair(state: substituted)
    }
    expectFailure {
        let target = "\(scratchDir)/phase3-symlink-target.json"
        let symlink = "\(scratchDir)/phase3-symlink-request.json"
        try? FileManager.default.removeItem(atPath: target)
        try? FileManager.default.removeItem(atPath: symlink)
        try writeBytesExclusive(Data("{}".utf8), to: target)
        try FileManager.default.createSymbolicLink(atPath: symlink, withDestinationPath: target)
        defer {
            try? FileManager.default.removeItem(atPath: symlink)
            try? FileManager.default.removeItem(atPath: target)
        }
        let _: SigningRequest = try readJSONSecurely(from: symlink)
    }

    let status = failed == 0 ? "passed" : "failed"
    return SummaryReport(
        phase: "phase3",
        mode: "failure",
        status: status,
        secureEnclaveAvailable: state.secureEnclaveAvailable,
        checksPassed: passed,
        checksFailed: failed,
        materialsPrinted: false,
        summary: "Failure checks exercised restricted files, role/tag substitution, invalid digests, public-key mismatch, missing rows, non-SE rows, wrong-size rows, and symlink rejection."
    )
}

private func cleanup(requestPath: String) throws -> SummaryReport {
    let request: SigningRequest = try readJSONSecurely(from: requestPath)
    var deleted = 0
    if let state: StateFile = try? readJSONSecurely(from: request.statePath),
       let accessGroup = try? resolvedKeychainAccessGroup() {
        for key in state.keys {
            if let tag = try? hexDecode(key.applicationTagHex) {
                try? deleteKey(applicationTag: tag, accessGroup: accessGroup)
                deleted += 1
            }
        }
        deleted += (try? cleanupStaleProbeKeys(accessGroup: accessGroup)) ?? 0
    }
    for path in ([request.statePath, request.responsePath].compactMap { $0 } + (request.cleanupPaths ?? [])) {
        if let attrs = try? secureFileMetadata(path), attrs.isRegularFile {
            try? FileManager.default.removeItem(atPath: path)
            deleted += 1
        }
    }
    if let attrs = try? secureFileMetadata(requestPath), attrs.isRegularFile {
        try? FileManager.default.removeItem(atPath: requestPath)
        deleted += 1
    }
    return SummaryReport(
        phase: "phase3",
        mode: "cleanup",
        status: "passed",
        secureEnclaveAvailable: nil,
        checksPassed: deleted,
        checksFailed: 0,
        materialsPrinted: false,
        summary: "Probe Keychain rows and temp capability files were removed where present."
    )
}

private func loadAndValidateKeyPair(state: StateFile) throws -> (ValidatedKey, ValidatedKey) {
    guard state.schema == stateSchema,
          state.secureEnclaveAvailable,
          state.implementation == "Security SecKey Secure Enclave permanent key",
          state.secKeyCreateRandomKeyAvailable,
          state.keychainAccessGroupSuffix == keychainAccessGroupSuffix,
          state.applicationTagPrefix == applicationTagPrefix else {
        throw ProbeError.invalidState
    }
    let accessGroup = try resolvedKeychainAccessGroup()
    let signing = try loadAndValidateKey(state: state, role: "signing", accessGroup: accessGroup)
    let agreement = try loadAndValidateKey(state: state, role: "keyAgreement", accessGroup: accessGroup)
    guard signing.publicX963 != agreement.publicX963 else { throw ProbeError.keyValidationFailed }
    return (signing, agreement)
}

private func loadAndValidateKey(state: StateFile, role: String, accessGroup: String) throws -> ValidatedKey {
    let keyState = try stateKey(state, role: role)
    guard keyState.keyType == "SecKey.ECSECPrimeRandom.PrivateKey",
          keyState.keyClass == "private",
          keyState.keySizeBits == 256,
          keyState.tokenID == "SecureEnclave",
          keyState.accessControl == "privateKeyUsage",
          keyState.publicKeyX963Length == 65 else {
        throw ProbeError.invalidState
    }
    let tag = try hexDecode(keyState.applicationTagHex)
    let expectedPublic = try hexDecode(keyState.publicKeyX963Hex)
    guard expectedPublic.count == 65 else { throw ProbeError.invalidState }
    let key = try lookupPrivateKey(applicationTag: tag, accessGroup: accessGroup)
    try validateSecKey(
        key,
        expectedPublicX963: expectedPublic,
        expectedRole: role,
        expectedApplicationTag: tag,
        accessGroup: accessGroup
    )
    return ValidatedKey(key: key, publicX963: expectedPublic)
}

private func stateKey(_ state: StateFile, role: String) throws -> StateKey {
    guard let key = state.keys.first(where: { $0.role == role }) else {
        throw ProbeError.invalidState
    }
    return key
}

private func createSoftwareFailureKey(instanceId: String, accessGroup: String, keySizeBits: Int) throws -> StateKey {
    let tagString = "\(applicationTagPrefix).\(instanceId).software-failure-\(keySizeBits)"
    let label = "CypherAir Secure Enclave Custody Probe software failure \(keySizeBits) \(instanceId)"
    let tag = Data(tagString.utf8)
    try deleteKey(applicationTag: tag, accessGroup: accessGroup)
    let key = try createPrivateKey(
        applicationTag: tag,
        label: label,
        accessGroup: accessGroup,
        keySizeBits: keySizeBits,
        tokenID: nil
    )
    let publicX963 = try publicX963Representation(for: key)
    return StateKey(
        role: "signing",
        applicationTagHex: tag.hexEncodedString(),
        label: label,
        publicKeyX963Hex: publicX963.hexEncodedString(),
        publicKeyX963Length: publicX963.count,
        keyType: "SecKey.ECSECPrimeRandom.PrivateKey",
        keyClass: "private",
        keySizeBits: keySizeBits,
        tokenID: "SecureEnclave",
        accessControl: "privateKeyUsage"
    )
}

private func replacing(state: StateFile, schema: String? = nil, signing: StateKey? = nil) -> StateFile {
    StateFile(
        schema: schema ?? state.schema,
        phase: state.phase,
        createdAt: state.createdAt,
        secureEnclaveAvailable: state.secureEnclaveAvailable,
        environment: state.environment,
        instanceId: state.instanceId,
        implementation: state.implementation,
        secKeyCreateRandomKeyAvailable: state.secKeyCreateRandomKeyAvailable,
        keychainAccessGroupSuffix: state.keychainAccessGroupSuffix,
        applicationTagPrefix: state.applicationTagPrefix,
        keys: [signing ?? state.keys.first { $0.role == "signing" }, state.keys.first { $0.role == "keyAgreement" }].compactMap { $0 },
        notes: state.notes
    )
}

private func replacing(
    _ key: StateKey,
    applicationTagHex: String? = nil,
    publicKeyX963Hex: String? = nil
) -> StateKey {
    StateKey(
        role: key.role,
        applicationTagHex: applicationTagHex ?? key.applicationTagHex,
        label: key.label,
        publicKeyX963Hex: publicKeyX963Hex ?? key.publicKeyX963Hex,
        publicKeyX963Length: key.publicKeyX963Length,
        keyType: key.keyType,
        keyClass: key.keyClass,
        keySizeBits: key.keySizeBits,
        tokenID: key.tokenID,
        accessControl: key.accessControl
    )
}

private func createPrivateKey(
    applicationTag: Data,
    label: String,
    accessGroup: String,
    keySizeBits: Int,
    tokenID: CFString?
) throws -> SecKey {
    var accessError: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage,
        &accessError
    ) else {
        throw ProbeError.accessControlFailed
    }

    var privateAttributes: [CFString: Any] = [
        kSecAttrIsPermanent: true,
        kSecAttrApplicationTag: applicationTag,
        kSecAttrLabel: label,
        kSecAttrAccessControl: accessControl,
        kSecAttrAccessGroup: accessGroup
    ]
    if tokenID == nil {
        privateAttributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }

    var attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: keySizeBits,
        kSecPrivateKeyAttrs: privateAttributes
    ]
    if let tokenID {
        attributes[kSecAttrTokenID] = tokenID
    }

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw ProbeError.keyGenerationFailed(cfErrorClass(error?.takeRetainedValue()))
    }
    return key
}

private func lookupPrivateKey(applicationTag: Data, accessGroup: String) throws -> SecKey {
    let query: [CFString: Any] = [
        kSecClass: kSecClassKey,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag: applicationTag,
        kSecAttrAccessGroup: accessGroup,
        kSecReturnRef: true,
        kSecMatchLimit: kSecMatchLimitOne
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let item = result, CFGetTypeID(item) == SecKeyGetTypeID() else {
        throw ProbeError.keychainLookupFailed(osStatusClass(status))
    }
    let key = item as! SecKey
    return key
}

private func validateSecKey(
    _ key: SecKey,
    expectedPublicX963: Data,
    expectedRole: String,
    expectedApplicationTag: Data,
    accessGroup: String
) throws {
    guard expectedRole == "signing" || expectedRole == "keyAgreement" else {
        throw ProbeError.keyValidationFailed
    }
    guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] else {
        throw ProbeError.keyValidationFailed
    }
    guard cfStringAttribute(attributes[kSecAttrKeyType]) == (kSecAttrKeyTypeECSECPrimeRandom as String),
          cfStringAttribute(attributes[kSecAttrKeyClass]) == (kSecAttrKeyClassPrivate as String),
          intAttribute(attributes[kSecAttrKeySizeInBits]) == 256,
          cfStringAttribute(attributes[kSecAttrTokenID]) == (kSecAttrTokenIDSecureEnclave as String) else {
        throw ProbeError.keyValidationFailed
    }
    if let tag = attributes[kSecAttrApplicationTag] as? Data, tag != expectedApplicationTag {
        throw ProbeError.keyValidationFailed
    }
    if let group = cfStringAttribute(attributes[kSecAttrAccessGroup]), group != accessGroup {
        throw ProbeError.keyValidationFailed
    }
    let publicX963 = try publicX963Representation(for: key)
    guard publicX963 == expectedPublicX963 else {
        throw ProbeError.keyValidationFailed
    }
}

private func publicX963Representation(for key: SecKey) throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(key) else {
        throw ProbeError.keyValidationFailed
    }
    var error: Unmanaged<CFError>?
    guard let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        throw ProbeError.keyValidationFailed
    }
    guard publicData.count == 65, publicData.first == 0x04 else {
        throw ProbeError.keyValidationFailed
    }
    return publicData
}

private func deleteKey(applicationTag: Data?, accessGroup: String) throws {
    guard let applicationTag else { return }
    let query: [CFString: Any] = [
        kSecClass: kSecClassKey,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag: applicationTag,
        kSecAttrAccessGroup: accessGroup
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw ProbeError.keychainLookupFailed(osStatusClass(status))
    }
}

private func cleanupStaleProbeKeys(accessGroup: String) throws -> Int {
    let query: [CFString: Any] = [
        kSecClass: kSecClassKey,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrAccessGroup: accessGroup,
        kSecReturnAttributes: true,
        kSecMatchLimit: kSecMatchLimitAll
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        return 0
    }
    guard status == errSecSuccess else {
        throw ProbeError.keychainLookupFailed(osStatusClass(status))
    }
    guard let rows = result as? [[CFString: Any]] else {
        return 0
    }
    var deleted = 0
    for row in rows {
        guard let tag = row[kSecAttrApplicationTag] as? Data,
              let tagString = String(data: tag, encoding: .utf8),
              tagString.hasPrefix(applicationTagPrefix) else {
            continue
        }
        try deleteKey(applicationTag: tag, accessGroup: accessGroup)
        deleted += 1
    }
    return deleted
}

private func resolvedKeychainAccessGroup() throws -> String {
    guard let task = SecTaskCreateFromSelf(nil) else {
        throw ProbeError.missingEntitlement
    }
    guard let value = SecTaskCopyValueForEntitlement(
        task,
        "keychain-access-groups" as CFString,
        nil
    ) else {
        throw ProbeError.missingEntitlement
    }
    guard let groups = value as? [String],
          let group = groups.first(where: { $0.hasSuffix(".\(keychainAccessGroupSuffix)") || $0 == keychainAccessGroupSuffix }) else {
        throw ProbeError.missingEntitlement
    }
    return group
}

private func cfStringAttribute(_ value: Any?) -> String? {
    if let value = value as? String {
        return value
    }
    if let value {
        return "\(value)"
    }
    return nil
}

private func intAttribute(_ value: Any?) -> Int? {
    if let value = value as? Int {
        return value
    }
    if let value = value as? NSNumber {
        return value.intValue
    }
    return nil
}

private func parseECDSADER(_ der: Data) throws -> (Data, Data) {
    let bytes = [UInt8](der)
    var index = 0
    guard readByte(bytes, &index) == 0x30 else { throw ProbeError.derParseFailed }
    let sequenceLength = try readDERLength(bytes, &index)
    guard index + sequenceLength == bytes.count else { throw ProbeError.derParseFailed }
    let r = try readDERInteger(bytes, &index)
    let s = try readDERInteger(bytes, &index)
    guard index == bytes.count else { throw ProbeError.derParseFailed }
    return (try fixedWidthInteger(r), try fixedWidthInteger(s))
}

private func readDERInteger(_ bytes: [UInt8], _ index: inout Int) throws -> [UInt8] {
    guard readByte(bytes, &index) == 0x02 else { throw ProbeError.derParseFailed }
    let length = try readDERLength(bytes, &index)
    guard length > 0, index + length <= bytes.count else { throw ProbeError.derParseFailed }
    let value = Array(bytes[index..<index + length])
    index += length
    return value
}

private func fixedWidthInteger(_ bytes: [UInt8]) throws -> Data {
    var value = bytes
    while value.count > 1 && value.first == 0 {
        value.removeFirst()
    }
    guard value.count <= 32 else { throw ProbeError.derParseFailed }
    return Data(repeating: 0, count: 32 - value.count) + Data(value)
}

private func readByte(_ bytes: [UInt8], _ index: inout Int) -> UInt8? {
    guard index < bytes.count else { return nil }
    defer { index += 1 }
    return bytes[index]
}

private func readDERLength(_ bytes: [UInt8], _ index: inout Int) throws -> Int {
    guard let first = readByte(bytes, &index) else { throw ProbeError.derParseFailed }
    if first < 0x80 {
        return Int(first)
    }
    let count = Int(first & 0x7f)
    guard count > 0, count <= 2, index + count <= bytes.count else {
        throw ProbeError.derParseFailed
    }
    var value = 0
    for _ in 0..<count {
        guard let byte = readByte(bytes, &index) else { throw ProbeError.derParseFailed }
        value = (value << 8) | Int(byte)
    }
    return value
}

private struct SecureFileMetadata {
    let isRegularFile: Bool
}

private func readJSONSecurely<T: Decodable>(from path: String) throws -> T {
    let data = try readBytesSecurely(from: path)
    do {
        return try JSONDecoder().decode(T.self, from: data)
    } catch {
        throw ProbeError.invalidRequest
    }
}

private func readBytesSecurely(from path: String) throws -> Data {
    try validatePrivateParentDirectory(for: path)
    let fd = open(path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else { throw ProbeError.insecurePath }
    defer { close(fd) }
    try validateOpenFileDescriptor(fd)

    var output = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let count = read(fd, &buffer, buffer.count)
        if count < 0 { throw ProbeError.fileIOFailed }
        if count == 0 { break }
        output.append(buffer, count: count)
    }
    return output
}

private func writeJSONExclusive<T: Encodable>(_ value: T, to path: String) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(value)
    try writeBytesExclusive(data, to: path)
}

private func writeBytesExclusive(_ data: Data, to path: String) throws {
    try validatePrivateParentDirectory(for: path)
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
    guard fd >= 0 else { throw ProbeError.insecurePath }
    defer { close(fd) }
    var written = 0
    try data.withUnsafeBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { return }
        while written < data.count {
            let count = write(fd, base.advanced(by: written), data.count - written)
            if count < 0 { throw ProbeError.fileIOFailed }
            written += count
        }
    }
    fchmod(fd, mode_t(0o600))
}

private func secureFileMetadata(_ path: String) throws -> SecureFileMetadata {
    let fd = open(path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else { throw ProbeError.insecurePath }
    defer { close(fd) }
    try validateOpenFileDescriptor(fd)
    return SecureFileMetadata(isRegularFile: true)
}

private func validatePrivateParentDirectory(for path: String) throws {
    let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
    var info = stat()
    guard lstat(parent, &info) == 0 else { throw ProbeError.insecurePath }
    let mode = info.st_mode
    guard (mode & S_IFMT) == S_IFDIR,
          info.st_uid == getuid(),
          (mode & 0o777) == 0o700 else {
        throw ProbeError.insecurePath
    }
}

private func validateOpenFileDescriptor(_ fd: Int32) throws {
    var info = stat()
    guard fstat(fd, &info) == 0 else { throw ProbeError.insecurePath }
    let mode = info.st_mode
    guard (mode & S_IFMT) == S_IFREG,
          info.st_uid == getuid(),
          (mode & 0o777) == 0o600 else {
        throw ProbeError.insecurePath
    }
}

private func environment() -> Environment {
    Environment(
        osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
        architecture: architectureName(),
        swiftVersion: swiftVersionString(),
        bundleIdentifier: Bundle.main.bundleIdentifier ?? bundleIdentifier
    )
}

private func architectureName() -> String {
    var systemInfo = utsname()
    uname(&systemInfo)
    return withUnsafePointer(to: &systemInfo.machine) {
        $0.withMemoryRebound(to: CChar.self, capacity: 1) {
            String(cString: $0)
        }
    }
}

private func swiftVersionString() -> String {
    #if compiler(>=6.0)
    return "swift>=6.0"
    #else
    return "swift<6.0"
    #endif
}

private func isoNow() -> String {
    ISO8601DateFormatter().string(from: Date())
}

private func hexDecode(_ input: String) throws -> Data {
    guard input.count % 2 == 0 else { throw ProbeError.invalidRequest }
    var output = Data()
    var index = input.startIndex
    while index < input.endIndex {
        let next = input.index(index, offsetBy: 2)
        guard let byte = UInt8(input[index..<next], radix: 16) else {
            throw ProbeError.invalidRequest
        }
        output.append(byte)
        index = next
    }
    return output
}

private func osStatusClass(_ status: OSStatus) -> String {
    switch status {
    case errSecSuccess: "errSecSuccess"
    case errSecItemNotFound: "errSecItemNotFound"
    case errSecDuplicateItem: "errSecDuplicateItem"
    case errSecMissingEntitlement: "errSecMissingEntitlement"
    case errSecAuthFailed: "errSecAuthFailed"
    case errSecInteractionNotAllowed: "errSecInteractionNotAllowed"
    case errSecParam: "errSecParam"
    default: "osStatus:\(status)"
    }
}

private func cfErrorClass(_ error: CFError?) -> String {
    guard let error else { return "cfError" }
    let nsError = error as Error as NSError
    if nsError.domain == NSOSStatusErrorDomain {
        return osStatusClass(OSStatus(nsError.code))
    }
    return "cfError:\(nsError.domain)"
}

private extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

do {
    let report = try run()
    print("Secure Enclave custody probe: \(report.mode) \(report.status)")
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(report)
    print(String(decoding: data, as: UTF8.self))
    if report.status == "failed" {
        exit(1)
    }
} catch {
    let report = SummaryReport(
        phase: "phase3",
        mode: "unknown",
        status: "failed",
        secureEnclaveAvailable: nil,
        checksPassed: 0,
        checksFailed: 1,
        materialsPrinted: false,
        summary: (error as? ProbeError)?.description ?? "operationFailed"
    )
    print("Secure Enclave custody probe: failed")
    if let data = try? JSONEncoder().encode(report) {
        print(String(decoding: data, as: UTF8.self))
    }
    exit(1)
}
