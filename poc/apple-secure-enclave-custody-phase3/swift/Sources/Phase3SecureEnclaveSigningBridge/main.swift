import Darwin
import Foundation
import Security

private let schema = "cypherair.se-custody.phase3.signing-state.v1"
private let requestSchema = "cypherair.se-custody.phase3.signing-request.v1"
private let responseSchema = "cypherair.se-custody.phase3.signing-response.v1"
private let keychainTagPrefix = "com.cypherair.poc.secure-enclave-custody.phase3.seckey."
private let keychainLabelPrefix = "CypherAir Phase 3 SecKey Bridge "
private let signingStateKeyType = "SecKey.ECSECPrimeRandom.SecureEnclave.Signing"
private let agreementStateKeyType = "SecKey.ECSECPrimeRandom.SecureEnclave.KeyAgreement"

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
    let instanceId: String?
    let implementation: String
    let secKeyCreateRandomKeyAvailable: Bool
    let keys: [StateKey]
    let notes: [String]
}

private struct StateKey: Codable {
    let role: String
    let applicationTagHex: String
    let applicationLabel: String
    let publicKeyX963Hex: String
    let publicKeyX963Length: Int
    let keyType: String
    let keySizeBits: Int
    let tokenID: String
}

private struct Environment: Codable {
    let osVersion: String
    let architecture: String
    let swiftVersion: String
}

private struct SigningRequest: Codable {
    let schema: String?
    let statePath: String
    let hashAlgorithm: String?
    let digestHex: String?
    let responsePath: String?
    let resultPath: String?
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
    let signingHandleReconstructed: Bool
    let agreementHandleRevalidated: Bool
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
    case secureEnclaveUnavailable
    case missingEntitlement
    case keyGenerationFailed
    case keychainLookupFailed
    case keyValidationFailed
    case unsupportedHash
    case wrongDigestLength
    case signatureFailed
    case derParseFailed
    case fileIOFailed

    var description: String {
        switch self {
        case .invalidArguments: "invalidArguments"
        case .insecurePath: "insecurePath"
        case .invalidState: "invalidState"
        case .invalidRequest: "invalidRequest"
        case .secureEnclaveUnavailable: "secureEnclaveUnavailable"
        case .missingEntitlement: "missingEntitlement"
        case .keyGenerationFailed: "keyGenerationFailed"
        case .keychainLookupFailed: "keychainLookupFailed"
        case .keyValidationFailed: "keyValidationFailed"
        case .unsupportedHash: "unsupportedHash"
        case .wrongDigestLength: "wrongDigestLength"
        case .signatureFailed: "signatureFailed"
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

    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .sha256: .ecdsaSignatureDigestX962SHA256
        case .sha384: .ecdsaSignatureDigestX962SHA384
        case .sha512: .ecdsaSignatureDigestX962SHA512
        }
    }
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

    let instanceId = UUID().uuidString.lowercased()
    let signingTag = "\(keychainTagPrefix)\(instanceId).signing"
    let agreementTag = "\(keychainTagPrefix)\(instanceId).agreement"
    let signingLabel = "\(keychainLabelPrefix)\(instanceId) signing"
    let agreementLabel = "\(keychainLabelPrefix)\(instanceId) keyAgreement"

    let signingTagData = Data(signingTag.utf8)
    let agreementTagData = Data(agreementTag.utf8)

    try? deleteKey(applicationTag: signingTagData)
    try? deleteKey(applicationTag: agreementTagData)

    do {
        let signingKey = try createSecureEnclavePrivateKey(
            applicationTag: signingTagData,
            label: signingLabel
        )
        let agreementKey = try createSecureEnclavePrivateKey(
            applicationTag: agreementTagData,
            label: agreementLabel
        )
        let signingPublic = try publicX963(for: signingKey)
        let agreementPublic = try publicX963(for: agreementKey)
        guard signingPublic != agreementPublic else { throw ProbeError.keyValidationFailed }

        let state = StateFile(
            schema: schema,
            phase: "phase3",
            createdAt: isoNow(),
            secureEnclaveAvailable: true,
            environment: environment(),
            instanceId: instanceId,
            implementation: "Security SecKey Secure Enclave P-256 permanent Keychain row",
            secKeyCreateRandomKeyAvailable: true,
            keys: [
                StateKey(
                    role: "signing",
                    applicationTagHex: signingTagData.hexEncodedString(),
                    applicationLabel: signingLabel,
                    publicKeyX963Hex: signingPublic.hexEncodedString(),
                    publicKeyX963Length: signingPublic.count,
                    keyType: signingStateKeyType,
                    keySizeBits: 256,
                    tokenID: "SecureEnclave"
                ),
                StateKey(
                    role: "keyAgreement",
                    applicationTagHex: agreementTagData.hexEncodedString(),
                    applicationLabel: agreementLabel,
                    publicKeyX963Hex: agreementPublic.hexEncodedString(),
                    publicKeyX963Length: agreementPublic.count,
                    keyType: agreementStateKeyType,
                    keySizeBits: 256,
                    tokenID: "SecureEnclave"
                )
            ],
            notes: [
                "State is local capability material and must remain 0600 in a 0700 directory.",
                "Keychain application tags and labels are intentionally present only in this state file and never printed to stdout.",
                "Each signing operation reloads the SecKey from Keychain and revalidates type, size, Secure Enclave token, role, and public key binding."
            ]
        )

        try writeJSONExclusive(state, to: outPath)
    } catch {
        try? deleteKey(applicationTag: signingTagData)
        try? deleteKey(applicationTag: agreementTagData)
        throw error
    }

    return SummaryReport(
        phase: "phase3",
        mode: "create-state",
        status: "passed",
        secureEnclaveAvailable: true,
        checksPassed: 7,
        checksFailed: 0,
        materialsPrinted: false,
        summary: "Permanent Secure Enclave SecKey rows created; restricted state written without printing locator material."
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
        summary: "Digest signed through a revalidated Secure Enclave SecKey row; response written to a restricted file."
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
    let (signingKey, signingPublic, agreementPublic) = try loadAndValidateSigningKey(state: state)
    guard signingPublic != agreementPublic else { throw ProbeError.keyValidationFailed }
    guard SecKeyIsAlgorithmSupported(signingKey, .sign, hash.secKeyAlgorithm) else {
        throw ProbeError.unsupportedHash
    }

    var error: Unmanaged<CFError>?
    guard let der = SecKeyCreateSignature(
        signingKey,
        hash.secKeyAlgorithm,
        digest as CFData,
        &error
    ) as Data? else {
        throw securityError(error) ?? ProbeError.signatureFailed
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
        signingHandleReconstructed: true,
        agreementHandleRevalidated: true,
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
    var cleanupTags: [Data] = []
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
            resultPath: nil,
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
            resultPath: nil,
            cleanupPaths: nil
        )
        _ = try performSignDigest(request: bad)
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let missingTag = Data("\(keychainTagPrefix)\(UUID().uuidString.lowercased()).missing".utf8)
        let badSigning = StateKey(
            role: signing.role,
            applicationTagHex: missingTag.hexEncodedString(),
            applicationLabel: signing.applicationLabel,
            publicKeyX963Hex: signing.publicKeyX963Hex,
            publicKeyX963Length: signing.publicKeyX963Length,
            keyType: signing.keyType,
            keySizeBits: signing.keySizeBits,
            tokenID: signing.tokenID
        )
        _ = try loadAndValidateSigningKey(state: replacingStateKey(state, role: "signing", with: badSigning))
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let agreement = try stateKey(state, role: "keyAgreement")
        let badSigning = StateKey(
            role: signing.role,
            applicationTagHex: agreement.applicationTagHex,
            applicationLabel: signing.applicationLabel,
            publicKeyX963Hex: signing.publicKeyX963Hex,
            publicKeyX963Length: signing.publicKeyX963Length,
            keyType: signing.keyType,
            keySizeBits: signing.keySizeBits,
            tokenID: signing.tokenID
        )
        _ = try loadAndValidateSigningKey(state: replacingStateKey(state, role: "signing", with: badSigning))
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let agreement = try stateKey(state, role: "keyAgreement")
        let badSigning = StateKey(
            role: signing.role,
            applicationTagHex: signing.applicationTagHex,
            applicationLabel: signing.applicationLabel,
            publicKeyX963Hex: agreement.publicKeyX963Hex,
            publicKeyX963Length: agreement.publicKeyX963Length,
            keyType: signing.keyType,
            keySizeBits: signing.keySizeBits,
            tokenID: signing.tokenID
        )
        _ = try loadAndValidateSigningKey(state: replacingStateKey(state, role: "signing", with: badSigning))
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let corrupted = StateKey(
            role: signing.role,
            applicationTagHex: "00",
            applicationLabel: signing.applicationLabel,
            publicKeyX963Hex: signing.publicKeyX963Hex,
            publicKeyX963Length: signing.publicKeyX963Length,
            keyType: signing.keyType,
            keySizeBits: signing.keySizeBits,
            tokenID: signing.tokenID
        )
        _ = try loadAndValidateSigningKey(state: replacingStateKey(state, role: "signing", with: corrupted))
    }
    expectFailure {
        let softwareTag = Data("\(keychainTagPrefix)\(UUID().uuidString.lowercased()).software-non-se".utf8)
        cleanupTags.append(softwareTag)
        let softwareKey = try createSoftwarePrivateKey(applicationTag: softwareTag, label: "phase3 non-se failure key", size: 256)
        let softwarePublic = try publicX963(for: softwareKey)
        let signing = try stateKey(state, role: "signing")
        let badSigning = StateKey(
            role: signing.role,
            applicationTagHex: softwareTag.hexEncodedString(),
            applicationLabel: signing.applicationLabel,
            publicKeyX963Hex: softwarePublic.hexEncodedString(),
            publicKeyX963Length: softwarePublic.count,
            keyType: signing.keyType,
            keySizeBits: signing.keySizeBits,
            tokenID: signing.tokenID
        )
        _ = try loadAndValidateSigningKey(state: replacingStateKey(state, role: "signing", with: badSigning))
    }
    expectFailure {
        let wrongSizeTag = Data("\(keychainTagPrefix)\(UUID().uuidString.lowercased()).software-wrong-size".utf8)
        cleanupTags.append(wrongSizeTag)
        let wrongSizeKey = try createSoftwarePrivateKey(applicationTag: wrongSizeTag, label: "phase3 wrong-size failure key", size: 384)
        let wrongSizePublic = try publicX963(for: wrongSizeKey)
        let signing = try stateKey(state, role: "signing")
        let badSigning = StateKey(
            role: signing.role,
            applicationTagHex: wrongSizeTag.hexEncodedString(),
            applicationLabel: signing.applicationLabel,
            publicKeyX963Hex: wrongSizePublic.hexEncodedString(),
            publicKeyX963Length: wrongSizePublic.count,
            keyType: signing.keyType,
            keySizeBits: signing.keySizeBits,
            tokenID: signing.tokenID
        )
        _ = try loadAndValidateSigningKey(state: replacingStateKey(state, role: "signing", with: badSigning))
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

    for tag in cleanupTags {
        try? deleteKey(applicationTag: tag)
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
        summary: "Failure checks exercised restricted files, missing rows, role/tag substitution, invalid digests, public-key mismatch, non-SE/wrong-size keys, corrupted state, and symlink rejection."
    )
}

private func cleanup(requestPath: String) throws -> SummaryReport {
    let request: SigningRequest = try readJSONSecurely(from: requestPath)
    var deleted = 0

    if let state = try? readJSONSecurely(from: request.statePath) as StateFile {
        for key in state.keys {
            if let tag = try? validatedApplicationTag(from: key) {
                try? deleteKey(applicationTag: tag)
            }
        }
    }
    deleted += deleteProbeKeysByPrefix()

    let paths = [request.statePath, request.responsePath, request.resultPath].compactMap { $0 } + (request.cleanupPaths ?? [])
    for path in paths {
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

private func createSecureEnclavePrivateKey(applicationTag: Data, label: String) throws -> SecKey {
    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        &accessError
    ) else {
        throw securityError(accessError) ?? ProbeError.keyGenerationFailed
    }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrLabel as String: label,
            kSecAttrAccessControl as String: access
        ]
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw securityError(error) ?? ProbeError.keyGenerationFailed
    }
    return key
}

private func createSoftwarePrivateKey(applicationTag: Data, label: String, size: Int) throws -> SecKey {
    try? deleteKey(applicationTag: applicationTag)
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: size,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrLabel as String: label
        ]
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw securityError(error) ?? ProbeError.keyGenerationFailed
    }
    return key
}

private func loadAndValidateSigningKey(state: StateFile) throws -> (SecKey, Data, Data) {
    guard state.schema == schema,
          state.secureEnclaveAvailable,
          state.secKeyCreateRandomKeyAvailable,
          state.implementation == "Security SecKey Secure Enclave P-256 permanent Keychain row" else {
        throw ProbeError.invalidState
    }

    let signing = try stateKey(state, role: "signing")
    let agreement = try stateKey(state, role: "keyAgreement")
    let signingKey = try loadPrivateKey(applicationTag: try validatedApplicationTag(from: signing))
    let agreementKey = try loadPrivateKey(applicationTag: try validatedApplicationTag(from: agreement))
    let signingPublic = try validatePrivateKey(signingKey, expected: signing, role: "signing")
    let agreementPublic = try validatePrivateKey(agreementKey, expected: agreement, role: "keyAgreement")
    guard signingPublic != agreementPublic,
          signingPublic.hexEncodedString() == signing.publicKeyX963Hex,
          agreementPublic.hexEncodedString() == agreement.publicKeyX963Hex else {
        throw ProbeError.keyValidationFailed
    }
    return (signingKey, signingPublic, agreementPublic)
}

private func validatePrivateKey(_ key: SecKey, expected: StateKey, role: String) throws -> Data {
    guard expected.role == role,
          expected.keyType == expectedStateKeyType(for: role),
          expected.keySizeBits == 256,
          expected.tokenID == "SecureEnclave" else {
        throw ProbeError.invalidState
    }

    let attributes = try secKeyAttributes(key)
    guard stringAttribute(attributes[kSecAttrKeyType as String]) == (kSecAttrKeyTypeECSECPrimeRandom as String) else {
        throw ProbeError.keyValidationFailed
    }
    guard intAttribute(attributes[kSecAttrKeySizeInBits as String]) == 256 else {
        throw ProbeError.keyValidationFailed
    }
    guard stringAttribute(attributes[kSecAttrTokenID as String]) == (kSecAttrTokenIDSecureEnclave as String) else {
        throw ProbeError.keyValidationFailed
    }

    let publicBytes = try publicX963(for: key)
    let expectedPublic = try hexDecode(expected.publicKeyX963Hex)
    guard publicBytes.count == 65,
          publicBytes.count == expected.publicKeyX963Length,
          publicBytes == expectedPublic else {
        throw ProbeError.keyValidationFailed
    }
    return publicBytes
}

private func expectedStateKeyType(for role: String) -> String {
    switch role {
    case "signing": signingStateKeyType
    case "keyAgreement": agreementStateKeyType
    default: ""
    }
}

private func stateKey(_ state: StateFile, role: String) throws -> StateKey {
    guard let key = state.keys.first(where: { $0.role == role }) else {
        throw ProbeError.invalidState
    }
    return key
}

private func replacingStateKey(_ state: StateFile, role: String, with replacement: StateKey) -> StateFile {
    StateFile(
        schema: state.schema,
        phase: state.phase,
        createdAt: state.createdAt,
        secureEnclaveAvailable: state.secureEnclaveAvailable,
        environment: state.environment,
        instanceId: state.instanceId,
        implementation: state.implementation,
        secKeyCreateRandomKeyAvailable: state.secKeyCreateRandomKeyAvailable,
        keys: state.keys.map { $0.role == role ? replacement : $0 },
        notes: state.notes
    )
}

private func validatedApplicationTag(from key: StateKey) throws -> Data {
    let tag = try hexDecode(key.applicationTagHex)
    guard let tagString = String(data: tag, encoding: .utf8),
          tagString.hasPrefix(keychainTagPrefix) else {
        throw ProbeError.invalidState
    }
    return tag
}

private func loadPrivateKey(applicationTag: Data) throws -> SecKey {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: applicationTag,
        kSecReturnRef as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let key = item as! SecKey? else {
        throw securityError(status) ?? ProbeError.keychainLookupFailed
    }
    return key
}

private func deleteKey(applicationTag: Data) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrApplicationTag as String: applicationTag
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw securityError(status) ?? ProbeError.keychainLookupFailed
    }
}

private func deleteProbeKeysByPrefix() -> Int {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let rows = item as? [[String: Any]] else {
        return 0
    }

    var deleted = 0
    for row in rows {
        guard let tag = row[kSecAttrApplicationTag as String] as? Data,
              let tagString = String(data: tag, encoding: .utf8),
              tagString.hasPrefix(keychainTagPrefix) else {
            continue
        }
        if (try? deleteKey(applicationTag: tag)) != nil {
            deleted += 1
        }
    }
    return deleted
}

private func secKeyAttributes(_ key: SecKey) throws -> [String: Any] {
    guard let attributes = SecKeyCopyAttributes(key) as? [String: Any] else {
        throw ProbeError.keyValidationFailed
    }
    return attributes
}

private func publicX963(for privateKey: SecKey) throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw ProbeError.keyValidationFailed
    }
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        throw securityError(error) ?? ProbeError.keyValidationFailed
    }
    return data
}

private func stringAttribute(_ value: Any?) -> String? {
    if let string = value as? String { return string }
    return nil
}

private func intAttribute(_ value: Any?) -> Int? {
    if let int = value as? Int { return int }
    if let number = value as? NSNumber { return number.intValue }
    return nil
}

private func securityError(_ error: Unmanaged<CFError>?) -> ProbeError? {
    guard let error else { return nil }
    let retained = (error.takeRetainedValue() as Error) as NSError
    if retained.domain == NSOSStatusErrorDomain {
        return securityError(OSStatus(retained.code))
    }
    return ProbeError.keyGenerationFailed
}

private func securityError(_ status: OSStatus) -> ProbeError? {
    switch status {
    case errSecMissingEntitlement:
        return .missingEntitlement
    case errSecItemNotFound:
        return .keychainLookupFailed
    case errSecUnimplemented, errSecNotAvailable:
        return .secureEnclaveUnavailable
    default:
        return nil
    }
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
    while value.count > 1 && value.first == 0 { value.removeFirst() }
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
    if first < 0x80 { return Int(first) }
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
        swiftVersion: swiftVersionString()
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

private extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

do {
    let report = try run()
    print("Phase 3 Secure Enclave signing bridge: \(report.mode) \(report.status)")
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
    print("Phase 3 Secure Enclave signing bridge: failed")
    if let data = try? JSONEncoder().encode(report) {
        print(String(decoding: data, as: UTF8.self))
    }
    exit(1)
}
