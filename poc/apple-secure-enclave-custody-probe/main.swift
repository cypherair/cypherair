import Darwin
import Foundation
import Security

private let bundleIdentifier = Bundle.main.bundleIdentifier
    ?? "com.chentianren.cypherair.poc.secureenclavecustody.probe"
private let fixtureSchema = "com.cypherair.poc.secure-enclave-custody.phase3.fixture.v1"
private let stateSchema = "com.cypherair.poc.secure-enclave-custody.phase3.state.v1"
private let requestSchema = "com.cypherair.poc.secure-enclave-custody.phase3.request.v1"
private let responseSchema = "com.cypherair.poc.secure-enclave-custody.phase3.response.v1"
private let signingRole = "signing"
private let keyAgreementRole = "keyAgreement"
private let sha256Name = "SHA256"
private let tagPrefix = "com.cypherair.poc.secure-enclave-custody.phase3"

enum ProbeError: Error {
    case arguments
    case requestFile
    case filePolicy
    case requestSchema
    case stateSchema
    case keychain
    case secureEnclave
    case keyBinding
    case unsupportedHash
    case digestLength
    case signatureEncoding
    case internalFailure
}

struct BootstrapRequest: Decodable {
    let schema: String?
    let runDirectory: String
    let statePath: String
    let fixturePath: String
}

struct SignDigestRequest: Decodable {
    let schema: String?
    let statePath: String
    let responsePath: String
    let hashAlgorithm: String
    let digestHex: String
    let expectedSigningPublicKeyX963Hex: String
}

struct CleanupRequest: Decodable {
    let schema: String?
    let statePath: String
    let additionalPaths: [String]?
    let removeRunDirectory: Bool?
}

struct FailureRequest: Decodable {
    let schema: String?
    let statePath: String
    let workDirectory: String
}

struct ProbeState: Codable {
    let schema: String
    let runId: String
    let createdAt: String
    let bundleId: String
    let keychainAccessGroup: String
    var keys: [StoredKey]
    let privateMaterialCaptured: Bool
}

struct StoredKey: Codable {
    var role: String
    var algorithm: String
    var curve: String
    var publicKeyEncoding: String
    var publicKeyX963Hex: String
    var publicKeyX963Length: Int
    var applicationTagHex: String
    var label: String
    var keyType: String
    var keySizeInBits: Int
    var tokenID: String
}

struct PublicFixture: Codable {
    struct PublicKey: Codable {
        let role: String
        let algorithm: String
        let curve: String
        let publicKeyEncoding: String
        let publicKeyX963Hex: String
        let publicKeyX963Length: Int
    }

    let schema: String
    let runId: String
    let createdAt: String
    let bundleId: String
    let secureEnclaveAvailable: Bool
    let keychainAccessGroupPresent: Bool
    let keys: [PublicKey]
    let privateMaterialCaptured: Bool
    let keychainLocatorsCaptured: Bool
}

struct SignResponse: Codable {
    let schema: String
    let status: String
    let hashAlgorithm: String
    let signatureEncoding: String
    let rHex: String
    let sHex: String
    let rLength: Int
    let sLength: Int
    let rawSignatureLength: Int
}

struct SignResult {
    let encoding: String
    let r: Data
    let s: Data
}

struct FailureCase: Codable {
    let name: String
    let rejected: Bool
    let errorClass: String
}

func main() {
    do {
        let (mode, requestPath) = try parseArguments()
        switch mode {
        case "bootstrap":
            let report = try bootstrap(requestPath: requestPath)
            printJSON(report)
        case "sign-digest":
            let report = try signDigestMode(requestPath: requestPath)
            printJSON(report)
        case "cleanup":
            let report = try cleanup(requestPath: requestPath)
            printJSON(report)
        case "failure":
            let report = try failureMode(requestPath: requestPath)
            printJSON(report)
        default:
            throw ProbeError.arguments
        }
    } catch {
        printJSON([
            "phase": "phase3",
            "status": "failed",
            "materialsPrinted": false,
            "errorClass": classify(error),
        ])
        exit(1)
    }
}

func parseArguments() throws -> (String, String) {
    var mode: String?
    var request: String?
    var iterator = CommandLine.arguments.dropFirst().makeIterator()
    while let argument = iterator.next() {
        switch argument {
        case "--mode":
            mode = iterator.next()
        case "--request":
            request = iterator.next()
        default:
            throw ProbeError.arguments
        }
    }
    guard let parsedMode = mode, let parsedRequest = request else {
        throw ProbeError.arguments
    }
    return (parsedMode, parsedRequest)
}

func bootstrap(requestPath: String) throws -> [String: Any] {
    let request: BootstrapRequest = try readJSONFile(requestPath)
    try validateRequestSchema(request.schema)
    try validateOwnedDirectory(request.runDirectory, expectedMode: 0o700)
    try requireInsideDirectory(request.statePath, directory: request.runDirectory)
    try requireInsideDirectory(request.fixturePath, directory: request.runDirectory)

    let accessGroup = try currentKeychainAccessGroup()
    let runId = UUID().uuidString.lowercased()
    let createdAt = isoTimestamp()
    let signing = try createSecureEnclaveKey(
        role: signingRole,
        runId: runId,
        accessGroup: accessGroup
    )
    let agreement = try createSecureEnclaveKey(
        role: keyAgreementRole,
        runId: runId,
        accessGroup: accessGroup
    )
    guard signing.publicKeyX963Hex != agreement.publicKeyX963Hex else {
        throw ProbeError.keyBinding
    }

    let state = ProbeState(
        schema: stateSchema,
        runId: runId,
        createdAt: createdAt,
        bundleId: bundleIdentifier,
        keychainAccessGroup: accessGroup,
        keys: [signing, agreement],
        privateMaterialCaptured: false
    )
    let fixture = PublicFixture(
        schema: fixtureSchema,
        runId: runId,
        createdAt: createdAt,
        bundleId: bundleIdentifier,
        secureEnclaveAvailable: true,
        keychainAccessGroupPresent: true,
        keys: [publicKey(from: signing), publicKey(from: agreement)],
        privateMaterialCaptured: false,
        keychainLocatorsCaptured: false
    )

    try writeJSONExclusive(state, to: request.statePath)
    try writeJSONExclusive(fixture, to: request.fixturePath)

    return [
        "phase": "phase3",
        "mode": "bootstrap",
        "status": "passed",
        "secureEnclaveAvailable": true,
        "stateWritten": true,
        "fixtureWritten": true,
        "keyCount": 2,
        "publicKeyX963Lengths": [signing.publicKeyX963Length, agreement.publicKeyX963Length],
        "publicKeysDistinct": true,
        "keychainAccessGroupPresent": true,
        "materialsPrinted": false,
    ]
}

func signDigestMode(requestPath: String) throws -> [String: Any] {
    let request: SignDigestRequest = try readJSONFile(requestPath)
    let result = try signDigest(request)
    let response = SignResponse(
        schema: responseSchema,
        status: "passed",
        hashAlgorithm: sha256Name,
        signatureEncoding: result.encoding,
        rHex: hex(result.r),
        sHex: hex(result.s),
        rLength: result.r.count,
        sLength: result.s.count,
        rawSignatureLength: result.r.count + result.s.count
    )
    try writeJSONExclusive(response, to: request.responsePath)
    return [
        "phase": "phase3",
        "mode": "sign-digest",
        "status": "passed",
        "hashAlgorithm": sha256Name,
        "signatureEncoding": result.encoding,
        "rLength": result.r.count,
        "sLength": result.s.count,
        "signatureWritten": true,
        "materialsPrinted": false,
    ]
}

func cleanup(requestPath: String) throws -> [String: Any] {
    let request: CleanupRequest = try readJSONFile(requestPath)
    try validateRequestSchema(request.schema)
    let state = try readState(request.statePath)
    var deletedKeyRows = 0
    for key in state.keys {
        if try deleteKey(key, accessGroup: state.keychainAccessGroup) {
            deletedKeyRows += 1
        }
    }

    var deletedFiles = 0
    if deletePathIfPresent(request.statePath) {
        deletedFiles += 1
    }
    for path in request.additionalPaths ?? [] where deletePathIfPresent(path) {
        deletedFiles += 1
    }
    if request.removeRunDirectory == true {
        _ = rmdir(parentCString(request.statePath))
    }

    return [
        "phase": "phase3",
        "mode": "cleanup",
        "status": "passed",
        "deletedKeychainRows": deletedKeyRows,
        "deletedCapabilityFiles": deletedFiles,
        "materialsPrinted": false,
    ]
}

func failureMode(requestPath: String) throws -> [String: Any] {
    let request: FailureRequest = try readJSONFile(requestPath)
    try validateRequestSchema(request.schema)
    try validateOwnedDirectory(request.workDirectory, expectedMode: 0o700)
    let state = try readState(request.statePath)
    let signing = try state.key(role: signingRole)
    let agreement = try state.key(role: keyAgreementRole)
    var cases: [FailureCase] = []

    cases.append(runFailureCase("unsupportedHash") {
        var req = validSignRequest(statePath: request.statePath, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        req = SignDigestRequest(schema: requestSchema, statePath: req.statePath, responsePath: req.responsePath, hashAlgorithm: "SHA512", digestHex: req.digestHex, expectedSigningPublicKeyX963Hex: req.expectedSigningPublicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("wrongDigestLength") {
        var req = validSignRequest(statePath: request.statePath, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        req = SignDigestRequest(schema: requestSchema, statePath: req.statePath, responsePath: req.responsePath, hashAlgorithm: sha256Name, digestHex: "00", expectedSigningPublicKeyX963Hex: req.expectedSigningPublicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("wrongExpectedPublic") {
        let req = validSignRequest(statePath: request.statePath, workDirectory: request.workDirectory, publicKeyHex: agreement.publicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("missingKeychainRow") {
        var modified = state
        modified.keys = state.keys.map { key in
            var copy = key
            if copy.role == signingRole {
                copy.applicationTagHex = hex(Data("\(tagPrefix).missing.\(UUID().uuidString)".utf8))
            }
            return copy
        }
        let path = try writeFailureState(modified, in: request.workDirectory)
        let req = validSignRequest(statePath: path, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("substitutedSigningAgreementTag") {
        var modified = state
        modified.keys = state.keys.map { key in
            var copy = key
            if copy.role == signingRole {
                copy.applicationTagHex = agreement.applicationTagHex
                copy.label = agreement.label
            }
            return copy
        }
        let path = try writeFailureState(modified, in: request.workDirectory)
        let req = validSignRequest(statePath: path, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("corruptedState") {
        let path = request.workDirectory + "/corrupted-state.json"
        try writeExclusive(Data("{".utf8), to: path)
        let req = validSignRequest(statePath: path, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("symlinkedState") {
        let path = request.workDirectory + "/symlink-state.json"
        _ = unlink(path)
        guard symlink(request.statePath, path) == 0 else {
            throw ProbeError.filePolicy
        }
        let req = validSignRequest(statePath: path, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("invalidStatePermissions") {
        let path = try writeFailureState(state, in: request.workDirectory)
        guard chmod(path, 0o644) == 0 else {
            throw ProbeError.filePolicy
        }
        let req = validSignRequest(statePath: path, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("nonSecureEnclaveKey") {
        let softwareKey = try createSoftwareKey(runId: state.runId, accessGroup: state.keychainAccessGroup)
        defer {
            _ = try? deleteKey(softwareKey, accessGroup: state.keychainAccessGroup)
        }
        var modified = state
        modified.keys = state.keys.map { key in
            key.role == signingRole ? softwareKey : key
        }
        let path = try writeFailureState(modified, in: request.workDirectory)
        let req = validSignRequest(statePath: path, workDirectory: request.workDirectory, publicKeyHex: softwareKey.publicKeyX963Hex)
        _ = try signDigest(req)
    })
    cases.append(runFailureCase("wrongSizeMetadata") {
        var modified = state
        modified.keys = state.keys.map { key in
            var copy = key
            if copy.role == signingRole {
                copy.keySizeInBits = 384
            }
            return copy
        }
        let path = try writeFailureState(modified, in: request.workDirectory)
        let req = validSignRequest(statePath: path, workDirectory: request.workDirectory, publicKeyHex: signing.publicKeyX963Hex)
        _ = try signDigest(req)
    })

    let passed = cases.allSatisfy(\.rejected)
    return [
        "phase": "phase3",
        "mode": "failure",
        "status": passed ? "passed" : "failed",
        "caseCount": cases.count,
        "cases": try jsonObject(cases),
        "materialsPrinted": false,
    ]
}

func signDigest(_ request: SignDigestRequest) throws -> SignResult {
    try validateRequestSchema(request.schema)
    guard request.hashAlgorithm == sha256Name else {
        throw ProbeError.unsupportedHash
    }
    let digest = try hexDecode(request.digestHex)
    guard digest.count == 32 else {
        throw ProbeError.digestLength
    }
    let expectedPublic = try hexDecode(request.expectedSigningPublicKeyX963Hex)
    try validateX963(expectedPublic)

    let state = try readState(request.statePath)
    let signing = try state.key(role: signingRole)
    let agreement = try state.key(role: keyAgreementRole)
    guard signing.publicKeyX963Hex == request.expectedSigningPublicKeyX963Hex else {
        throw ProbeError.keyBinding
    }
    guard signing.publicKeyX963Hex != agreement.publicKeyX963Hex else {
        throw ProbeError.keyBinding
    }

    let privateKey = try copyPrivateKey(signing, accessGroup: state.keychainAccessGroup)
    try validatePrivateKey(
        privateKey,
        signing: signing,
        agreement: agreement,
        accessGroup: state.keychainAccessGroup
    )

    let rawAlgorithm = SecKeyAlgorithm.ecdsaSignatureDigestRFC4754SHA256
    if SecKeyIsAlgorithmSupported(privateKey, .sign, rawAlgorithm) {
        let signature = try createSignature(privateKey, algorithm: rawAlgorithm, digest: digest)
        guard signature.count == 64 else {
            throw ProbeError.signatureEncoding
        }
        return SignResult(encoding: "ecdsa-rfc4754-raw", r: signature.prefix(32), s: signature.suffix(32))
    }

    let derAlgorithm = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, derAlgorithm) else {
        throw ProbeError.secureEnclave
    }
    let der = try createSignature(privateKey, algorithm: derAlgorithm, digest: digest)
    let (r, s) = try parseDERSignature(der)
    return SignResult(encoding: "ecdsa-x962-der", r: r, s: s)
}

func createSecureEnclaveKey(role: String, runId: String, accessGroup: String) throws -> StoredKey {
    try createKey(role: role, runId: runId, accessGroup: accessGroup, secureEnclave: true, keySize: 256)
}

func createSoftwareKey(runId: String, accessGroup: String) throws -> StoredKey {
    try createKey(role: signingRole, runId: runId, accessGroup: accessGroup, secureEnclave: false, keySize: 256)
}

func createKey(
    role: String,
    runId: String,
    accessGroup: String,
    secureEnclave: Bool,
    keySize: Int
) throws -> StoredKey {
    let tag = "\(tagPrefix).\(runId).\(role).\(UUID().uuidString.lowercased())"
    let label = "CypherAir Secure Enclave Custody Probe \(role) \(runId)"
    let tagData = Data(tag.utf8)
    let accessControl = try privateKeyAccessControl()
    var privateAttributes: [CFString: Any] = [
        kSecAttrIsPermanent: true,
        kSecAttrApplicationTag: tagData,
        kSecAttrLabel: label,
        kSecAttrAccessControl: accessControl,
        kSecAttrAccessGroup: accessGroup,
    ]
    if role == signingRole {
        privateAttributes[kSecAttrCanSign] = true
    }
    var attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: keySize,
        kSecPrivateKeyAttrs: privateAttributes,
        kSecUseDataProtectionKeychain: true,
    ]
    if secureEnclave {
        attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
    }

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw secureEnclave ? ProbeError.secureEnclave : ProbeError.keychain
    }
    let publicKey = try publicX963(from: key)
    return StoredKey(
        role: role,
        algorithm: role == signingRole ? "ECDSA" : "ECDH",
        curve: "NIST P-256",
        publicKeyEncoding: "x963-uncompressed",
        publicKeyX963Hex: hex(publicKey),
        publicKeyX963Length: publicKey.count,
        applicationTagHex: hex(tagData),
        label: label,
        keyType: "ECSECPrimeRandom",
        keySizeInBits: keySize,
        tokenID: secureEnclave ? "SecureEnclave" : "Software"
    )
}

func privateKeyAccessControl() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage,
        &error
    ) else {
        throw ProbeError.secureEnclave
    }
    return accessControl
}

func currentKeychainAccessGroup() throws -> String {
    guard let task = SecTaskCreateFromSelf(kCFAllocatorDefault),
          let value = SecTaskCopyValueForEntitlement(
            task,
            "keychain-access-groups" as CFString,
            nil
          ) else {
        throw ProbeError.keychain
    }
    let groups = value as AnyObject as? [String]
    guard let accessGroup = groups?.first, !accessGroup.isEmpty else {
        throw ProbeError.keychain
    }
    return accessGroup
}

func copyPrivateKey(_ stored: StoredKey, accessGroup: String) throws -> SecKey {
    let tagData = try hexDecode(stored.applicationTagHex)
    let query: [CFString: Any] = [
        kSecClass: kSecClassKey,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag: tagData,
        kSecAttrAccessGroup: accessGroup,
        kSecUseDataProtectionKeychain: true,
        kSecReturnRef: true,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let key = result as! SecKey? else {
        throw ProbeError.keychain
    }
    return key
}

func deleteKey(_ stored: StoredKey, accessGroup: String) throws -> Bool {
    let tagData = try hexDecode(stored.applicationTagHex)
    let query: [CFString: Any] = [
        kSecClass: kSecClassKey,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag: tagData,
        kSecAttrAccessGroup: accessGroup,
        kSecUseDataProtectionKeychain: true,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess {
        return true
    }
    if status == errSecItemNotFound {
        return false
    }
    throw ProbeError.keychain
}

func validatePrivateKey(
    _ privateKey: SecKey,
    signing: StoredKey,
    agreement: StoredKey,
    accessGroup: String
) throws {
    guard signing.role == signingRole,
          agreement.role == keyAgreementRole,
          signing.algorithm == "ECDSA",
          agreement.algorithm == "ECDH",
          signing.curve == "NIST P-256",
          agreement.curve == "NIST P-256",
          signing.keySizeInBits == 256,
          signing.tokenID == "SecureEnclave",
          signing.publicKeyX963Hex != agreement.publicKeyX963Hex else {
        throw ProbeError.keyBinding
    }
    let publicKey = try publicX963(from: privateKey)
    guard hex(publicKey) == signing.publicKeyX963Hex else {
        throw ProbeError.keyBinding
    }
    guard publicKey.count == 65 else {
        throw ProbeError.keyBinding
    }

    guard let attributes = SecKeyCopyAttributes(privateKey) as? [CFString: Any] else {
        throw ProbeError.keychain
    }
    guard cfStringEquals(attributes[kSecAttrKeyType], kSecAttrKeyTypeECSECPrimeRandom),
          intValue(attributes[kSecAttrKeySizeInBits]) == 256,
          cfStringEquals(attributes[kSecAttrTokenID], kSecAttrTokenIDSecureEnclave) else {
        throw ProbeError.keyBinding
    }

    _ = accessGroup
}

func publicX963(from privateKey: SecKey) throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw ProbeError.keychain
    }
    var error: Unmanaged<CFError>?
    guard let representation = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        throw ProbeError.keychain
    }
    try validateX963(representation)
    return representation
}

func createSignature(_ privateKey: SecKey, algorithm: SecKeyAlgorithm, digest: Data) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(privateKey, algorithm, digest as CFData, &error) as Data? else {
        throw ProbeError.secureEnclave
    }
    return signature
}

func parseDERSignature(_ der: Data) throws -> (Data, Data) {
    var offset = 0
    guard readByte(der, &offset) == 0x30 else {
        throw ProbeError.signatureEncoding
    }
    _ = try readASN1Length(der, &offset)
    guard readByte(der, &offset) == 0x02 else {
        throw ProbeError.signatureEncoding
    }
    let rLength = try readASN1Length(der, &offset)
    let rRaw = try readBytes(der, &offset, count: rLength)
    guard readByte(der, &offset) == 0x02 else {
        throw ProbeError.signatureEncoding
    }
    let sLength = try readASN1Length(der, &offset)
    let sRaw = try readBytes(der, &offset, count: sLength)
    return (try fixedWidthInteger(rRaw), try fixedWidthInteger(sRaw))
}

func readASN1Length(_ data: Data, _ offset: inout Int) throws -> Int {
    let first = readByte(data, &offset)
    if first < 0x80 {
        return Int(first)
    }
    let count = Int(first & 0x7f)
    guard count > 0, count <= 2 else {
        throw ProbeError.signatureEncoding
    }
    var length = 0
    for _ in 0..<count {
        length = (length << 8) | Int(readByte(data, &offset))
    }
    return length
}

func fixedWidthInteger(_ raw: Data) throws -> Data {
    var bytes = Array(raw)
    while bytes.first == 0, bytes.count > 1 {
        bytes.removeFirst()
    }
    guard bytes.count <= 32 else {
        throw ProbeError.signatureEncoding
    }
    return Data(repeating: 0, count: 32 - bytes.count) + Data(bytes)
}

func readByte(_ data: Data, _ offset: inout Int) -> UInt8 {
    if offset >= data.count {
        return 0
    }
    let value = data[offset]
    offset += 1
    return value
}

func readBytes(_ data: Data, _ offset: inout Int, count: Int) throws -> Data {
    guard offset + count <= data.count else {
        throw ProbeError.signatureEncoding
    }
    let bytes = data[offset..<(offset + count)]
    offset += count
    return Data(bytes)
}

func readState(_ path: String) throws -> ProbeState {
    let state: ProbeState = try readJSONFile(path)
    guard state.schema == stateSchema,
          state.bundleId == bundleIdentifier,
          state.privateMaterialCaptured == false,
          try state.key(role: signingRole).publicKeyX963Length == 65,
          try state.key(role: keyAgreementRole).publicKeyX963Length == 65 else {
        throw ProbeError.stateSchema
    }
    return state
}

func validSignRequest(statePath: String, workDirectory: String, publicKeyHex: String) -> SignDigestRequest {
    let responsePath = workDirectory + "/response-\(UUID().uuidString.lowercased()).json"
    return SignDigestRequest(
        schema: requestSchema,
        statePath: statePath,
        responsePath: responsePath,
        hashAlgorithm: sha256Name,
        digestHex: String(repeating: "11", count: 32),
        expectedSigningPublicKeyX963Hex: publicKeyHex
    )
}

func writeFailureState(_ state: ProbeState, in directory: String) throws -> String {
    let path = directory + "/state-\(UUID().uuidString.lowercased()).json"
    try writeJSONExclusive(state, to: path)
    return path
}

func runFailureCase(_ name: String, operation: () throws -> Void) -> FailureCase {
    do {
        try operation()
        return FailureCase(name: name, rejected: false, errorClass: "notRejected")
    } catch {
        return FailureCase(name: name, rejected: true, errorClass: classify(error))
    }
}

extension ProbeState {
    func key(role: String) throws -> StoredKey {
        guard let found = keys.first(where: { $0.role == role }) else {
            throw ProbeError.stateSchema
        }
        return found
    }
}

func publicKey(from stored: StoredKey) -> PublicFixture.PublicKey {
    PublicFixture.PublicKey(
        role: stored.role,
        algorithm: stored.algorithm,
        curve: stored.curve,
        publicKeyEncoding: stored.publicKeyEncoding,
        publicKeyX963Hex: stored.publicKeyX963Hex,
        publicKeyX963Length: stored.publicKeyX963Length
    )
}

func readJSONFile<T: Decodable>(_ path: String) throws -> T {
    let data = try readStrictFile(path)
    do {
        return try JSONDecoder().decode(T.self, from: data)
    } catch {
        throw ProbeError.requestSchema
    }
}

func writeJSONExclusive<T: Encodable>(_ value: T, to path: String) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(value)
    try writeExclusive(data, to: path)
}

func jsonObject<T: Encodable>(_ value: T) throws -> Any {
    let data = try JSONEncoder().encode(value)
    return try JSONSerialization.jsonObject(with: data)
}

func readStrictFile(_ path: String) throws -> Data {
    try validateOwnedRegularFile(path, expectedMode: 0o600)
    let fd = open(path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else {
        throw ProbeError.requestFile
    }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    return handle.readDataToEndOfFile()
}

func writeExclusive(_ data: Data, to path: String) throws {
    let parent = (path as NSString).deletingLastPathComponent
    try validateOwnedDirectory(parent, expectedMode: 0o700)
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
    guard fd >= 0 else {
        throw ProbeError.filePolicy
    }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    try handle.write(contentsOf: data)
    guard fchmod(fd, 0o600) == 0 else {
        throw ProbeError.filePolicy
    }
    try handle.close()
}

func validateOwnedDirectory(_ path: String, expectedMode: mode_t) throws {
    let info = try lstatInfo(path)
    guard (info.st_mode & S_IFMT) == S_IFDIR else {
        throw ProbeError.filePolicy
    }
    try validateOwnerAndMode(info, expectedMode: expectedMode)
}

func validateOwnedRegularFile(_ path: String, expectedMode: mode_t) throws {
    let info = try lstatInfo(path)
    guard (info.st_mode & S_IFMT) == S_IFREG else {
        throw ProbeError.filePolicy
    }
    try validateOwnerAndMode(info, expectedMode: expectedMode)
}

func validateOwnerAndMode(_ info: stat, expectedMode: mode_t) throws {
    guard info.st_uid == getuid() else {
        throw ProbeError.filePolicy
    }
    guard (info.st_mode & 0o777) == expectedMode else {
        throw ProbeError.filePolicy
    }
}

func lstatInfo(_ path: String) throws -> stat {
    var info = stat()
    guard lstat(path, &info) == 0 else {
        throw ProbeError.filePolicy
    }
    return info
}

func requireInsideDirectory(_ path: String, directory: String) throws {
    let normalizedPath = URL(fileURLWithPath: path).standardizedFileURL.path
    let normalizedDirectory = URL(fileURLWithPath: directory).standardizedFileURL.path
    guard normalizedPath.hasPrefix(normalizedDirectory + "/") else {
        throw ProbeError.filePolicy
    }
}

func validateRequestSchema(_ schema: String?) throws {
    guard schema == nil || schema == requestSchema else {
        throw ProbeError.requestSchema
    }
}

func validateX963(_ data: Data) throws {
    guard data.count == 65, data.first == 0x04 else {
        throw ProbeError.keyBinding
    }
}

func deletePathIfPresent(_ path: String) -> Bool {
    var info = stat()
    guard lstat(path, &info) == 0 else {
        return false
    }
    return unlink(path) == 0
}

func parentCString(_ path: String) -> UnsafePointer<CChar> {
    let parent = (path as NSString).deletingLastPathComponent
    return (parent as NSString).fileSystemRepresentation
}

func cfStringEquals(_ value: Any?, _ expected: CFString) -> Bool {
    if let string = value as? String {
        return string == (expected as String)
    }
    guard let value else {
        return false
    }
    return CFEqual(value as CFTypeRef, expected)
}

func intValue(_ value: Any?) -> Int? {
    if let int = value as? Int {
        return int
    }
    if let number = value as? NSNumber {
        return number.intValue
    }
    return nil
}

func hexDecode(_ input: String) throws -> Data {
    guard input.count % 2 == 0 else {
        throw ProbeError.requestSchema
    }
    var bytes = Data()
    var index = input.startIndex
    while index < input.endIndex {
        let next = input.index(index, offsetBy: 2)
        guard let byte = UInt8(input[index..<next], radix: 16) else {
            throw ProbeError.requestSchema
        }
        bytes.append(byte)
        index = next
    }
    return bytes
}

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func isoTimestamp() -> String {
    ISO8601DateFormatter().string(from: Date())
}

func classify(_ error: Error) -> String {
    switch error {
    case ProbeError.arguments:
        return "arguments"
    case ProbeError.requestFile:
        return "requestFile"
    case ProbeError.filePolicy:
        return "filePolicy"
    case ProbeError.requestSchema:
        return "requestSchema"
    case ProbeError.stateSchema:
        return "stateSchema"
    case ProbeError.keychain:
        return "keychain"
    case ProbeError.secureEnclave:
        return "secureEnclave"
    case ProbeError.keyBinding:
        return "keyBinding"
    case ProbeError.unsupportedHash:
        return "unsupportedHash"
    case ProbeError.digestLength:
        return "digestLength"
    case ProbeError.signatureEncoding:
        return "signatureEncoding"
    default:
        return "internal"
    }
}

func printJSON(_ object: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

main()
