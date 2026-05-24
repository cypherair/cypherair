import CryptoKit
import Darwin
import Foundation

private let schema = "cypherair.se-custody.phase3.signing-state.v1"
private let requestSchema = "cypherair.se-custody.phase3.signing-request.v1"
private let responseSchema = "cypherair.se-custody.phase3.signing-response.v1"

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
    let handleRepresentationHex: String
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
    case keyGenerationFailed
    case keyReconstructionFailed
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
        case .keyGenerationFailed: "keyGenerationFailed"
        case .keyReconstructionFailed: "keyReconstructionFailed"
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
}

private struct ExternalSHA256Digest: Digest {
    static let byteCount = 32
    let bytes: [UInt8]
    init(_ data: Data) throws {
        guard data.count == Self.byteCount else { throw ProbeError.wrongDigestLength }
        bytes = Array(data)
    }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    var description: String { "ExternalSHA256Digest" }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    static func == (lhs: Self, rhs: Self) -> Bool { lhs.bytes == rhs.bytes }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
}

private struct ExternalSHA384Digest: Digest {
    static let byteCount = 48
    let bytes: [UInt8]
    init(_ data: Data) throws {
        guard data.count == Self.byteCount else { throw ProbeError.wrongDigestLength }
        bytes = Array(data)
    }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    var description: String { "ExternalSHA384Digest" }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    static func == (lhs: Self, rhs: Self) -> Bool { lhs.bytes == rhs.bytes }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
}

private struct ExternalSHA512Digest: Digest {
    static let byteCount = 64
    let bytes: [UInt8]
    init(_ data: Data) throws {
        guard data.count == Self.byteCount else { throw ProbeError.wrongDigestLength }
        bytes = Array(data)
    }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    var description: String { "ExternalSHA512Digest" }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    static func == (lhs: Self, rhs: Self) -> Bool { lhs.bytes == rhs.bytes }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
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

    guard SecureEnclave.isAvailable else {
        let state = StateFile(
            schema: schema,
            phase: "phase3",
            createdAt: isoNow(),
            secureEnclaveAvailable: false,
            environment: environment(),
            instanceId: nil,
            implementation: "CryptoKit SecureEnclave P-256 handle",
            secKeyCreateRandomKeyAvailable: false,
            keys: [],
            notes: ["Secure Enclave unavailable; no software fallback attempted."]
        )
        try writeJSONExclusive(state, to: outPath)
        return SummaryReport(
            phase: "phase3",
            mode: "create-state",
            status: "skipped",
            secureEnclaveAvailable: false,
            checksPassed: 1,
            checksFailed: 0,
            materialsPrinted: false,
            summary: "Secure Enclave unavailable; state records no fallback."
        )
    }

    let signingKey = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false)
    let agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: false)
    let signingPublic = signingKey.publicKey.x963Representation
    let agreementPublic = agreementKey.publicKey.x963Representation
    guard signingPublic != agreementPublic else { throw ProbeError.keyValidationFailed }

    let state = StateFile(
        schema: schema,
        phase: "phase3",
        createdAt: isoNow(),
        secureEnclaveAvailable: true,
        environment: environment(),
        instanceId: UUID().uuidString.lowercased(),
        implementation: "CryptoKit SecureEnclave P-256 handle",
        secKeyCreateRandomKeyAvailable: false,
        keys: [
            StateKey(
                role: "signing",
                handleRepresentationHex: signingKey.dataRepresentation.hexEncodedString(),
                publicKeyX963Hex: signingPublic.hexEncodedString(),
                publicKeyX963Length: signingPublic.count,
                keyType: "SecureEnclave.P256.Signing.PrivateKey",
                keySizeBits: 256,
                tokenID: "SecureEnclave"
            ),
            StateKey(
                role: "keyAgreement",
                handleRepresentationHex: agreementKey.dataRepresentation.hexEncodedString(),
                publicKeyX963Hex: agreementPublic.hexEncodedString(),
                publicKeyX963Length: agreementPublic.count,
                keyType: "SecureEnclave.P256.KeyAgreement.PrivateKey",
                keySizeBits: 256,
                tokenID: "SecureEnclave"
            )
        ],
        notes: [
            "State is local capability material and must remain 0600 in a 0700 directory.",
            "The local SwiftPM command-line environment returned errSecMissingEntitlement for SecKeyCreateRandomKey with Secure Enclave token, so this bridge uses CryptoKit SecureEnclave handles while retaining the Phase 3 no-argv-digest and per-signature public-key revalidation requirements.",
            "Stdout intentionally omits handles, paths, digests, signatures, and stable fingerprints."
        ]
    )

    try writeJSONExclusive(state, to: outPath)

    return SummaryReport(
        phase: "phase3",
        mode: "create-state",
        status: "passed",
        secureEnclaveAvailable: true,
        checksPassed: 5,
        checksFailed: 0,
        materialsPrinted: false,
        summary: "Secure Enclave signing and agreement handles created; sensitive state written with restricted permissions."
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
        checksPassed: 6,
        checksFailed: 0,
        materialsPrinted: false,
        summary: "Digest signed through a revalidated Secure Enclave handle; response written to a restricted file."
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
    let (key, signingPublic, agreementPublic) = try loadAndValidateSigningKey(state: state)
    guard signingPublic != agreementPublic else { throw ProbeError.keyValidationFailed }

    let signature: P256.Signing.ECDSASignature
    switch hash {
    case .sha256:
        signature = try key.signature(for: ExternalSHA256Digest(digest))
    case .sha384:
        signature = try key.signature(for: ExternalSHA384Digest(digest))
    case .sha512:
        signature = try key.signature(for: ExternalSHA512Digest(digest))
    }

    let (r, s) = try parseECDSADER(signature.derRepresentation)
    return SigningResponse(
        schema: responseSchema,
        status: "passed",
        hashAlgorithm: hash.rawValue,
        digestByteLength: digest.count,
        derSignatureByteLength: signature.derRepresentation.count,
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
        var swapped = state
        let signing = try stateKey(state, role: "signing")
        let agreement = try stateKey(state, role: "keyAgreement")
        swapped = StateFile(
            schema: state.schema,
            phase: state.phase,
            createdAt: state.createdAt,
            secureEnclaveAvailable: state.secureEnclaveAvailable,
            environment: state.environment,
            instanceId: state.instanceId,
            implementation: state.implementation,
            secKeyCreateRandomKeyAvailable: state.secKeyCreateRandomKeyAvailable,
            keys: [
                StateKey(
                    role: "signing",
                    handleRepresentationHex: agreement.handleRepresentationHex,
                    publicKeyX963Hex: signing.publicKeyX963Hex,
                    publicKeyX963Length: signing.publicKeyX963Length,
                    keyType: signing.keyType,
                    keySizeBits: signing.keySizeBits,
                    tokenID: signing.tokenID
                ),
                agreement
            ],
            notes: state.notes
        )
        _ = try loadAndValidateSigningKey(state: swapped)
    }
    expectFailure {
        var mismatched = state
        let signing = try stateKey(state, role: "signing")
        let agreement = try stateKey(state, role: "keyAgreement")
        mismatched = StateFile(
            schema: state.schema,
            phase: state.phase,
            createdAt: state.createdAt,
            secureEnclaveAvailable: state.secureEnclaveAvailable,
            environment: state.environment,
            instanceId: state.instanceId,
            implementation: state.implementation,
            secKeyCreateRandomKeyAvailable: state.secKeyCreateRandomKeyAvailable,
            keys: [
                StateKey(
                    role: "signing",
                    handleRepresentationHex: signing.handleRepresentationHex,
                    publicKeyX963Hex: agreement.publicKeyX963Hex,
                    publicKeyX963Length: agreement.publicKeyX963Length,
                    keyType: signing.keyType,
                    keySizeBits: signing.keySizeBits,
                    tokenID: signing.tokenID
                ),
                agreement
            ],
            notes: state.notes
        )
        _ = try loadAndValidateSigningKey(state: mismatched)
    }
    expectFailure {
        let signing = try stateKey(state, role: "signing")
        let agreement = try stateKey(state, role: "keyAgreement")
        let corrupted = StateFile(
            schema: state.schema,
            phase: state.phase,
            createdAt: state.createdAt,
            secureEnclaveAvailable: state.secureEnclaveAvailable,
            environment: state.environment,
            instanceId: state.instanceId,
            implementation: state.implementation,
            secKeyCreateRandomKeyAvailable: state.secKeyCreateRandomKeyAvailable,
            keys: [
                StateKey(
                    role: "signing",
                    handleRepresentationHex: "00",
                    publicKeyX963Hex: signing.publicKeyX963Hex,
                    publicKeyX963Length: signing.publicKeyX963Length,
                    keyType: signing.keyType,
                    keySizeBits: signing.keySizeBits,
                    tokenID: signing.tokenID
                ),
                agreement
            ],
            notes: state.notes
        )
        _ = try loadAndValidateSigningKey(state: corrupted)
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
        summary: "Failure checks exercised restricted files, role substitution, invalid digests, public-key mismatch, corrupted handles, and symlink rejection."
    )
}

private func cleanup(requestPath: String) throws -> SummaryReport {
    let request: SigningRequest = try readJSONSecurely(from: requestPath)
    var deleted = 0
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
        summary: "Temp capability files were removed where present."
    )
}

private func loadAndValidateSigningKey(state: StateFile) throws -> (
    SecureEnclave.P256.Signing.PrivateKey,
    Data,
    Data
) {
    guard state.schema == schema, state.secureEnclaveAvailable else { throw ProbeError.invalidState }
    let signing = try stateKey(state, role: "signing")
    let agreement = try stateKey(state, role: "keyAgreement")
    guard signing.keyType == "SecureEnclave.P256.Signing.PrivateKey",
          agreement.keyType == "SecureEnclave.P256.KeyAgreement.PrivateKey",
          signing.keySizeBits == 256,
          agreement.keySizeBits == 256,
          signing.tokenID == "SecureEnclave",
          agreement.tokenID == "SecureEnclave",
          signing.publicKeyX963Length == 65,
          agreement.publicKeyX963Length == 65,
          signing.publicKeyX963Hex != agreement.publicKeyX963Hex else {
        throw ProbeError.invalidState
    }

    let signingHandle = try hexDecode(signing.handleRepresentationHex)
    let agreementHandle = try hexDecode(agreement.handleRepresentationHex)
    let signingKey: SecureEnclave.P256.Signing.PrivateKey
    let agreementKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        signingKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signingHandle)
        agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: agreementHandle)
    } catch {
        throw ProbeError.keyReconstructionFailed
    }

    let signingPublic = signingKey.publicKey.x963Representation
    let agreementPublic = agreementKey.publicKey.x963Representation
    guard signingPublic.hexEncodedString() == signing.publicKeyX963Hex,
          agreementPublic.hexEncodedString() == agreement.publicKeyX963Hex,
          signingPublic != agreementPublic else {
        throw ProbeError.keyValidationFailed
    }
    return (signingKey, signingPublic, agreementPublic)
}

private func stateKey(_ state: StateFile, role: String) throws -> StateKey {
    guard let key = state.keys.first(where: { $0.role == role }) else {
        throw ProbeError.invalidState
    }
    return key
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
