import CryptoKit
import Darwin
import Foundation
import Security

private enum Mode: String {
    case emitPublicFixture = "emit-public-fixture"
}

private struct Arguments {
    let mode: Mode
    let out: String
}

private struct Fixture: Encodable {
    let schema: String
    let phase: String
    let createdAt: String
    let secureEnclaveAvailable: Bool
    let environment: Environment
    let keys: [FixtureKey]
    let handleBytesCaptured: Bool
    let privateMaterialCaptured: Bool
    let notes: [String]
}

private struct Environment: Encodable {
    let osVersion: String
    let architecture: String
    let swiftVersion: String
}

private struct FixtureKey: Encodable {
    let role: String
    let algorithm: String
    let curve: String
    let publicKeyEncoding: String
    let publicKeyX963Hex: String
    let publicKeyX963Length: Int
}

private struct SummaryReport: Encodable {
    let phase: String
    let mode: String
    let status: String
    let secureEnclaveAvailable: Bool
    let signingPublicKeyX963Length: Int
    let keyAgreementPublicKeyX963Length: Int
    let fixturePublicKeysDistinct: Bool
    let privateMaterialCaptured: Bool
    let handleBytesCaptured: Bool
    let materialsPrinted: Bool
    let fixturePath: String
}

private enum ProbeError: Error, CustomStringConvertible {
    case invalidArguments(String)
    case writeFailed(String)

    var description: String {
        switch self {
        case .invalidArguments(let message):
            return "invalidArguments:\(message)"
        case .writeFailed(let message):
            return "writeFailed:\(message)"
        }
    }
}

private func parseArguments() throws -> Arguments {
    var mode: Mode?
    var out: String?
    var iterator = CommandLine.arguments.dropFirst().makeIterator()

    while let argument = iterator.next() {
        switch argument {
        case "--":
            continue
        case "--mode":
            guard let value = iterator.next(), let parsed = Mode(rawValue: value) else {
                throw ProbeError.invalidArguments("expected --mode emit-public-fixture")
            }
            mode = parsed
        case "--out":
            guard let value = iterator.next(), !value.isEmpty else {
                throw ProbeError.invalidArguments("expected --out <path>")
            }
            out = value
        default:
            throw ProbeError.invalidArguments("unexpected argument \(argument)")
        }
    }

    guard let mode else {
        throw ProbeError.invalidArguments("missing --mode")
    }
    guard let out else {
        throw ProbeError.invalidArguments("missing --out")
    }
    return Arguments(mode: mode, out: out)
}

private func makeFixture() throws -> Fixture {
    let environment = Environment(
        osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
        architecture: architectureName(),
        swiftVersion: swiftVersionString()
    )

    guard SecureEnclave.isAvailable else {
        return Fixture(
            schema: "cypherair.se-custody.phase2.public-fixture.v1",
            phase: "phase2",
            createdAt: isoNow(),
            secureEnclaveAvailable: false,
            environment: environment,
            keys: [],
            handleBytesCaptured: false,
            privateMaterialCaptured: false,
            notes: [
                "Secure Enclave unavailable; no software fallback attempted."
            ]
        )
    }

    let signingKey = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false)
    let agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: false)

    let signingPublic = signingKey.publicKey.x963Representation
    let agreementPublic = agreementKey.publicKey.x963Representation

    return Fixture(
        schema: "cypherair.se-custody.phase2.public-fixture.v1",
        phase: "phase2",
        createdAt: isoNow(),
        secureEnclaveAvailable: true,
        environment: environment,
        keys: [
            FixtureKey(
                role: "signing",
                algorithm: "ECDSA",
                curve: "NIST P-256",
                publicKeyEncoding: "x963-uncompressed",
                publicKeyX963Hex: signingPublic.hexEncodedString(),
                publicKeyX963Length: signingPublic.count
            ),
            FixtureKey(
                role: "keyAgreement",
                algorithm: "ECDH",
                curve: "NIST P-256",
                publicKeyEncoding: "x963-uncompressed",
                publicKeyX963Hex: agreementPublic.hexEncodedString(),
                publicKeyX963Length: agreementPublic.count
            )
        ],
        handleBytesCaptured: false,
        privateMaterialCaptured: false,
        notes: [
            "Fixture contains public X9.63 key bytes only.",
            "Secure Enclave key handles and private material are not exported or printed."
        ]
    )
}

private func writeFixture(_ fixture: Fixture, to path: String) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(fixture)
    let url = URL(fileURLWithPath: path)
    try FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    do {
        try data.write(to: url, options: .atomic)
    } catch {
        throw ProbeError.writeFailed(error.localizedDescription)
    }
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

private extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

do {
    let arguments = try parseArguments()
    switch arguments.mode {
    case .emitPublicFixture:
        let fixture = try makeFixture()
        try writeFixture(fixture, to: arguments.out)

        let signingKey = fixture.keys.first { $0.role == "signing" }
        let agreementKey = fixture.keys.first { $0.role == "keyAgreement" }
        let signingLength = signingKey?.publicKeyX963Length ?? 0
        let agreementLength = agreementKey?.publicKeyX963Length ?? 0
        let summary = SummaryReport(
            phase: "phase2",
            mode: "emit-public-fixture",
            status: fixture.secureEnclaveAvailable ? "passed" : "skipped",
            secureEnclaveAvailable: fixture.secureEnclaveAvailable,
            signingPublicKeyX963Length: signingLength,
            keyAgreementPublicKeyX963Length: agreementLength,
            fixturePublicKeysDistinct: signingKey?.publicKeyX963Hex != agreementKey?.publicKeyX963Hex,
            privateMaterialCaptured: false,
            handleBytesCaptured: false,
            materialsPrinted: false,
            fixturePath: arguments.out
        )
        let summaryEncoder = JSONEncoder()
        summaryEncoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let summaryData = try summaryEncoder.encode(summary)

        print("Phase 2 Secure Enclave public-key fixture: \(fixture.secureEnclaveAvailable ? "emitted" : "unavailable")")
        print(String(decoding: summaryData, as: UTF8.self))
    }
} catch {
    fputs("Phase2SecureEnclavePublicKeyProbe failed: \(error)\n", stderr)
    exit(1)
}
