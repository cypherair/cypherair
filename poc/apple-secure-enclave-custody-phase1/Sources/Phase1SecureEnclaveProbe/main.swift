import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

private let servicePrefix = "com.cypherair.poc.secure-enclave-custody.phase1"
private let account = "phase1-probe"

private enum Mode: String {
    case noninteractive
    case failure
    case manualAuth = "manual-auth"
    case negativeExportCheck = "negative-export-check"
    case cleanup
}

private enum ManualPolicy: String {
    case standard
    case highSecurity

    var laPolicy: LAPolicy {
        switch self {
        case .standard:
            return .deviceOwnerAuthentication
        case .highSecurity:
            return .deviceOwnerAuthenticationWithBiometrics
        }
    }

    var accessFlags: SecAccessControlCreateFlags {
        switch self {
        case .standard:
            return [.privateKeyUsage, .biometryAny, .or, .devicePasscode]
        case .highSecurity:
            return [.privateKeyUsage, .biometryAny]
        }
    }
}

private struct Arguments {
    var mode: Mode = .noninteractive
    var policy: ManualPolicy = .standard
}

private struct ProbeReport: Encodable {
    let phase: String
    let mode: String
    let status: String
    let startedAt: String
    let finishedAt: String
    let secureEnclaveAvailable: Bool
    let environment: Environment
    let checks: [Check]
    let warnings: [String]
    let summary: String
}

private struct Environment: Encodable {
    let osVersion: String
    let architecture: String
    let swiftVersion: String
}

private struct Check: Encodable {
    let name: String
    let status: String
    let details: [String: String]
}

private enum ProbeFailure: Error, CustomStringConvertible {
    case invalidArguments(String)
    case accessControlCreationFailed(String)
    case keychainStatus(operation: String, status: OSStatus)
    case expectedFailureDidNotOccur(String)
    case unexpectedCondition(String)
    case commandLaunchFailed(String)

    var description: String {
        switch self {
        case .invalidArguments(let message):
            return "invalidArguments:\(message)"
        case .accessControlCreationFailed(let context):
            return "accessControlCreationFailed:\(context)"
        case .keychainStatus(let operation, let status):
            return "keychainStatus:\(operation):\(status)"
        case .expectedFailureDidNotOccur(let name):
            return "expectedFailureDidNotOccur:\(name)"
        case .unexpectedCondition(let name):
            return "unexpectedCondition:\(name)"
        case .commandLaunchFailed(let name):
            return "commandLaunchFailed:\(name)"
        }
    }
}

private final class ProbeState {
    var checks: [Check] = []
    var warnings: [String] = []
    private(set) var hasUnexpectedFailure = false

    func pass(_ name: String, _ details: [String: String] = [:]) {
        checks.append(Check(name: name, status: "passed", details: details))
    }

    func observe(_ name: String, _ details: [String: String] = [:]) {
        checks.append(Check(name: name, status: "observed", details: details))
    }

    func skip(_ name: String, _ details: [String: String] = [:]) {
        checks.append(Check(name: name, status: "skipped", details: details))
    }

    func fail(_ name: String, _ details: [String: String] = [:]) {
        hasUnexpectedFailure = true
        checks.append(Check(name: name, status: "failed", details: details))
    }
}

private struct ProbeKeychain {
    func save(_ data: Data, service: String) throws {
        var query: [String: Any] = baseQuery(service: service)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        try withDataProtectionFallback(operation: "save") { usesDataProtection in
            var q = query
            if usesDataProtection {
                q[kSecUseDataProtectionKeychain as String] = true
            }
            let status = SecItemAdd(q as CFDictionary, nil)
            if status == errSecDuplicateItem {
                _ = try? delete(service: service)
                let retryStatus = SecItemAdd(q as CFDictionary, nil)
                return retryStatus
            }
            return status
        }
    }

    func load(service: String) throws -> Data {
        var query: [String: Any] = baseQuery(service: service)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        try withDataProtectionFallback(operation: "load") { usesDataProtection in
            var q = query
            if usesDataProtection {
                q[kSecUseDataProtectionKeychain as String] = true
            }
            return SecItemCopyMatching(q as CFDictionary, &result)
        }
        guard let data = result as? Data else {
            throw ProbeFailure.keychainStatus(operation: "loadResultType", status: errSecInternalError)
        }
        return data
    }

    func delete(service: String) throws {
        let status = try deleteReturningStatus(service: service)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw ProbeFailure.keychainStatus(operation: "delete", status: status)
        }
    }

    func cleanupProbeItems() throws -> Int {
        let services = try listProbeServices()
        var deleted = 0
        for service in services {
            let status = try deleteReturningStatus(service: service)
            if status == errSecSuccess {
                deleted += 1
            } else if status != errSecItemNotFound {
                throw ProbeFailure.keychainStatus(operation: "cleanup", status: status)
            }
        }
        return deleted
    }

    private func listProbeServices() throws -> [String] {
        let standard = try listProbeServices(usesDataProtection: false)
        let dataProtection = try listProbeServices(usesDataProtection: true)
        return Array(Set(standard + dataProtection)).sorted()
    }

    private func listProbeServices(usesDataProtection: Bool) throws -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        if usesDataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        if usesDataProtection && (status == errSecParam || status == errSecMissingEntitlement) {
            return []
        }
        if status != errSecSuccess {
            throw ProbeFailure.keychainStatus(operation: "list", status: status)
        }

        guard let rows = result as? [[String: Any]] else {
            throw ProbeFailure.keychainStatus(operation: "listResultType", status: errSecInternalError)
        }
        return rows.compactMap { row in
            row[kSecAttrService as String] as? String
        }.filter { service in
            service.hasPrefix(servicePrefix)
        }
    }

    private func deleteReturningStatus(service: String) throws -> OSStatus {
        let query = baseQuery(service: service)
        let standardStatus = try withDataProtectionFallbackReturningStatus { usesDataProtection in
            var q = query
            if usesDataProtection {
                q[kSecUseDataProtectionKeychain as String] = true
            }
            return SecItemDelete(q as CFDictionary)
        }
        if standardStatus != errSecItemNotFound {
            return standardStatus
        }

        var dataProtectionQuery = query
        dataProtectionQuery[kSecUseDataProtectionKeychain as String] = true
        let dataProtectionStatus = SecItemDelete(dataProtectionQuery as CFDictionary)
        if dataProtectionStatus == errSecParam || dataProtectionStatus == errSecMissingEntitlement {
            return standardStatus
        }
        return dataProtectionStatus
    }

    private func baseQuery(service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private func withDataProtectionFallback(
        operation: String,
        body: (Bool) throws -> OSStatus
    ) throws {
        let status = try withDataProtectionFallbackReturningStatus(body)
        switch status {
        case errSecSuccess:
            return
        default:
            throw ProbeFailure.keychainStatus(operation: operation, status: status)
        }
    }

    private func withDataProtectionFallbackReturningStatus(
        _ body: (Bool) throws -> OSStatus
    ) throws -> OSStatus {
        let status = try body(false)
        if status == errSecParam || status == errSecMissingEntitlement {
            return try body(true)
        }
        return status
    }
}

private struct ProbeServices {
    let runID = UUID().uuidString.lowercased()

    func service(_ component: String) -> String {
        "\(servicePrefix).\(runID).\(component)"
    }
}

private func parseArguments(_ raw: [String]) throws -> Arguments {
    var args = Arguments()
    var index = 1
    while index < raw.count {
        let value = raw[index]
        switch value {
        case "--":
            break
        case "--mode":
            index += 1
            guard index < raw.count, let mode = Mode(rawValue: raw[index]) else {
                throw ProbeFailure.invalidArguments("missing-or-invalid-mode")
            }
            args.mode = mode
        case "--policy":
            index += 1
            guard index < raw.count, let policy = ManualPolicy(rawValue: raw[index]) else {
                throw ProbeFailure.invalidArguments("missing-or-invalid-policy")
            }
            args.policy = policy
        case "--help", "-h":
            printUsage()
            exit(0)
        default:
            throw ProbeFailure.invalidArguments("unknown-argument")
        }
        index += 1
    }
    return args
}

private func printUsage() {
    print("""
    Phase1SecureEnclaveProbe

    Options:
      --mode noninteractive
      --mode failure
      --mode manual-auth --policy standard
      --mode manual-auth --policy highSecurity
      --mode negative-export-check
      --mode cleanup
    """)
}

private func makeSilentAccessControl() throws -> SecAccessControl {
    try makeAccessControl(
        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags: [.privateKeyUsage],
        context: "silent"
    )
}

private func makeManualAccessControl(policy: ManualPolicy) throws -> SecAccessControl {
    try makeAccessControl(
        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags: policy.accessFlags,
        context: policy.rawValue
    )
}

private func makeAccessControl(
    accessibility: CFString,
    flags: SecAccessControlCreateFlags,
    context: String
) throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        accessibility,
        flags,
        &error
    ) else {
        _ = error?.takeRetainedValue()
        throw ProbeFailure.accessControlCreationFailed(context)
    }
    return accessControl
}

private func runNoninteractive(state: ProbeState) {
    let keychain = ProbeKeychain()
    let services = ProbeServices()
    defer {
        try? keychain.delete(service: services.service("signing"))
        try? keychain.delete(service: services.service("agreement"))
    }

    state.observe("secureEnclave.availability", [
        "available": String(SecureEnclave.isAvailable)
    ])
    guard SecureEnclave.isAvailable else {
        state.skip("secureEnclave.primitiveValidation", [
            "reason": "secure-enclave-unavailable",
            "softwareFallbackCreated": "false"
        ])
        return
    }

    do {
        let accessControl = try makeSilentAccessControl()
        let signingKey = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )
        let agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )
        state.pass("secureEnclave.generateDistinctKeys", [
            "signingHandleBytes": String(signingKey.dataRepresentation.count),
            "agreementHandleBytes": String(agreementKey.dataRepresentation.count),
            "signingPublicKeyBytes": String(signingKey.publicKey.x963Representation.count),
            "agreementPublicKeyBytes": String(agreementKey.publicKey.x963Representation.count),
            "publicKeysDistinct": String(signingKey.publicKey.x963Representation != agreementKey.publicKey.x963Representation),
            "handlesDistinct": String(signingKey.dataRepresentation != agreementKey.dataRepresentation)
        ])

        try keychain.save(signingKey.dataRepresentation, service: services.service("signing"))
        try keychain.save(agreementKey.dataRepresentation, service: services.service("agreement"))
        let persistedSigning = try keychain.load(service: services.service("signing"))
        let persistedAgreement = try keychain.load(service: services.service("agreement"))
        let reconstructedSigning = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: persistedSigning)
        let reconstructedAgreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: persistedAgreement)
        state.pass("secureEnclave.persistAndReconstructHandles", [
            "signingHandleBytes": String(persistedSigning.count),
            "agreementHandleBytes": String(persistedAgreement.count)
        ])

        let message = Data("CypherAir Phase 1 Secure Enclave signing probe".utf8)
        let messageSignature = try reconstructedSigning.signature(for: message)
        let messageVerified = reconstructedSigning.publicKey.isValidSignature(messageSignature, for: message)
        let digest = SHA256.hash(data: message)
        let digestSignature = try reconstructedSigning.signature(for: digest)
        let digestVerified = reconstructedSigning.publicKey.isValidSignature(digestSignature, for: digest)
        if messageVerified && digestVerified {
            state.pass("secureEnclave.signAndVerify", [
                "algorithm": "P-256 ECDSA",
                "messageSignatureRawBytes": String(messageSignature.rawRepresentation.count),
                "digestSignatureRawBytes": String(digestSignature.rawRepresentation.count),
                "messageVerified": String(messageVerified),
                "digestVerified": String(digestVerified)
            ])
        } else {
            state.fail("secureEnclave.signAndVerify", [
                "messageVerified": String(messageVerified),
                "digestVerified": String(digestVerified)
            ])
        }

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secureShared = try reconstructedAgreement.sharedSecretFromKeyAgreement(with: ephemeral.publicKey)
        let softwareShared = try ephemeral.sharedSecretFromKeyAgreement(with: reconstructedAgreement.publicKey)
        var secureDerived = symmetricKeyData(
            secureShared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("phase1-salt".utf8),
                sharedInfo: Data("phase1-shared-info".utf8),
                outputByteCount: 32
            )
        )
        var softwareDerived = symmetricKeyData(
            softwareShared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("phase1-salt".utf8),
                sharedInfo: Data("phase1-shared-info".utf8),
                outputByteCount: 32
            )
        )
        let agreementMatches = secureDerived == softwareDerived
        let derivedByteCount = secureDerived.count
        secureZero(&secureDerived)
        secureZero(&softwareDerived)
        if agreementMatches && derivedByteCount == 32 {
            state.pass("secureEnclave.ecdhAndKdf", [
                "algorithm": "P-256 ECDH + HKDF-SHA256",
                "softwareEphemeralPublicKeyBytes": String(ephemeral.publicKey.x963Representation.count),
                "derivedKeyBytes": String(derivedByteCount),
                "reverseAgreementMatches": String(agreementMatches)
            ])
        } else {
            state.fail("secureEnclave.ecdhAndKdf", [
                "derivedKeyBytes": String(derivedByteCount),
                "reverseAgreementMatches": String(agreementMatches)
            ])
        }

        try keychain.delete(service: services.service("signing"))
        try keychain.delete(service: services.service("agreement"))
        state.pass("secureEnclave.cleanup", [
            "keychainRowsDeleted": "2"
        ])
    } catch {
        state.fail("secureEnclave.noninteractive", [
            "error": sanitize(error)
        ])
    }
}

private func runFailureMode(state: ProbeState) {
    let keychain = ProbeKeychain()
    let services = ProbeServices()
    defer {
        try? keychain.delete(service: services.service("signing"))
        try? keychain.delete(service: services.service("agreement"))
        try? keychain.delete(service: services.service("deleted"))
    }

    do {
        do {
            _ = try keychain.load(service: services.service("missing"))
            state.fail("failure.missingHandle", ["result": "unexpected-load-success"])
        } catch {
            if isItemNotFound(error) {
                state.pass("failure.missingHandle", ["error": "itemNotFound"])
            } else {
                state.fail("failure.missingHandle", ["error": sanitize(error)])
            }
        }

        do {
            _ = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(repeating: 0xA5, count: 32))
            state.fail("failure.corruptedHandle", ["result": "unexpected-reconstruct-success"])
        } catch {
            state.pass("failure.corruptedHandle", ["error": sanitize(error)])
        }

        guard SecureEnclave.isAvailable else {
            state.skip("failure.wrongRoleAndDeletedHandle", [
                "reason": "secure-enclave-unavailable",
                "softwareFallbackCreated": "false"
            ])
            state.pass("failure.unavailableHardwareNoFallback", [
                "secureEnclaveAvailable": "false",
                "softwareFallbackCreated": "false"
            ])
            return
        }

        let accessControl = try makeSilentAccessControl()
        let signingKey = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )
        let agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )

        do {
            let reconstructed = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: signingKey.dataRepresentation)
            let ephemeral = P256.KeyAgreement.PrivateKey()
            _ = try reconstructed.sharedSecretFromKeyAgreement(with: ephemeral.publicKey)
            state.observe("failure.signingHandleAsAgreement", [
                "reconstructionAccepted": "true",
                "operationAccepted": "true",
                "risk": "cryptoKitDoesNotEncodeOpenPGPRole"
            ])
        } catch {
            state.pass("failure.signingHandleAsAgreement", ["error": sanitize(error)])
        }

        do {
            let reconstructed = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: agreementKey.dataRepresentation)
            let message = Data("CypherAir Phase 1 wrong-role signing probe".utf8)
            let signature = try reconstructed.signature(for: message)
            let verified = reconstructed.publicKey.isValidSignature(signature, for: message)
            state.observe("failure.agreementHandleAsSigning", [
                "reconstructionAccepted": "true",
                "operationAccepted": String(verified),
                "risk": "cryptoKitDoesNotEncodeOpenPGPRole"
            ])
        } catch {
            state.pass("failure.agreementHandleAsSigning", ["error": sanitize(error)])
        }

        try keychain.save(signingKey.dataRepresentation, service: services.service("deleted"))
        try keychain.delete(service: services.service("deleted"))
        do {
            _ = try keychain.load(service: services.service("deleted"))
            state.fail("failure.deletedKeychainRow", ["result": "unexpected-load-success"])
        } catch {
            if isItemNotFound(error) {
                state.pass("failure.deletedKeychainRow", ["error": "itemNotFound"])
            } else {
                state.fail("failure.deletedKeychainRow", ["error": sanitize(error)])
            }
        }

        state.skip("failure.unavailableHardwareNoFallback", [
            "reason": "secure-enclave-available-on-this-host",
            "softwareFallbackCreated": "false"
        ])
    } catch {
        state.fail("failure.mode", ["error": sanitize(error)])
    }
}

private func runManualAuth(policy: ManualPolicy, state: ProbeState) {
    let keychain = ProbeKeychain()
    let services = ProbeServices()
    defer {
        try? keychain.delete(service: services.service("manual-signing"))
        try? keychain.delete(service: services.service("manual-agreement"))
    }

    state.observe("manualAuth.policy", [
        "policy": policy.rawValue
    ])
    guard SecureEnclave.isAvailable else {
        state.skip("manualAuth.operations", [
            "reason": "secure-enclave-unavailable",
            "softwareFallbackCreated": "false"
        ])
        return
    }

    let context = LAContext()
    context.localizedReason = "Authenticate to validate CypherAir Phase 1 Secure Enclave primitive behavior."
    if policy == .highSecurity {
        context.localizedFallbackTitle = ""
    }

    var evaluateError: NSError?
    let canEvaluate = context.canEvaluatePolicy(policy.laPolicy, error: &evaluateError)
    state.observe("manualAuth.canEvaluate", [
        "canEvaluate": String(canEvaluate),
        "error": evaluateError.map(sanitizeNSError) ?? "none"
    ])
    guard canEvaluate else {
        if let evaluateError, isLockout(evaluateError) {
            state.observe("manualAuth.lockout", ["error": sanitizeNSError(evaluateError)])
        } else {
            state.skip("manualAuth.operations", ["reason": "policy-not-evaluable"])
        }
        return
    }

    do {
        let accessControl = try makeManualAccessControl(policy: policy)
        let signingKey = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl,
            authenticationContext: context
        )
        let agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl,
            authenticationContext: context
        )
        try keychain.save(signingKey.dataRepresentation, service: services.service("manual-signing"))
        try keychain.save(agreementKey.dataRepresentation, service: services.service("manual-agreement"))

        let signingData = try keychain.load(service: services.service("manual-signing"))
        let agreementData = try keychain.load(service: services.service("manual-agreement"))
        let reconstructedSigning = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: signingData,
            authenticationContext: context
        )
        let reconstructedAgreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: agreementData,
            authenticationContext: context
        )

        let message = Data("CypherAir Phase 1 manual authentication signing probe".utf8)
        let signature = try reconstructedSigning.signature(for: message)
        let signatureVerified = reconstructedSigning.publicKey.isValidSignature(signature, for: message)

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try reconstructedAgreement.sharedSecretFromKeyAgreement(with: ephemeral.publicKey)
        var derived = symmetricKeyData(
            shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("phase1-manual-salt".utf8),
                sharedInfo: Data("phase1-manual-info".utf8),
                outputByteCount: 32
            )
        )
        let derivedCount = derived.count
        secureZero(&derived)

        if signatureVerified && derivedCount == 32 {
            state.pass("manualAuth.operations", [
                "policy": policy.rawValue,
                "signatureVerified": String(signatureVerified),
                "derivedKeyBytes": String(derivedCount)
            ])
        } else {
            state.fail("manualAuth.operations", [
                "signatureVerified": String(signatureVerified),
                "derivedKeyBytes": String(derivedCount)
            ])
        }
    } catch {
        if isUserCancellation(error) {
            state.observe("manualAuth.userCancellation", ["error": sanitize(error)])
        } else if isLockout(error) {
            state.observe("manualAuth.lockout", ["error": sanitize(error)])
        } else {
            state.fail("manualAuth.operations", ["error": sanitize(error)])
        }
    }
}

private func runNegativeExportCheck(state: ProbeState) {
    let fixture = """
    import CryptoKit
    import Security

    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        &error
    )!
    let signingKey = try SecureEnclave.P256.Signing.PrivateKey(
        compactRepresentable: false,
        accessControl: accessControl
    )
    let agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        compactRepresentable: false,
        accessControl: accessControl
    )
    _ = signingKey.dataRepresentation
    _ = agreementKey.dataRepresentation
    _ = signingKey.rawRepresentation
    _ = agreementKey.rawRepresentation
    """

    let fileManager = FileManager.default
    let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("cypherair-phase1-negative-\(UUID().uuidString)", isDirectory: true)
    let fixtureURL = tempRoot.appendingPathComponent("NegativeExportCheck.swift")
    let moduleCacheURL = tempRoot.appendingPathComponent("ModuleCache", isDirectory: true)
    do {
        try fileManager.createDirectory(at: moduleCacheURL, withIntermediateDirectories: true)
        try fixture.write(to: fixtureURL, atomically: true, encoding: .utf8)
        defer {
            try? fileManager.removeItem(at: tempRoot)
        }

        let result = try runProcess(
            executable: "/usr/bin/xcrun",
            arguments: [
                "swiftc",
                "-typecheck",
                "-module-cache-path",
                moduleCacheURL.path,
                fixtureURL.path
            ]
        )
        let diagnostics = result.stdout + "\n" + result.stderr
        let mentionsRawRepresentation = diagnostics.contains("rawRepresentation")
        if result.exitCode != 0 && mentionsRawRepresentation {
            state.pass("negativeExportCheck.rawPrivateScalarUnavailable", [
                "typecheckExitCode": String(result.exitCode),
                "diagnosticMentionsRawRepresentation": String(mentionsRawRepresentation),
                "dataRepresentationStillTypecheckedBeforeFailure": "true"
            ])
        } else {
            state.fail("negativeExportCheck.rawPrivateScalarUnavailable", [
                "typecheckExitCode": String(result.exitCode),
                "diagnosticMentionsRawRepresentation": String(mentionsRawRepresentation)
            ])
        }
    } catch {
        state.fail("negativeExportCheck.command", ["error": sanitize(error)])
    }
}

private func runCleanup(state: ProbeState) {
    do {
        let deleted = try ProbeKeychain().cleanupProbeItems()
        state.pass("cleanup.probeKeychainRows", [
            "deletedRows": String(deleted)
        ])
    } catch {
        state.fail("cleanup.probeKeychainRows", [
            "error": sanitize(error)
        ])
    }
}

private struct ProcessResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

private func runProcess(executable: String, arguments: [String]) throws -> ProcessResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    do {
        try process.run()
    } catch {
        throw ProbeFailure.commandLaunchFailed((executable as NSString).lastPathComponent)
    }
    process.waitUntilExit()

    let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
    let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
    return ProcessResult(
        exitCode: process.terminationStatus,
        stdout: String(data: stdoutData, encoding: .utf8) ?? "",
        stderr: String(data: stderrData, encoding: .utf8) ?? ""
    )
}

private func symmetricKeyData(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes { rawBuffer in
        Data(rawBuffer)
    }
}

private func secureZero(_ data: inout Data) {
    data.resetBytes(in: 0..<data.count)
}

private func isItemNotFound(_ error: Error) -> Bool {
    guard case ProbeFailure.keychainStatus(_, let status) = error else {
        return false
    }
    return status == errSecItemNotFound
}

private func isUserCancellation(_ error: Error) -> Bool {
    let nsError = error as NSError
    if nsError.domain == NSOSStatusErrorDomain && nsError.code == Int(errSecUserCanceled) {
        return true
    }
    if nsError.domain == LAError.errorDomain && nsError.code == LAError.userCancel.rawValue {
        return true
    }
    return "\(error)".localizedCaseInsensitiveContains("cancel")
}

private func isLockout(_ error: Error) -> Bool {
    let nsError = error as NSError
    return isLockout(nsError)
}

private func isLockout(_ error: NSError) -> Bool {
    error.domain == LAError.errorDomain && error.code == LAError.biometryLockout.rawValue
}

private func sanitize(_ error: Error) -> String {
    if let probeFailure = error as? ProbeFailure {
        return probeFailure.description
    }
    return sanitizeNSError(error as NSError)
}

private func sanitizeNSError(_ error: NSError) -> String {
    if error.domain == LAError.errorDomain {
        return "LAError:\(error.code)"
    }
    if error.domain == NSOSStatusErrorDomain {
        return "OSStatus:\(error.code)"
    }
    return "\(error.domain):\(error.code)"
}

private func environment() -> Environment {
    Environment(
        osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
        architecture: machineArchitecture(),
        swiftVersion: swiftVersion()
    )
}

private func machineArchitecture() -> String {
    var systemInfo = utsname()
    uname(&systemInfo)
    let mirror = Mirror(reflecting: systemInfo.machine)
    return mirror.children.reduce(into: "") { result, element in
        guard let value = element.value as? Int8, value != 0 else {
            return
        }
        result.append(Character(UnicodeScalar(UInt8(value))))
    }
}

private func swiftVersion() -> String {
    do {
        let result = try runProcess(executable: "/usr/bin/xcrun", arguments: ["swift", "--version"])
        return result.stdout
            .split(separator: "\n")
            .first
            .map(String.init) ?? "unknown"
    } catch {
        return "unknown"
    }
}

private func finish(mode: Mode, startedAt: String, state: ProbeState) -> Int32 {
    let finishedAt = ISO8601DateFormatter().string(from: Date())
    let status = state.hasUnexpectedFailure ? "failed" : "completed"
    let summary = "\(mode.rawValue): \(status), checks=\(state.checks.count), secureEnclaveAvailable=\(SecureEnclave.isAvailable)"
    let report = ProbeReport(
        phase: "Apple Secure Enclave Custody POC Phase 1",
        mode: mode.rawValue,
        status: status,
        startedAt: startedAt,
        finishedAt: finishedAt,
        secureEnclaveAvailable: SecureEnclave.isAvailable,
        environment: environment(),
        checks: state.checks,
        warnings: state.warnings,
        summary: summary
    )

    print(summary)
    print("JSON_RESULT_BEGIN")
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(report),
       let json = String(data: data, encoding: .utf8) {
        print(json)
    } else {
        print("{\"status\":\"failed\",\"error\":\"json-encoding-failed\"}")
        return 1
    }
    return state.hasUnexpectedFailure ? 1 : 0
}

private let startedAt = ISO8601DateFormatter().string(from: Date())
private let state = ProbeState()
private let args: Arguments
do {
    args = try parseArguments(CommandLine.arguments)
} catch {
    state.fail("arguments.parse", ["error": sanitize(error)])
    let code = finish(mode: .noninteractive, startedAt: startedAt, state: state)
    exit(code)
}

switch args.mode {
case .noninteractive:
    runNoninteractive(state: state)
case .failure:
    runFailureMode(state: state)
case .manualAuth:
    runManualAuth(policy: args.policy, state: state)
case .negativeExportCheck:
    runNegativeExportCheck(state: state)
case .cleanup:
    runCleanup(state: state)
}

let code = finish(mode: args.mode, startedAt: startedAt, state: state)
exit(code)
