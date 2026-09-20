import CryptoKit
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

/// Records how the Secure Enclave treats the application-password access-control
/// option on CryptoKit enclave keys, for every key type the vault design uses.
///
/// Password-only access control, so this class runs with no user interaction.
/// Its printed report is the evidence behind the platform-facts section of
/// docs/SECURITY.md. The biometric combination lives in
/// `DeviceApplicationPasswordBiometricProbeTests`, which needs one approval.
final class DeviceApplicationPasswordProbeTests: XCTestCase {
    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")
    }

    func test_passwordOnly_everyKeyType_operationRequiresTheExactCredential() throws {
        var report = ApplicationPasswordProbeReport(title: "password-only access control, per key type")
        let control = try ApplicationPasswordProbe.accessControl([.privateKeyUsage, .applicationPassword])

        for kind in ApplicationPasswordProbeKeyKind.allCases where !kind.isMLKEM {
            let credential = ApplicationPasswordProbe.randomCredential()
            let wrong = ApplicationPasswordProbe.randomCredential()

            var created: ApplicationPasswordProbeKey?
            report.step(kind, "create with credential", expectSuccess: true, tolerateUnsupported: kind.isHighTier) {
                created = try kind.create(control: control, context: ApplicationPasswordProbe.context(credential: credential))
            }
            guard let key = created else { continue }

            report.step(kind, "operate, same credential, fresh context", expectSuccess: true) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: credential))
            }
            report.step(kind, "operate, no credential, interaction disallowed", expectSuccess: false) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: nil))
            }
            report.step(kind, "operate, wrong credential", expectSuccess: false) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: wrong))
            }
            report.step(kind, "operate, right credential again", expectSuccess: true) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: credential))
            }
        }
        report.publish(in: self)
    }

    /// Platform fact, not a design choice: an enclave ML-KEM key created with the
    /// application-password option cannot decapsulate at all, even with the right
    /// credential. CUSTODY.md §4 rests on this. When this test fails, the enclave
    /// has started honouring the option for ML-KEM and the exception should go.
    func test_mlkem_withThePasswordOption_cannotDecapsulate_revisitWhenThisFails() throws {
        var report = ApplicationPasswordProbeReport(title: "ML-KEM with the application-password option")
        let control = try ApplicationPasswordProbe.accessControl([.privateKeyUsage, .applicationPassword])
        for kind in [ApplicationPasswordProbeKeyKind.mlkem768, .mlkem1024] {
            let credential = ApplicationPasswordProbe.randomCredential()
            var created: ApplicationPasswordProbeKey?
            report.step(kind, "create with credential", expectSuccess: true, tolerateUnsupported: kind.isHighTier) {
                created = try kind.create(control: control, context: ApplicationPasswordProbe.context(credential: credential))
            }
            guard let key = created else { continue }
            report.step(kind, "operate, right credential, fresh context", expectSuccess: false) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: credential))
            }
            report.step(kind, "operate, no credential, interaction disallowed", expectSuccess: false) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: nil))
            }
        }
        report.publish(in: self)
    }

    func test_control_mlkemWithoutThePasswordOption_decapsulates() throws {
        var report = ApplicationPasswordProbeReport(title: "control: ML-KEM without the application-password option")
        let control = try ApplicationPasswordProbe.accessControl([.privateKeyUsage])
        for kind in [ApplicationPasswordProbeKeyKind.mlkem768, .mlkem1024] {
            var created: ApplicationPasswordProbeKey?
            report.step(kind, "create without the password option", expectSuccess: true, tolerateUnsupported: kind.isHighTier) {
                created = try kind.create(control: control, context: ApplicationPasswordProbe.context(credential: nil))
            }
            guard let key = created else { continue }
            report.step(kind, "operate, no credential", expectSuccess: true) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: nil))
            }
        }
        report.publish(in: self)
    }

    func test_passwordOnly_creationWithoutCredential_neverYieldsAKeyUsableWithoutOne() throws {
        var report = ApplicationPasswordProbeReport(title: "creation without a credential")
        let control = try ApplicationPasswordProbe.accessControl([.privateKeyUsage, .applicationPassword])

        for kind in ApplicationPasswordProbeKeyKind.allCases where !kind.isHighTier {
            var created: ApplicationPasswordProbeKey?
            report.observe(kind, "create with no credential, interaction disallowed") {
                created = try kind.create(control: control, context: ApplicationPasswordProbe.context(credential: nil))
            }
            guard let key = created else { continue }
            report.step(kind, "operate the credential-less key with no credential", expectSuccess: false) {
                try key.operate(context: ApplicationPasswordProbe.context(credential: nil))
            }
        }
        report.publish(in: self)
    }
}

/// Combines the biometric constraint with the application password. Needs one
/// Touch ID / Face ID approval; asserts that the single authenticated context
/// then covers a second key without another prompt, and that the password stays
/// required even when the biometric constraint is satisfied.
final class DeviceApplicationPasswordBiometricProbeTests: SecureEnclaveCustodyDeviceTestCase {
    func test_biometricAndPassword_oneApprovalCoversTwoKeys_andPasswordStaysRequired() async throws {
        try requireSecureEnclaveCustodyHardware()
        var report = ApplicationPasswordProbeReport(title: "biometric constraint plus application password")
        let control = try ApplicationPasswordProbe.accessControl([.privateKeyUsage, .biometryAny, .applicationPassword])
        let credential = ApplicationPasswordProbe.randomCredential()
        let wrong = ApplicationPasswordProbe.randomCredential()
        let kind = ApplicationPasswordProbeKeyKind.p256KeyAgreement

        let context = try await authenticatedBiometricsContext(
            reason: "Probe: one approval should cover every enclave key in this test."
        )
        defer { context.invalidate() }

        var first: ApplicationPasswordProbeKey?
        report.observe(kind, "create with authenticated context but no credential") {
            first = try kind.create(control: control, context: context)
        }
        if let key = first {
            report.step(kind, "operate the credential-less key, authenticated context", expectSuccess: false) {
                try key.operate(context: context)
            }
        }

        XCTAssertTrue(context.setCredential(credential, type: .applicationPassword))
        var second: ApplicationPasswordProbeKey?
        let creationStart = Date()
        report.step(kind, "create with authenticated context and credential", expectSuccess: true) {
            second = try kind.create(control: control, context: context)
        }
        guard let key = second else { return report.publish(in: self) }
        report.line("creation with the already-authenticated context took \(String(format: "%.2f", Date().timeIntervalSince(creationStart))) s")

        let operateStart = Date()
        report.step(kind, "operate, authenticated context with credential", expectSuccess: true) {
            try key.operate(context: context)
        }
        let elapsed = Date().timeIntervalSince(operateStart)
        report.line("operation with the already-authenticated context took \(String(format: "%.2f", elapsed)) s")
        XCTAssertLessThan(elapsed, 2.0, "a second prompt would have blocked here")

        XCTAssertTrue(context.setCredential(nil, type: .applicationPassword))
        report.step(kind, "operate, authenticated context, credential removed", expectSuccess: false) {
            try key.operate(context: context)
        }
        XCTAssertTrue(context.setCredential(wrong, type: .applicationPassword))
        report.step(kind, "operate, authenticated context, wrong credential", expectSuccess: false) {
            try key.operate(context: context)
        }
        XCTAssertTrue(context.setCredential(credential, type: .applicationPassword))
        report.step(kind, "operate, authenticated context, right credential again", expectSuccess: true) {
            try key.operate(context: context)
        }

        let thirdStart = Date()
        report.step(kind, "create and operate a second key with the same context", expectSuccess: true) {
            try kind.create(control: control, context: context).operate(context: context)
        }
        report.line("second key with the same context took \(String(format: "%.2f", Date().timeIntervalSince(thirdStart))) s")

        report.step(kind, "operate, fresh context with credential but no biometric, interaction disallowed", expectSuccess: false) {
            try key.operate(context: ApplicationPasswordProbe.context(credential: credential))
        }
        report.publish(in: self)
    }
}

// MARK: - Probe support

enum ApplicationPasswordProbeError: Error {
    case resultMismatch
}

struct ApplicationPasswordProbeKey {
    let operate: (LAContext) throws -> Void
    func operate(context: LAContext) throws { try operate(context) }
}

enum ApplicationPasswordProbeKeyKind: String, CaseIterable {
    case p256KeyAgreement = "P-256 key agreement"
    case p256Signing = "P-256 signing"
    case mlkem768 = "ML-KEM-768"
    case mldsa65 = "ML-DSA-65"
    case mlkem1024 = "ML-KEM-1024"
    case mldsa87 = "ML-DSA-87"

    var isHighTier: Bool { self == .mlkem1024 || self == .mldsa87 }
    var isMLKEM: Bool { self == .mlkem768 || self == .mlkem1024 }

    private static let message = Data("CypherAir application-password probe".utf8)

    func create(control: SecAccessControl, context: LAContext) throws -> ApplicationPasswordProbeKey {
        switch self {
        case .p256KeyAgreement:
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control, authenticationContext: context)
            let peer = P256.KeyAgreement.PrivateKey()
            let expected = try peer.sharedSecretFromKeyAgreement(with: key.publicKey).withUnsafeBytes { Data($0) }
            let blob = key.dataRepresentation
            return ApplicationPasswordProbeKey { ctx in
                let reconstructed = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                let secret = try reconstructed.sharedSecretFromKeyAgreement(with: peer.publicKey).withUnsafeBytes { Data($0) }
                guard secret == expected else { throw ApplicationPasswordProbeError.resultMismatch }
            }
        case .p256Signing:
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: control, authenticationContext: context)
            let publicKey = key.publicKey
            let blob = key.dataRepresentation
            return ApplicationPasswordProbeKey { ctx in
                let reconstructed = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                let signature = try reconstructed.signature(for: Self.message)
                guard publicKey.isValidSignature(signature, for: Self.message) else { throw ApplicationPasswordProbeError.resultMismatch }
            }
        case .mlkem768:
            let key = try SecureEnclave.MLKEM768.PrivateKey(accessControl: control, authenticationContext: context)
            let encapsulation = try key.publicKey.encapsulate()
            let expected = encapsulation.sharedSecret.withUnsafeBytes { Data($0) }
            let blob = key.dataRepresentation
            return ApplicationPasswordProbeKey { ctx in
                let reconstructed = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                let secret = try reconstructed.decapsulate(encapsulation.encapsulated).withUnsafeBytes { Data($0) }
                guard secret == expected else { throw ApplicationPasswordProbeError.resultMismatch }
            }
        case .mldsa65:
            let key = try SecureEnclave.MLDSA65.PrivateKey(accessControl: control, authenticationContext: context)
            let publicKey = key.publicKey
            let blob = key.dataRepresentation
            return ApplicationPasswordProbeKey { ctx in
                let reconstructed = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                let signature = try reconstructed.signature(for: Self.message)
                guard publicKey.isValidSignature(signature, for: Self.message) else { throw ApplicationPasswordProbeError.resultMismatch }
            }
        case .mlkem1024:
            let key = try SecureEnclave.MLKEM1024.PrivateKey(accessControl: control, authenticationContext: context)
            let encapsulation = try key.publicKey.encapsulate()
            let expected = encapsulation.sharedSecret.withUnsafeBytes { Data($0) }
            let blob = key.dataRepresentation
            return ApplicationPasswordProbeKey { ctx in
                let reconstructed = try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                let secret = try reconstructed.decapsulate(encapsulation.encapsulated).withUnsafeBytes { Data($0) }
                guard secret == expected else { throw ApplicationPasswordProbeError.resultMismatch }
            }
        case .mldsa87:
            let key = try SecureEnclave.MLDSA87.PrivateKey(accessControl: control, authenticationContext: context)
            let publicKey = key.publicKey
            let blob = key.dataRepresentation
            return ApplicationPasswordProbeKey { ctx in
                let reconstructed = try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                let signature = try reconstructed.signature(for: Self.message)
                guard publicKey.isValidSignature(signature, for: Self.message) else { throw ApplicationPasswordProbeError.resultMismatch }
            }
        }
    }
}

enum ApplicationPasswordProbe {
    static func accessControl(_ flags: SecAccessControlCreateFlags) throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            flags,
            &error
        ) else {
            if let error = error?.takeRetainedValue() { throw error }
            throw ApplicationPasswordProbeError.resultMismatch
        }
        return control
    }

    static func context(credential: Data?) -> LAContext {
        let context = LAContext()
        context.interactionNotAllowed = true
        if let credential {
            precondition(context.setCredential(credential, type: .applicationPassword))
        }
        return context
    }

    static func randomCredential() -> Data {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }
}

struct ApplicationPasswordProbeReport {
    private(set) var lines: [String]

    init(title: String) {
        lines = ["== \(title) =="]
    }

    mutating func line(_ text: String) {
        lines.append(text)
    }

    /// Runs a step whose outcome the design depends on, records it, and asserts it.
    mutating func step(
        _ kind: ApplicationPasswordProbeKeyKind,
        _ name: String,
        expectSuccess: Bool,
        tolerateUnsupported: Bool = false,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () throws -> Void
    ) {
        do {
            try body()
            lines.append("\(kind.rawValue) | \(name) | succeeded\(expectSuccess ? "" : "  <-- UNEXPECTED")")
            XCTAssertTrue(expectSuccess, "\(kind.rawValue): '\(name)' succeeded but was expected to fail", file: file, line: line)
        } catch {
            let described = Self.describe(error)
            if tolerateUnsupported, expectSuccess {
                lines.append("\(kind.rawValue) | \(name) | threw, treated as unsupported on this hardware: \(described)")
                return
            }
            lines.append("\(kind.rawValue) | \(name) | threw: \(described)\(expectSuccess ? "  <-- UNEXPECTED" : "")")
            XCTAssertFalse(expectSuccess, "\(kind.rawValue): '\(name)' threw but was expected to succeed: \(described)", file: file, line: line)
        }
    }

    /// Runs a step whose outcome is unknown beforehand and only records it.
    mutating func observe(_ kind: ApplicationPasswordProbeKeyKind, _ name: String, _ body: () throws -> Void) {
        do {
            try body()
            lines.append("\(kind.rawValue) | \(name) | succeeded")
        } catch {
            lines.append("\(kind.rawValue) | \(name) | threw: \(Self.describe(error))")
        }
    }

    func publish(in testCase: XCTestCase) {
        let text = lines.joined(separator: "\n")
        print("\n=== ApplicationPasswordProbe ===\n\(text)\n=== end ===\n")
        let attachment = XCTAttachment(string: text)
        attachment.name = "ApplicationPasswordProbe"
        attachment.lifetime = .keepAlways
        testCase.add(attachment)
    }

    private static func describe(_ error: Error) -> String {
        let nsError = error as NSError
        return "\(nsError.domain)#\(nsError.code) \(String(describing: error))"
    }
}
