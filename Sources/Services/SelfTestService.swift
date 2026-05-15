import Foundation

/// One-tap self-diagnostic covering both profiles:
/// key generation → encrypt/decrypt → sign/verify → tamper detection → QR round-trip.
///
/// Results are kept as an in-memory export-only report.
@Observable
final class SelfTestService {

    /// Individual test result.
    struct TestResult: Identifiable {
        let id = UUID()
        let name: String
        let profile: PGPKeyProfile?
        let passed: Bool
        let message: String
        let duration: TimeInterval
    }

    /// Overall test run state.
    enum RunState {
        case idle
        case running(progress: Double)
        case completed(results: [TestResult])
        case failed(error: Error)
    }

    /// In-memory report prepared for explicit user export.
    struct SelfTestReport: Equatable {
        let data: Data
        let suggestedFilename: String
    }

    /// Current state of the self-test run.
    private(set) var state: RunState = .idle

    /// Most recent report data, retained only in process memory.
    private(set) var latestReport: SelfTestReport?

    private let engine: PgpEngine
    private let messageAdapter: PGPMessageOperationAdapter

    init(
        engine: PgpEngine,
        messageAdapter: PGPMessageOperationAdapter? = nil
    ) {
        self.engine = engine
        self.messageAdapter = messageAdapter ?? PGPMessageOperationAdapter(engine: engine)
    }

    // MARK: - Run Self-Test

    /// Run the complete self-test suite for both profiles.
    /// Heavy crypto work is delegated to `@concurrent` helpers so progress
    /// updates remain responsive while crypto stays off the main actor.
    func runAllTests() async {
        latestReport = nil
        state = .running(progress: 0)

        let engine = self.engine
        let messageAdapter = self.messageAdapter
        var results: [TestResult] = []
        let profiles = PGPKeyProfile.allCases
        let totalTests = profiles.count * 5 + 1 // 5 tests per profile + 1 QR test
        var completedTests = 0

        for profile in profiles {
            // Test 1: Key generation
            let genResult = await runTest(
                name: String(localized: "selftest.name.keyGeneration", defaultValue: "Key Generation"),
                profile: profile
            ) {
                try await Self.runKeyGenerationTest(engine: engine, profile: profile)
            }
            results.append(genResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Need key data for subsequent tests
            guard genResult.passed, var generated = genResult.value else { continue }
            defer {
                // Best-effort zeroing of self-test key material per CLAUDE.md #5.
                generated.certData.resetBytes(in: 0..<generated.certData.count)
                generated.revocationCert.resetBytes(in: 0..<generated.revocationCert.count)
            }

            // Test 2: Encrypt/Decrypt round-trip
            let encDecResult = await runTest(
                name: String(localized: "selftest.name.encryptDecrypt", defaultValue: "Encrypt/Decrypt"),
                profile: profile
            ) {
                try await Self.runEncryptDecryptTest(
                    messageAdapter: messageAdapter,
                    generated: generated
                )
            }
            results.append(encDecResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Test 3: Sign/Verify round-trip
            let signResult = await runTest(
                name: String(localized: "selftest.name.signVerify", defaultValue: "Sign/Verify"),
                profile: profile
            ) {
                try await Self.runSignVerifyTest(
                    messageAdapter: messageAdapter,
                    generated: generated
                )
            }
            results.append(signResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Test 4: Tamper detection (1-bit flip)
            let tamperResult = await runTest(
                name: String(localized: "selftest.name.tamperDetection", defaultValue: "Tamper Detection"),
                profile: profile
            ) {
                try await Self.runTamperDetectionTest(
                    messageAdapter: messageAdapter,
                    generated: generated
                )
            }
            results.append(tamperResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Test 5: Key export/import round-trip
            let exportResult = await runTest(
                name: String(localized: "selftest.name.exportImport", defaultValue: "Export/Import"),
                profile: profile
            ) {
                try await Self.runExportImportTest(
                    engine: engine,
                    generated: generated,
                    profile: profile
                )
            }
            results.append(exportResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))
        }

        // QR URL round-trip test (profile-agnostic, use first generated key)
        let qrResult = await runTest(
            name: String(localized: "selftest.name.qrRoundTrip", defaultValue: "QR URL Encode/Decode"),
            profile: nil
        ) {
            try await Self.runQrRoundTripTest(engine: engine)
        }
        results.append(qrResult.result)
        completedTests += 1
        state = .running(progress: Double(completedTests) / Double(totalTests))

        latestReport = Self.makeReport(results: results)
        state = .completed(results: results)
    }

    func clearLatestReport() {
        latestReport = nil
    }

    // MARK: - Private Helpers

    private struct TestOutput<T> {
        let result: TestResult
        let passed: Bool
        let value: T?
    }

    private func runTest<T>(
        name: String,
        profile: PGPKeyProfile?,
        operation: () async throws -> T
    ) async -> TestOutput<T> {
        let start = Date()
        do {
            let value = try await operation()
            let duration = Date().timeIntervalSince(start)
            let result = TestResult(
                name: name,
                profile: profile,
                passed: true,
                message: String(localized: "selftest.result.passed", defaultValue: "Passed"),
                duration: duration
            )
            return TestOutput(result: result, passed: true, value: value)
        } catch {
            let duration = Date().timeIntervalSince(start)
            let result = TestResult(
                name: name,
                profile: profile,
                passed: false,
                message: error.localizedDescription,
                duration: duration
            )
            return TestOutput(result: result, passed: false, value: nil)
        }
    }

    @concurrent
    private static func runKeyGenerationTest(
        engine: PgpEngine,
        profile: PGPKeyProfile
    ) async throws -> GeneratedKey {
        let generated = try engine.generateKey(
            name: "Self-Test",
            email: "test@cypherair.local",
            expirySeconds: 3600,
            profile: profile.ffiValue
        )
        let info = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        guard info.keyVersion == profile.keyVersion else {
            throw CypherAirError.corruptData(
                reason: "Wrong key version: expected \(profile.keyVersion), got \(info.keyVersion)"
            )
        }
        return generated
    }

    @concurrent
    private static func runEncryptDecryptTest(
        messageAdapter: PGPMessageOperationAdapter,
        generated: GeneratedKey
    ) async throws -> DetailedSignatureVerification {
        let plaintext = Data("Self-test 自检 🔐".utf8)
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: plaintext,
            recipientKeys: [generated.publicKeyData],
            signingKey: generated.certData,
            selfKey: nil,
            binary: false
        )
        let decrypted = try await messageAdapter.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationContext: verificationContext(for: generated)
        )
        guard decrypted.plaintext == plaintext else {
            throw CypherAirError.corruptData(reason: "Plaintext mismatch after round-trip")
        }
        guard decrypted.verification.legacyStatus == .valid else {
            throw CypherAirError.badSignature
        }
        return decrypted.verification
    }

    @concurrent
    private static func runSignVerifyTest(
        messageAdapter: PGPMessageOperationAdapter,
        generated: GeneratedKey
    ) async throws -> DetailedSignatureVerification {
        let text = Data("Signed message 签名消息".utf8)
        let signed = try await messageAdapter.signCleartext(
            text: text,
            signerCert: generated.certData
        )
        let verified = try await messageAdapter.verifyCleartextDetailed(
            signedMessage: signed,
            verificationContext: verificationContext(for: generated)
        )
        guard verified.text == text else {
            throw CypherAirError.corruptData(reason: "Signed text mismatch after verification")
        }
        guard verified.verification.legacyStatus == .valid else {
            throw CypherAirError.badSignature
        }
        return verified.verification
    }

    @concurrent
    private static func runTamperDetectionTest(
        messageAdapter: PGPMessageOperationAdapter,
        generated: GeneratedKey
    ) async throws -> Bool {
        let plaintext = Data("Tamper test".utf8)
        var ciphertext = try await messageAdapter.encrypt(
            plaintext: plaintext,
            recipientKeys: [generated.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: false
        )

        let midpoint = ciphertext.count / 2
        ciphertext[midpoint] ^= 0x01

        let decryptSucceeded: Bool
        do {
            _ = try await messageAdapter.decryptDetailed(
                ciphertext: ciphertext,
                secretKeys: [generated.certData],
                verificationContext: PGPMessageVerificationContext(
                    verificationKeys: [],
                    contacts: [],
                    ownKeys: [],
                    contactsAvailability: .availableLegacyCompatibility
                )
            )
            decryptSucceeded = true
        } catch {
            decryptSucceeded = false
        }

        guard !decryptSucceeded else {
            throw CypherAirError.corruptData(reason: "Tampered ciphertext was not rejected")
        }

        return true
    }

    private static func verificationContext(for generated: GeneratedKey) -> PGPMessageVerificationContext {
        PGPMessageVerificationContext(
            verificationKeys: [generated.publicKeyData],
            contacts: [],
            ownKeys: [],
            contactsAvailability: .availableLegacyCompatibility
        )
    }

    @concurrent
    private static func runExportImportTest(
        engine: PgpEngine,
        generated: GeneratedKey,
        profile: PGPKeyProfile
    ) async throws -> PGPKeyMetadata {
        let passphrase = "self-test-passphrase-2024"
        var exported = try engine.exportSecretKey(
            certData: generated.certData,
            passphrase: passphrase,
            profile: profile.ffiValue
        )
        var imported = try engine.importSecretKey(
            armoredData: exported,
            passphrase: passphrase
        )
        defer {
            exported.resetBytes(in: 0..<exported.count)
            imported.resetBytes(in: 0..<imported.count)
        }
        let originalInfo = try engine.parseKeyInfo(keyData: generated.certData)
        let importedInfo = try engine.parseKeyInfo(keyData: imported)
        guard originalInfo.fingerprint == importedInfo.fingerprint else {
            throw CypherAirError.corruptData(reason: "Fingerprint mismatch after export/import")
        }
        return PGPKeyMetadataAdapter.metadata(from: importedInfo)
    }

    @concurrent
    private static func runQrRoundTripTest(engine: PgpEngine) async throws -> PGPKeyMetadata {
        var generated = try engine.generateKey(
            name: "QR-Test",
            email: nil,
            expirySeconds: 3600,
            profile: PGPKeyProfile.universal.ffiValue
        )
        defer {
            generated.certData.resetBytes(in: 0..<generated.certData.count)
            generated.revocationCert.resetBytes(in: 0..<generated.revocationCert.count)
        }
        let url = try engine.encodeQrUrl(publicKeyData: generated.publicKeyData)
        let decoded = try engine.decodeQrUrl(url: url)
        let originalInfo = try engine.parseKeyInfo(keyData: generated.publicKeyData)
        let decodedInfo = try engine.parseKeyInfo(keyData: decoded)
        guard originalInfo.fingerprint == decodedInfo.fingerprint else {
            throw CypherAirError.corruptData(reason: "QR round-trip fingerprint mismatch")
        }
        return PGPKeyMetadataAdapter.metadata(from: decodedInfo)
    }

    private static func makeReport(results: [TestResult], date: Date = Date()) -> SelfTestReport {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd_HHmmss"
        let filename = "CypherAir-SelfTest-Report-\(dateFormatter.string(from: date)).txt"

        var report = String(localized: "selftest.report.title", defaultValue: "CypherAir Self-Test Report") + "\n"
        let dateString = String(describing: date)
        report += String(localized: "selftest.report.date", defaultValue: "Date: \(dateString)") + "\n"
        report += "========================\n\n"

        let passed = results.filter { $0.passed }.count
        report += String(localized: "selftest.report.summary", defaultValue: "Results: \(passed)/\(results.count) passed") + "\n\n"

        let passStr = String(localized: "selftest.report.pass", defaultValue: "PASS")
        let failStr = String(localized: "selftest.report.fail", defaultValue: "FAIL")
        let generalStr = String(localized: "selftest.report.general", defaultValue: "General")

        for result in results {
            let profileStr = result.profile?.displayName ?? generalStr
            let statusStr = result.passed ? passStr : failStr
            report += "[\(statusStr)] \(profileStr) — \(result.name)"
            report += " (\(String(format: "%.3f", result.duration))s)"
            if !result.passed {
                report += "\n  " + String(localized: "selftest.report.error", defaultValue: "Error: \(result.message)")
            }
            report += "\n"
        }

        return SelfTestReport(
            data: Data(report.utf8),
            suggestedFilename: filename
        )
    }
}
