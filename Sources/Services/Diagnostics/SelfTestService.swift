import Foundation

/// One-tap self-diagnostic covering all software suites:
/// key generation → encrypt/decrypt → sign/verify → tamper detection → QR round-trip.
///
/// Results are kept as an in-memory export-only report.
@Observable
final class SelfTestService {

    /// Individual test result.
    struct TestResult: Identifiable {
        let id = UUID()
        let name: String
        let suite: PGPKeySuite?
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

    /// Report held in process memory, prepared for explicit user export. Saving
    /// one stages it through the shared export path like any other artifact.
    struct SelfTestReport: Equatable {
        let data: Data
        let exportFilename: ExportFilename
    }

    /// Current state of the self-test run.
    private(set) var state: RunState = .idle

    /// Most recent report data, retained only in process memory.
    private(set) var latestReport: SelfTestReport?

    private let selfTestAdapter: PGPSelfTestOperationAdapter
    private let messageAdapter: PGPMessageOperationAdapter
    private let memoryInfo: any MemoryInfoProvidable

    init(
        selfTestAdapter: PGPSelfTestOperationAdapter,
        messageAdapter: PGPMessageOperationAdapter,
        memoryInfo: any MemoryInfoProvidable = SystemMemoryInfo()
    ) {
        self.selfTestAdapter = selfTestAdapter
        self.messageAdapter = messageAdapter
        self.memoryInfo = memoryInfo
    }

    // MARK: - Run Self-Test

    /// Run the complete self-test pass for all software suites.
    /// Heavy crypto work is delegated to FFI adapters so progress
    /// updates remain responsive while crypto stays off the main actor.
    func runAllTests() async {
        latestReport = nil
        state = .running(progress: 0)

        let selfTestAdapter = self.selfTestAdapter
        let messageAdapter = self.messageAdapter
        var results: [TestResult] = []
        let suites = PGPKeySuite.allCases
        let totalTests = suites.count * 5 + 1 // 5 tests per suite + 1 QR test
        var completedTests = 0

        for suite in suites {
            // Test 1: Key generation
            let genResult = await runTest(
                name: String(localized: "selftest.name.keyGeneration", defaultValue: "Key Generation"),
                suite: suite
            ) {
                try await Self.runKeyGenerationTest(
                    selfTestAdapter: selfTestAdapter,
                    suite: suite
                )
            }
            results.append(genResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Need key data for subsequent tests
            guard genResult.passed, var generated = genResult.value else { continue }
            defer {
                // Best-effort zeroing of self-test key material.
                generated.zeroizeSensitiveMaterial()
            }

            // Test 2: Encrypt/Decrypt round-trip
            let encDecResult = await runTest(
                name: String(localized: "selftest.name.encryptDecrypt", defaultValue: "Encrypt/Decrypt"),
                suite: suite
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
                suite: suite
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
                suite: suite
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
                suite: suite
            ) {
                try await Self.runExportImportTest(
                    selfTestAdapter: selfTestAdapter,
                    memoryInfo: memoryInfo,
                    generated: generated,
                    suite: suite
                )
            }
            results.append(exportResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))
        }

        // QR URL round-trip test (suite-agnostic, use first generated key)
        let qrResult = await runTest(
            name: String(localized: "selftest.name.qrRoundTrip", defaultValue: "QR URL Encode/Decode"),
            suite: nil
        ) {
            try await Self.runQrRoundTripTest(selfTestAdapter: selfTestAdapter)
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
        suite: PGPKeySuite?,
        operation: () async throws -> T
    ) async -> TestOutput<T> {
        let start = Date()
        do {
            let value = try await operation()
            let duration = Date().timeIntervalSince(start)
            let result = TestResult(
                name: name,
                suite: suite,
                passed: true,
                message: String(localized: "selftest.result.passed", defaultValue: "Passed"),
                duration: duration
            )
            return TestOutput(result: result, passed: true, value: value)
        } catch {
            let duration = Date().timeIntervalSince(start)
            let result = TestResult(
                name: name,
                suite: suite,
                passed: false,
                message: error.localizedDescription,
                duration: duration
            )
            return TestOutput(result: result, passed: false, value: nil)
        }
    }

    private static func runKeyGenerationTest(
        selfTestAdapter: PGPSelfTestOperationAdapter,
        suite: PGPKeySuite
    ) async throws -> PGPSelfTestGeneratedKey {
        let generated = try await selfTestAdapter.generateKey(
            name: "Self-Test",
            email: "test@cypherair.local",
            validity: .expiresIn(seconds: 3600),
            suite: suite
        )
        guard generated.keyVersion == suite.keyVersion else {
            throw CypherAirError.corruptData(
                reason: "Wrong key version: expected \(suite.keyVersion), got \(generated.keyVersion)"
            )
        }
        return generated
    }

    private static func runEncryptDecryptTest(
        messageAdapter: PGPMessageOperationAdapter,
        generated: PGPSelfTestGeneratedKey
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
        guard decrypted.verification.summaryState == .verified else {
            throw CypherAirError.badSignature
        }
        return decrypted.verification
    }

    private static func runSignVerifyTest(
        messageAdapter: PGPMessageOperationAdapter,
        generated: PGPSelfTestGeneratedKey
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
        guard verified.verification.summaryState == .verified else {
            throw CypherAirError.badSignature
        }
        return verified.verification
    }

    /// Flip one byte inside the encryption container and require the container's
    /// own authentication to be what rejects it — the AEAD tag of SEIPDv2 for a
    /// v6 recipient, the MDC of SEIPDv1 for a v4 one. That hard fail is Hard
    /// Constraint 3, and it is the only thing this test is entitled to claim.
    ///
    /// The message is therefore encrypted binary, and the flipped byte is its
    /// last — always inside the SEIPD packet's authenticated region. An
    /// ASCII-armored message would put the flip on a base64 character instead,
    /// where the armor decoder rejects a good share of flips before the
    /// ciphertext is ever authenticated: a rejection that proves nothing about
    /// authenticated encryption.
    ///
    /// The same ciphertext is decrypted untampered first. That leaves exactly one
    /// difference between the run that succeeds and the run that fails — one byte
    /// inside the authenticated region — so the rejection is attributable to the
    /// container's authentication and not to the key, the format, or the parser.
    /// It is also what lets `noMatchingKey` count as a pass for a v6 recipient:
    /// Sequoia authenticates the first chunk while probing a candidate session
    /// key, and a failed probe is reported as "no key worked" rather than as an
    /// AEAD failure. With the untampered decryption succeeding on the same key,
    /// that answer can only have come from the AEAD tag.
    private static func runTamperDetectionTest(
        messageAdapter: PGPMessageOperationAdapter,
        generated: PGPSelfTestGeneratedKey
    ) async throws -> Bool {
        let tamperVerificationContext = PGPMessageVerificationContext(
            verificationKeys: [],
            contactKeys: [],
            ownKeys: [],
            contactsAvailability: .availableProtectedDomain
        )
        let plaintext = Data("Tamper test".utf8)
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: plaintext,
            recipientKeys: [generated.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )
        let untamperedDecryption = try await messageAdapter.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [generated.certData],
            verificationContext: tamperVerificationContext
        )
        guard untamperedDecryption.plaintext == plaintext else {
            throw CypherAirError.corruptData(reason: "Untampered ciphertext did not round-trip")
        }

        var tamperedCiphertext = ciphertext
        guard let finalByteIndex = tamperedCiphertext.indices.last else {
            throw CypherAirError.corruptData(reason: "Encryption produced no ciphertext to tamper with")
        }
        tamperedCiphertext[finalByteIndex] ^= 0x01

        do {
            _ = try await messageAdapter.decryptDetailed(
                ciphertext: tamperedCiphertext,
                secretKeys: [generated.certData],
                verificationContext: tamperVerificationContext
            )
        } catch CypherAirError.aeadAuthenticationFailed,
                CypherAirError.integrityCheckFailed,
                CypherAirError.noMatchingKey {
            return true
        }

        throw CypherAirError.corruptData(reason: "Tampered ciphertext was not rejected")
    }

    private static func verificationContext(for generated: PGPSelfTestGeneratedKey) -> PGPMessageVerificationContext {
        PGPMessageVerificationContext(
            verificationKeys: [generated.publicKeyData],
            contactKeys: [],
            ownKeys: [],
            contactsAvailability: .availableProtectedDomain
        )
    }

    private static func runExportImportTest(
        selfTestAdapter: PGPSelfTestOperationAdapter,
        memoryInfo: any MemoryInfoProvidable,
        generated: PGPSelfTestGeneratedKey,
        suite: PGPKeySuite
    ) async throws -> PGPKeyMetadata {
        // The self-test runs a real export and a real import, so it runs the
        // real Argon2id derivation twice. A device that cannot afford it should
        // report that as the diagnostic result, not be terminated producing one.
        try Argon2idMemoryGuard(memoryInfo: memoryInfo).validate(
            protectionInfo: selfTestAdapter.exportProtectionInfo(suite: suite)
        )

        let passphrase = "self-test-passphrase-2024"
        var exported = try await selfTestAdapter.exportSecretKey(
            certData: generated.certData,
            passphrase: passphrase
        )
        var imported = try await selfTestAdapter.importSecretKey(
            armoredData: exported,
            passphrase: passphrase
        )
        defer {
            exported.resetBytes(in: 0..<exported.count)
            imported.resetBytes(in: 0..<imported.count)
        }
        let originalMetadata = try await selfTestAdapter.metadata(forKeyData: generated.certData)
        let importedMetadata = try await selfTestAdapter.metadata(forKeyData: imported)
        guard originalMetadata.fingerprint == importedMetadata.fingerprint else {
            throw CypherAirError.corruptData(reason: "Fingerprint mismatch after export/import")
        }
        return importedMetadata
    }

    private static func runQrRoundTripTest(
        selfTestAdapter: PGPSelfTestOperationAdapter
    ) async throws -> PGPKeyMetadata {
        var generated = try await selfTestAdapter.generateKey(
            name: "QR-Test",
            email: nil,
            validity: .expiresIn(seconds: 3600),
            suite: .ed25519LegacyCurve25519Legacy
        )
        defer {
            generated.zeroizeSensitiveMaterial()
        }
        let url = try await selfTestAdapter.encodeQrUrl(publicKeyData: generated.publicKeyData)
        let decoded = try await selfTestAdapter.decodeQrUrl(url)
        let originalMetadata = try await selfTestAdapter.metadata(forKeyData: generated.publicKeyData)
        let decodedMetadata = try await selfTestAdapter.metadata(forKeyData: decoded)
        guard originalMetadata.fingerprint == decodedMetadata.fingerprint else {
            throw CypherAirError.corruptData(reason: "QR round-trip fingerprint mismatch")
        }
        return decodedMetadata
    }

    private static func makeReport(results: [TestResult], date: Date = Date()) -> SelfTestReport {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd_HHmmss"
        let filename = ExportFilename(
            "CypherAir-X-SelfTest-Report-\(dateFormatter.string(from: date)).txt"
        )

        var report = String(localized: "selftest.report.title", defaultValue: "CypherAir X Self-Test Report") + "\n"
        let dateString = String(describing: date)
        report += String(localized: "selftest.report.date", defaultValue: "Date: \(dateString)") + "\n"
        report += "========================\n\n"

        let passed = results.filter { $0.passed }.count
        report += String(localized: "selftest.report.summary", defaultValue: "Results: \(passed)/\(results.count) passed") + "\n\n"

        let passStr = String(localized: "selftest.report.pass", defaultValue: "PASS")
        let failStr = String(localized: "selftest.report.fail", defaultValue: "FAIL")
        let generalStr = String(localized: "selftest.report.general", defaultValue: "General")

        for result in results {
            let suiteStr = result.suite.map(localizedSuiteName(for:)) ?? generalStr
            let statusStr = result.passed ? passStr : failStr
            report += "[\(statusStr)] \(suiteStr) — \(result.name)"
            report += " (\(String(format: "%.3f", result.duration))s)"
            if !result.passed {
                report += "\n  " + String(localized: "selftest.report.error", defaultValue: "Error: \(result.message)")
            }
            report += "\n"
        }

        return SelfTestReport(
            data: Data(report.utf8),
            exportFilename: filename
        )
    }

    private static func localizedSuiteName(for suite: PGPKeySuite) -> String {
        // Derive from the family vocabulary so new suites are covered
        // automatically and the report name never drifts from the picker.
        suite.portableFamily.familyDisplayName
    }
}
