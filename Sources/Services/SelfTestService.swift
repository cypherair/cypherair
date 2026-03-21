import Foundation

/// One-tap self-diagnostic covering both profiles:
/// key generation → encrypt/decrypt → sign/verify → tamper detection → QR round-trip.
///
/// Results are stored as a shareable report in Documents/self-test/.
@Observable
final class SelfTestService {

    /// Individual test result.
    struct TestResult: Identifiable {
        let id = UUID()
        let name: String
        let profile: KeyProfile?
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

    /// Current state of the self-test run.
    private(set) var state: RunState = .idle

    /// URL of the most recently saved report, for sharing.
    private(set) var lastReportURL: URL?

    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    // MARK: - Run Self-Test

    /// Run the complete self-test suite for both profiles.
    /// Heavy crypto work runs via synchronous `runTest` calls which execute
    /// on the caller's actor context, while state updates go via MainActor.
    func runAllTests() async {
        state = .running(progress: 0)

        let engine = self.engine
        var results: [TestResult] = []
        let profiles: [KeyProfile] = [.universal, .advanced]
        let totalTests = profiles.count * 5 + 1 // 5 tests per profile + 1 QR test
        var completedTests = 0

        for profile in profiles {
            // Test 1: Key generation
            let genResult = runTest(
                name: String(localized: "selftest.name.keyGeneration", defaultValue: "Key Generation"),
                profile: profile
            ) {
                let generated = try engine.generateKey(
                    name: "Self-Test",
                    email: "test@cypherair.local",
                    expirySeconds: 3600,
                    profile: profile
                )
                let info = try engine.parseKeyInfo(keyData: generated.publicKeyData)
                guard info.keyVersion == profile.keyVersion else {
                    throw CypherAirError.corruptData(reason: "Wrong key version: expected \(profile.keyVersion), got \(info.keyVersion)")
                }
                return generated
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
            let encDecResult = runTest(
                name: String(localized: "selftest.name.encryptDecrypt", defaultValue: "Encrypt/Decrypt"),
                profile: profile
            ) {
                let plaintext = Data("Self-test 自检 🔐".utf8)
                let ciphertext = try engine.encrypt(
                    plaintext: plaintext,
                    recipients: [generated.publicKeyData],
                    signingKey: generated.certData,
                    encryptToSelf: nil
                )
                let decrypted = try engine.decrypt(
                    ciphertext: ciphertext,
                    secretKeys: [generated.certData],
                    verificationKeys: [generated.publicKeyData]
                )
                guard decrypted.plaintext == plaintext else {
                    throw CypherAirError.corruptData(reason: "Plaintext mismatch after round-trip")
                }
                return decrypted
            }
            results.append(encDecResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Test 3: Sign/Verify round-trip
            let signResult = runTest(
                name: String(localized: "selftest.name.signVerify", defaultValue: "Sign/Verify"),
                profile: profile
            ) {
                let text = Data("Signed message 签名消息".utf8)
                let signed = try engine.signCleartext(
                    text: text,
                    signerCert: generated.certData
                )
                let verified = try engine.verifyCleartext(
                    signedMessage: signed,
                    verificationKeys: [generated.publicKeyData]
                )
                guard verified.status == .valid else {
                    throw CypherAirError.badSignature
                }
                return verified
            }
            results.append(signResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Test 4: Tamper detection (1-bit flip)
            let tamperResult = runTest(
                name: String(localized: "selftest.name.tamperDetection", defaultValue: "Tamper Detection"),
                profile: profile
            ) {
                let plaintext = Data("Tamper test".utf8)
                var ciphertext = try engine.encrypt(
                    plaintext: plaintext,
                    recipients: [generated.publicKeyData],
                    signingKey: nil,
                    encryptToSelf: nil
                )

                // Flip one bit near the middle
                let midpoint = ciphertext.count / 2
                ciphertext[midpoint] ^= 0x01

                let decryptSucceeded: Bool
                do {
                    _ = try engine.decrypt(
                        ciphertext: ciphertext,
                        secretKeys: [generated.certData],
                        verificationKeys: []
                    )
                    decryptSucceeded = true
                } catch {
                    // Any error = decryption correctly rejected tampered data
                    decryptSucceeded = false
                }
                guard !decryptSucceeded else {
                    throw CypherAirError.corruptData(reason: "Tampered ciphertext was not rejected")
                }
                return true
            }
            results.append(tamperResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))

            // Test 5: Key export/import round-trip
            let exportResult = runTest(
                name: String(localized: "selftest.name.exportImport", defaultValue: "Export/Import"),
                profile: profile
            ) {
                let passphrase = "self-test-passphrase-2024"
                var exported = try engine.exportSecretKey(
                    certData: generated.certData,
                    passphrase: passphrase,
                    profile: profile
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
                return importedInfo
            }
            results.append(exportResult.result)
            completedTests += 1
            state = .running(progress: Double(completedTests) / Double(totalTests))
        }

        // QR URL round-trip test (profile-agnostic, use first generated key)
        let qrResult = runTest(name: String(localized: "selftest.name.qrRoundTrip", defaultValue: "QR URL Encode/Decode"), profile: nil) {
            // Generate a fresh key for QR test
            var generated = try engine.generateKey(
                name: "QR-Test",
                email: nil,
                expirySeconds: 3600,
                profile: .universal
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
            return decodedInfo
        }
        results.append(qrResult.result)
        completedTests += 1
        state = .running(progress: Double(completedTests) / Double(totalTests))

        // Save report
        saveReport(results: results)
        state = .completed(results: results)
    }

    // MARK: - Private Helpers

    private struct TestOutput<T> {
        let result: TestResult
        let passed: Bool
        let value: T?
    }

    private func runTest<T>(
        name: String,
        profile: KeyProfile?,
        operation: () throws -> T
    ) -> TestOutput<T> {
        let start = Date()
        do {
            let value = try operation()
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

    private func saveReport(results: [TestResult]) {
        let fm = FileManager.default
        let docsDir = fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let reportDir = docsDir.appendingPathComponent("self-test", isDirectory: true)

        try? fm.createDirectory(at: reportDir, withIntermediateDirectories: true)

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd_HHmmss"
        let filename = "self-test-\(dateFormatter.string(from: Date())).txt"
        let fileURL = reportDir.appendingPathComponent(filename)

        var report = String(localized: "selftest.report.title", defaultValue: "CypherAir Self-Test Report") + "\n"
        let dateString = String(describing: Date())
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

        do {
            try report.write(to: fileURL, atomically: true, encoding: .utf8)
            lastReportURL = fileURL
        } catch {
            lastReportURL = nil
        }
    }
}
