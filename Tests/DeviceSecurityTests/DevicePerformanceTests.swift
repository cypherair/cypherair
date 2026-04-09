import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// C10: Device performance benchmarks.
final class DevicePerformanceTests: DeviceSecurityTestCase {
    // MARK: - C10: Performance Benchmarks

    /// C10.1: Text encryption latency (1 KB) — Profile A (Ed25519+X25519, SEIPDv1).
    /// Threshold: < 50ms. Soft-fail: record and document.
    func test_perf_textEncrypt1KB_profileA_latencyUnder50ms() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.1 A", email: nil, expirySeconds: nil, profile: .universal
        )
        let plaintext = Data(repeating: 0x41, count: 1024) // 1 KB

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )
        }
    }

    /// C10.1: Text encryption latency (1 KB) — Profile B (Ed448+X448, SEIPDv2 AEAD OCB).
    /// Threshold: < 50ms. Soft-fail: record and document.
    func test_perf_textEncrypt1KB_profileB_latencyUnder50ms() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.1 B", email: nil, expirySeconds: nil, profile: .advanced
        )
        let plaintext = Data(repeating: 0x41, count: 1024) // 1 KB

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )
        }
    }

    /// C10.2: 100 MB file encryption — Profile A (X25519, SEIPDv1).
    /// Threshold: < 10s. Soft-fail: record and document.
    /// Uses encryptBinary() (.gpg format) — matches real file encryption workflow.
    func test_perf_fileEncrypt100MB_profileA_latencyUnder10s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.2", email: nil, expirySeconds: nil, profile: .universal
        )
        let fileData = Data(count: 100 * 1024 * 1024) // 100 MB zero-filled

        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = try! engine.encryptBinary(
                plaintext: fileData,
                recipients: [key.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )
        }
    }

    /// C10.3: 100 MB file encryption — Profile B (X448, SEIPDv2 AEAD OCB).
    /// Threshold: < 15s. Soft-fail: record and document.
    /// Uses encryptBinary() (.gpg format) — matches real file encryption workflow.
    func test_perf_fileEncrypt100MB_profileB_latencyUnder15s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.3", email: nil, expirySeconds: nil, profile: .advanced
        )
        let fileData = Data(count: 100 * 1024 * 1024) // 100 MB zero-filled

        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = try! engine.encryptBinary(
                plaintext: fileData,
                recipients: [key.publicKeyData],
                signingKey: nil,
                encryptToSelf: nil
            )
        }
    }

    /// C10.4: Key generation latency — Profile A (Ed25519+X25519).
    /// No hard threshold. Record value.
    func test_perf_keyGeneration_profileA_recordLatency() throws {
        let engine = PgpEngine()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.generateKey(
                name: "Perf C10.4", email: nil, expirySeconds: nil, profile: .universal
            )
        }
    }

    /// C10.5: Key generation latency — Profile B (Ed448+X448).
    /// No hard threshold. Record value.
    /// Note: Ed448 key generation is expected to be significantly slower than Ed25519.
    func test_perf_keyGeneration_profileB_recordLatency() throws {
        let engine = PgpEngine()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.generateKey(
                name: "Perf C10.5", email: nil, expirySeconds: nil, profile: .advanced
            )
        }
    }

    /// C10.6: SE key reconstruction from dataRepresentation.
    /// Threshold: < 10ms. ARCHITECTURE.md documents 2–5ms.
    func test_perf_seKeyReconstruction_latencyUnder10ms() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        // Generate SE key and extract its dataRepresentation for reconstruction.
        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let keyData = handle.dataRepresentation

        let options = XCTMeasureOptions()
        options.iterationCount = 20

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! secureEnclave.reconstructKey(from: keyData)
        }
    }

    /// C10.7: SE wrap/unwrap end-to-end (excluding biometric prompt).
    /// Threshold: < 100ms. Soft-fail: record and document.
    /// Measures: SE P-256 key gen + self-ECDH + HKDF + AES-GCM seal + unwrap cycle.
    func test_perf_seWrapUnwrap_endToEnd_latencyUnder100ms() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fakePrivateKey = Data(repeating: 0xAB, count: 57) // Ed448 size (worst case)
        let fingerprint = uniqueFingerprint()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            let handle = try! secureEnclave.generateWrappingKey(accessControl: nil)
            let bundle = try! secureEnclave.wrap(
                privateKey: fakePrivateKey, using: handle, fingerprint: fingerprint
            )
            let unwrapped = try! secureEnclave.unwrap(
                bundle: bundle, using: handle, fingerprint: fingerprint
            )
            assert(unwrapped == fakePrivateKey)
        }
    }

    /// C10.8: Argon2id calibration time (512 MB / p=4).
    /// Target: ~3s. Soft-fail: record actual value.
    /// Measures exportSecretKey with Profile B, which triggers Argon2id S2K.
    func test_perf_argon2id_512MB_calibrationTime_target3s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf C10.8", email: nil, expirySeconds: nil, profile: .advanced
        )

        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = try! engine.exportSecretKey(
                certData: key.certData,
                passphrase: "benchmark-passphrase",
                profile: .advanced
            )
        }
    }
}
