import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// Device performance benchmarks.
final class DevicePerformanceTests: DeviceSecurityTestCase {
    // MARK: - Performance Benchmarks

    /// Text encryption latency (1 KB) — Legacy (Ed25519+X25519, SEIPDv1).
    /// Threshold: < 50ms. Soft-fail: record and document.
    func test_perf_textEncrypt1KB_legacy_latencyUnder50ms() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf A", email: nil, validity: .never, suite: .ed25519LegacyCurve25519Legacy
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

    /// Text encryption latency (1 KB) — Modern High (Ed448+X448, SEIPDv2 AEAD OCB).
    /// Threshold: < 50ms. Soft-fail: record and document.
    func test_perf_textEncrypt1KB_modernHigh_latencyUnder50ms() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf B", email: nil, validity: .never, suite: .ed448X448
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

    /// 100 MB file encryption — Legacy (X25519, SEIPDv1).
    /// Threshold: < 10s. Soft-fail: record and document.
    /// Uses encryptBinary() (.gpg format) — matches real file encryption workflow.
    func test_perf_fileEncrypt100MB_legacy_latencyUnder10s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf", email: nil, validity: .never, suite: .ed25519LegacyCurve25519Legacy
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

    /// 100 MB file encryption — Modern High (X448, SEIPDv2 AEAD OCB).
    /// Threshold: < 15s. Soft-fail: record and document.
    /// Uses encryptBinary() (.gpg format) — matches real file encryption workflow.
    func test_perf_fileEncrypt100MB_modernHigh_latencyUnder15s() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf", email: nil, validity: .never, suite: .ed448X448
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

    /// Key generation latency — Legacy (Ed25519+X25519).
    /// No hard threshold. Record value.
    func test_perf_keyGeneration_legacy_recordLatency() throws {
        let engine = PgpEngine()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.generateKey(
                name: "Perf", email: nil, validity: .never, suite: .ed25519LegacyCurve25519Legacy
            )
        }
    }

    /// Key generation latency — Modern High (Ed448+X448).
    /// No hard threshold. Record value.
    /// Note: Ed448 key generation is expected to be significantly slower than Ed25519.
    func test_perf_keyGeneration_modernHigh_recordLatency() throws {
        let engine = PgpEngine()

        let options = XCTMeasureOptions()
        options.iterationCount = 10

        measure(metrics: [XCTClockMetric()], options: options) {
            _ = try! engine.generateKey(
                name: "Perf", email: nil, validity: .never, suite: .ed448X448
            )
        }
    }

    /// Argon2id calibration time at the shipped export parameters
    /// (2 GiB / t=1 / p=4). Recorded, not asserted — the point is the number,
    /// and the memory metric matters as much as the clock here.
    /// Measures exportSecretKey with Modern High, which triggers Argon2id S2K.
    func test_perf_argon2id_exportCalibrationTime() throws {
        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "Perf", email: nil, validity: .never, suite: .ed448X448
        )

        let options = XCTMeasureOptions()
        options.iterationCount = 3

        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()], options: options) {
            _ = try! engine.exportSecretKey(
                certData: key.certData,
                passphrase: "benchmark-passphrase"
            )
        }
    }
}
