import CryptoKit
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

// macOS-only: this harness spawns the `gpg` binary via Foundation.Process, which is
// unavailable on iOS/iPadOS. The guard keeps the shared test target compiling for
// on-device (iPhone/iPad) runs of the other device plans.
#if os(macOS)

/// Manual macOS-only evidence harness: a REAL Secure Enclave custody v4 key
/// interoperating bidirectionally with the local `gpg` binary, through the
/// production external signer and key-agreement seams. This is the production
/// successor to the POC `gnupg-interop --request` mode — without the POC's
/// raw-shared-secret response file (the in-process callback bridges carry the
/// private operations).
///
/// It is intentionally selected ONLY by `CypherAir-InteropEvidenceTests` and is
/// excluded from `CypherAir-UnitTests` and the device plans. It requires real
/// Secure Enclave hardware + enrolled biometrics (one approval) AND a local `gpg`
/// binary. GnuPG cannot run on iOS/iPadOS, so this automated lane is macOS-only;
/// iPhone/iPad gpg interop follows the documented manual cross-device procedure in
/// docs/APPLE_SECURE_ENCLAVE_CUSTODY_EVIDENCE.md.
///
/// Run: xcodebuild test -scheme CypherAir \
///        -testPlan CypherAir-InteropEvidenceTests \
///        -destination 'platform=macOS,arch=arm64e'
final class DeviceSecureEnclaveGnuPGInteropEvidenceTests: SecureEnclaveCustodyDeviceTestCase {
    func test_realSecureEnclaveV4_bidirectionalGnuPGInterop_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()
        let gpg = try requireGpg()

        let handleStore = SecureEnclaveCustodyHandleStore(keyStore: SystemSecureEnclaveCustodyKeyStore())
        let pair = try handleStore.createHandlePair()
        defer {
            try? handleStore.deleteHandlePair(pair)
        }

        // One biometric approval covers loading + signing + key agreement.
        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate Secure Enclave custody GnuPG interop."
        )
        defer {
            context.invalidate()
        }

        let signingKey = try loadPrivateKey(reference: pair.signing.reference, authenticationContext: context)
        let keyAgreementKey = try loadPrivateKey(
            reference: pair.keyAgreement.reference,
            authenticationContext: context
        )
        let loadedPair = try SecureEnclaveCustodyLoadedHandlePair(
            signing: SecureEnclaveCustodyLoadedHandle(binding: pair.signing, privateKey: signingKey),
            keyAgreement: SecureEnclaveCustodyLoadedHandle(binding: pair.keyAgreement, privateKey: keyAgreementKey)
        )

        let engine = PgpEngine()
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(engine: engine)
            .generatePublicCertificate(
                name: "Device Secure Enclave Interop",
                email: "device-se-interop@example.invalid",
                expirySeconds: 3600,
                configuration: PGPKeyConfiguration.Identity.compatibleP256V4.configuration,
                handlePair: loadedPair,
                digestSigner: SystemSecureEnclaveCustodyDigestSigner()
            )

        let gnupgHome = try makeGnupgHome()
        defer {
            try? FileManager.default.removeItem(at: gnupgHome)
        }

        // GnuPG imports the real SE custody public certificate (binary OpenPGP).
        let certFile = gnupgHome.appendingPathComponent("se_cert.gpg")
        try material.publicKeyData.write(to: certFile)
        let importResult = try runGpg(["--import", certFile.path], gpg: gpg, gnupgHome: gnupgHome)
        XCTAssertEqual(
            importResult.status,
            0,
            "gpg --import of the real SE certificate should succeed.\n\(importResult.stderrText)"
        )

        // Direction A (SE -> gpg): the production external signer signs with the real
        // Secure Enclave signing handle; gpg verifies the signature.
        let message = Data("Real Secure Enclave custody signature for GnuPG verification".utf8)
        let signingProvider = PGPExternalP256SigningProviderBridge(
            handle: loadedPair.signing,
            digestSigner: SystemSecureEnclaveCustodyDigestSigner()
        )
        let signed = try engine.signCleartextWithExternalP256Signer(
            text: message,
            publicCert: material.publicKeyData,
            signingKeyFingerprint: material.signingKeyFingerprint,
            signer: signingProvider
        )
        let signedFile = gnupgHome.appendingPathComponent("se_signed.asc")
        try signed.write(to: signedFile)
        let verifyResult = try runGpg(["--verify", signedFile.path], gpg: gpg, gnupgHome: gnupgHome)
        XCTAssertEqual(
            verifyResult.status,
            0,
            "gpg --verify of the SE-generated signature should succeed.\n\(verifyResult.stderrText)"
        )
        XCTAssertTrue(
            verifyResult.stderrText.contains("Good signature"),
            "gpg should report a good SE signature.\n\(verifyResult.stderrText)"
        )

        // Direction B (gpg -> SE): gpg encrypts to the SE certificate; the production
        // key-agreement seam decrypts via the real Secure Enclave .keyAgreement handle.
        let plaintext = Data("GnuPG to real Secure Enclave custody v4".utf8)
        let plaintextFile = gnupgHome.appendingPathComponent("plaintext.txt")
        try plaintext.write(to: plaintextFile)
        let ciphertextFile = gnupgHome.appendingPathComponent("ciphertext.gpg")
        let encryptResult = try runGpg(
            [
                "--encrypt",
                "--recipient", material.signingKeyFingerprint,
                "--output", ciphertextFile.path,
                plaintextFile.path
            ],
            gpg: gpg,
            gnupgHome: gnupgHome
        )
        XCTAssertEqual(
            encryptResult.status,
            0,
            "gpg --encrypt to the SE certificate should succeed.\n\(encryptResult.stderrText)"
        )
        let ciphertext = try Data(contentsOf: ciphertextFile)

        let keyAgreementProvider = PGPExternalP256KeyAgreementProviderBridge(
            handle: loadedPair.keyAgreement,
            keyAgreement: SystemSecureEnclaveCustodyKeyAgreement()
        )
        let decrypted = try engine.decryptDetailedWithExternalP256KeyAgreement(
            ciphertext: ciphertext,
            recipientPublicCert: material.publicKeyData,
            keyAgreementSubkeyFingerprint: material.keyAgreementSubkeyFingerprint,
            keyAgreementProvider: keyAgreementProvider,
            verificationKeys: []
        )
        XCTAssertEqual(
            decrypted.plaintext,
            plaintext,
            "the production key-agreement seam should decrypt the GnuPG-originated message"
        )
        XCTAssertEqual(decrypted.summaryState, .notSigned)

        SecureEnclaveCustodyEvidenceLog.record(
            SecureEnclaveCustodyEvidenceSummary(
                scenario: .gnupgInteropV4,
                configuration: .compatibleP256V4,
                outcome: .passed
            )
        )
    }

    // MARK: - gpg process harness

    private func requireGpg() throws -> URL {
        let candidates = ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"]
        for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
            return URL(fileURLWithPath: candidate)
        }

        // PATH lookup via `which`.
        let which = Process()
        which.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        which.arguments = ["gpg"]
        let pipe = Pipe()
        which.standardOutput = pipe
        which.standardError = Pipe()
        if (try? which.run()) != nil {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            which.waitUntilExit()
            let path = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            if which.terminationStatus == 0, !path.isEmpty,
               FileManager.default.isExecutableFile(atPath: path) {
                return URL(fileURLWithPath: path)
            }
        }
        throw XCTSkip("gpg binary not found; the GnuPG interop evidence harness requires a local gpg")
    }

    private func makeGnupgHome() throws -> URL {
        // gpg-agent's Unix socket is created inside GNUPGHOME; the sandboxed test
        // host's temporary directory is already a long path, so keep the directory
        // name short to stay under the ~104-character sun_path limit — otherwise gpg
        // fails with "can't connect to the gpg-agent: File name too long".
        let shortID = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8)
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("seg-\(shortID)")
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try "no-tty\nbatch\nyes\ntrust-model always\nforce-mdc\n"
            .write(to: dir.appendingPathComponent("gpg.conf"), atomically: true, encoding: .utf8)
        return dir
    }

    private struct GpgResult {
        let status: Int32
        let stdout: Data
        let stderr: Data

        var stderrText: String {
            String(decoding: stderr, as: UTF8.self)
        }
    }

    /// Run gpg non-interactively against an isolated GNUPGHOME. Outputs here are
    /// small (verdicts to stderr, ciphertext to a file), so reading the pipes
    /// before `waitUntilExit` does not risk a buffer-fill deadlock.
    private func runGpg(_ args: [String], gpg: URL, gnupgHome: URL) throws -> GpgResult {
        let process = Process()
        process.executableURL = gpg
        process.arguments = ["--batch", "--yes", "--trust-model", "always"] + args
        var environment = ProcessInfo.processInfo.environment
        environment["GNUPGHOME"] = gnupgHome.path
        process.environment = environment

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        return GpgResult(status: process.terminationStatus, stdout: stdoutData, stderr: stderrData)
    }
}

#endif
