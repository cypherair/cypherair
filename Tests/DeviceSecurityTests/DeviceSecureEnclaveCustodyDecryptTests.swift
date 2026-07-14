import CryptoKit
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

/// Device-only evidence for Phase 6 Secure Enclave custody decrypt through a real
/// `.keyAgreement` P-256 handle (the external ECDH/key-agreement route).
///
/// This test creates and deletes only the handle pair it owns; it does not invoke
/// Reset All Local Data cleanup, delete inventory-wide custody rows, or touch real
/// user keys. It authenticates a single biometric `LAContext` and reuses it for the
/// signing (generation) and key-agreement (decrypt) private operations so a real run
/// needs only one approval.
///
/// The Secure Enclave is available on Apple Silicon / T2 Macs and SE-capable
/// iPhones/iPads; the guard keys off `SecureEnclave.isAvailable` plus biometric
/// availability. (The A19/A19 Pro requirement is for MIE / Hardware Memory Tagging,
/// not for Secure Enclave.) Where Secure Enclave or biometrics are unavailable —
/// simulator or a Mac without enrolled Touch ID — the test skips.
final class DeviceSecureEnclaveCustodyDecryptTests: SecureEnclaveCustodyDeviceTestCase {
    func test_secureEnclaveRouteDecryptsV4AndV6MessagesWithRealKeyAgreementHandle_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()

        let handleStore = SecureEnclaveCustodyHandleStore(keyStore: SystemSecureEnclaveCustodyKeyStore())
        let pair = try handleStore.createHandlePair()
        defer {
            try? handleStore.deleteHandlePair(pair)
        }

        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate Secure Enclave custody message decrypt."
        )
        defer {
            context.invalidate()
        }

        let loadedPair = try loadHandlePair(pair, context: context)
        let messageAdapter = PGPMessageOperationAdapter(engine: PgpEngine())

        for configuration in [PGPKeyConfiguration.Identity.compatibleP256V4, .modernP256V6] {
            let prepared = try await prepareSecureEnclaveDecryptRoute(
                configuration: configuration,
                loadedPair: loadedPair
            )
            let plaintext = "device secure enclave \(configuration) message decrypt 🔐"
            let ciphertext = try await messageAdapter.encrypt(
                plaintext: Data(plaintext.utf8),
                recipientKeys: [prepared.identity.publicKeyData],
                signingKey: nil,
                selfKey: nil,
                binary: true
            )
            let unwrapper = UnusedSoftwareSecretCertificateUnwrapper()
            let service = PrivateKeyMessageDecryptionService(
                router: StaticRoute(.secureEnclaveKeyAgreement(prepared.route)),
                softwarePrivateKeyAccess: unwrapper,
                messageAdapter: messageAdapter,
                keyAgreement: SystemSecureEnclaveCustodyKeyAgreement(),
                compositeDecapsulator: SystemSecureEnclaveCompositeOperations()
            )

            let result = try await service.decryptDetailed(
                ciphertext: ciphertext,
                recipientFingerprint: prepared.identity.fingerprint,
                verificationContext: verificationContext(for: prepared.identity)
            )

            XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), plaintext)
            XCTAssertFalse(
                unwrapper.didUnwrap,
                "Secure Enclave decrypt must not unwrap a secret certificate"
            )
            recordEvidence(
                .ecdhDecrypt,
                configuration: configuration == .compatibleP256V4 ? .compatibleP256V4 : .modernP256V6
            )
        }
    }

    func test_secureEnclaveRouteDecryptsMixedRecipientFileAndHardFailsOnTamper_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()

        let handleStore = SecureEnclaveCustodyHandleStore(keyStore: SystemSecureEnclaveCustodyKeyStore())
        let pair = try handleStore.createHandlePair()
        defer {
            try? handleStore.deleteHandlePair(pair)
        }

        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate Secure Enclave custody file decrypt."
        )
        defer {
            context.invalidate()
        }

        let loadedPair = try loadHandlePair(pair, context: context)
        let prepared = try await prepareSecureEnclaveDecryptRoute(
            configuration: .compatibleP256V4,
            loadedPair: loadedPair
        )
        let engine = PgpEngine()
        let messageAdapter = PGPMessageOperationAdapter(engine: engine)
        let otherRecipient = try engine.generateKey(
            name: "Device Other Recipient",
            email: "device-other-recipient@example.invalid",
            expirySeconds: nil,
            profile: .universal
        )

        // Mixed-recipient round-trip: the Secure Enclave key-agreement recipient is second
        // so the matching PKESK is selected past a non-matching recipient's packet.
        let plaintext = String(repeating: "device mixed-recipient file ", count: 256)
        let ciphertext = try await messageAdapter.encrypt(
            plaintext: Data(plaintext.utf8),
            recipientKeys: [otherRecipient.publicKeyData, prepared.identity.publicKeyData],
            signingKey: nil,
            selfKey: nil,
            binary: true
        )

        let input = try writeTemporaryFile(ciphertext)
        let output = temporaryOutputURL()
        defer {
            removeItems(input, output)
        }
        let unwrapper = UnusedSoftwareSecretCertificateUnwrapper()
        let service = PrivateKeyStreamingFileDecryptionService(
            router: StaticRoute(.secureEnclaveKeyAgreement(prepared.route)),
            softwarePrivateKeyAccess: unwrapper,
            messageAdapter: messageAdapter,
            keyAgreement: SystemSecureEnclaveCustodyKeyAgreement(),
            compositeDecapsulator: SystemSecureEnclaveCompositeOperations()
        )

        let verification = try await service.decryptFile(
            inputPath: input.path,
            outputPath: output.path,
            recipientFingerprint: prepared.identity.fingerprint,
            verificationContext: verificationContext(for: prepared.identity),
            progress: nil
        )
        XCTAssertEqual(verification.summaryState, .notSigned)
        XCTAssertEqual(String(data: try Data(contentsOf: output), encoding: .utf8), plaintext)
        XCTAssertFalse(
            unwrapper.didUnwrap,
            "Secure Enclave file decrypt must not unwrap a secret certificate"
        )

        // Tamper the payload tail → hard-fail with no plaintext output (no partial plaintext).
        var tampered = ciphertext
        XCTAssertGreaterThan(tampered.count, 16)
        tampered[tampered.count - 8] ^= 0x01
        let tamperedInput = try writeTemporaryFile(tampered)
        let tamperedOutput = temporaryOutputURL()
        defer {
            removeItems(tamperedInput, tamperedOutput)
        }
        do {
            _ = try await service.decryptFile(
                inputPath: tamperedInput.path,
                outputPath: tamperedOutput.path,
                recipientFingerprint: prepared.identity.fingerprint,
                verificationContext: verificationContext(for: prepared.identity),
                progress: nil
            )
            XCTFail("Tampered file must hard-fail without releasing plaintext")
        } catch let error as CypherAirError {
            switch error {
            case .aeadAuthenticationFailed, .integrityCheckFailed, .corruptData:
                break
            default:
                XCTFail("Expected payload-authentication hard-fail, got \(error)")
            }
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: tamperedOutput.path),
            "No plaintext output may exist after a tampered file hard-fail"
        )
        recordEvidence(.ecdhDecrypt, configuration: .compatibleP256V4)
        recordEvidence(
            .payloadTamperHardFail,
            configuration: .compatibleP256V4,
            observedCategory: .payloadAuthenticationFailure
        )
    }

    // MARK: - Route construction

    private struct PreparedSecureEnclaveDecryptRoute {
        let identity: PGPKeyIdentity
        let route: SecureEnclaveKeyAgreementRoute
    }

    /// Builds a public-only Secure Enclave custody certificate from the loaded handle
    /// pair (real signing handle), then assembles the matching identity and
    /// key-agreement decrypt route bound to the real `.keyAgreement` handle.
    private func prepareSecureEnclaveDecryptRoute(
        configuration: PGPKeyConfiguration.Identity,
        loadedPair: SecureEnclaveCustodyLoadedHandlePair
    ) async throws -> PreparedSecureEnclaveDecryptRoute {
        let engine = PgpEngine()
        let material = try await PGPSecureEnclaveCustodyGenerationAdapter(engine: engine)
            .generatePublicCertificate(
                name: "Device Secure Enclave Decrypt",
                email: "device-secure-decrypt@example.invalid",
                expirySeconds: 3600,
                configuration: configuration.configuration,
                handlePair: loadedPair,
                digestSigner: SystemSecureEnclaveCustodyDigestSigner()
            )
        let identity = PGPKeyIdentity(
            fingerprint: material.metadata.fingerprint,
            keyVersion: material.metadata.keyVersion,
            userId: material.metadata.userId,
            hasEncryptionSubkey: material.metadata.hasEncryptionSubkey,
            isRevoked: material.metadata.isRevoked,
            isExpired: material.metadata.isExpired,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: material.publicKeyData,
            revocationCert: material.revocationCert,
            primaryAlgo: material.metadata.primaryAlgo,
            subkeyAlgo: material.metadata.subkeyAlgo,
            expiryDate: material.metadata.expiryDate,
            openPGPConfigurationIdentity: configuration,
            privateKeyCustodyKind: .appleSecureEnclavePrivateOperations
        )
        let inspection = try PGPSecureEnclaveCustodyPublicBindingInspector(engine: engine)
            .inspectPublicBindings(publicKeyData: material.publicKeyData)
        return PreparedSecureEnclaveDecryptRoute(
            identity: identity,
            route: SecureEnclaveKeyAgreementRoute(
                identity: identity,
                operation: .decrypt,
                publicBindingInspection: inspection,
                keyAgreementHandle: loadedPair.keyAgreement
            )
        )
    }

    private func loadHandlePair(
        _ pair: SecureEnclaveCustodyHandlePair,
        context: LAContext
    ) throws -> SecureEnclaveCustodyLoadedHandlePair {
        let signingKey = try loadPrivateKey(
            reference: pair.signing.reference,
            authenticationContext: context
        )
        let keyAgreementKey = try loadPrivateKey(
            reference: pair.keyAgreement.reference,
            authenticationContext: context
        )
        return try SecureEnclaveCustodyLoadedHandlePair(
            signing: SecureEnclaveCustodyLoadedHandle(
                binding: pair.signing,
                privateKey: signingKey
            ),
            keyAgreement: SecureEnclaveCustodyLoadedHandle(
                binding: pair.keyAgreement,
                privateKey: keyAgreementKey
            )
        )
    }

    private func verificationContext(for identity: PGPKeyIdentity) -> PGPMessageVerificationContext {
        PGPMessageVerificationContext(
            verificationKeys: [identity.publicKeyData],
            contactKeys: [],
            ownKeys: [identity],
            contactsAvailability: .availableProtectedDomain
        )
    }

    // MARK: - Temporary file helpers

    private func writeTemporaryFile(_ contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(
            "device-se-decrypt-\(UUID().uuidString).gpg"
        )
        try contents.write(to: url, options: .atomic)
        return url
    }

    private func temporaryOutputURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(
            "device-se-decrypt-out-\(UUID().uuidString).bin"
        )
    }

    private func removeItems(_ urls: URL...) {
        for url in urls {
            try? FileManager.default.removeItem(at: url)
        }
    }
}

// MARK: - Local routing doubles

private struct StaticRoute: PrivateKeyOperationRouting {
    let route: PrivateKeyOperationRoute

    init(_ route: PrivateKeyOperationRoute) {
        self.route = route
    }

    func route(for request: PrivateKeyOperationRequest) async -> PrivateKeyOperationRoute {
        route
    }
}

private final class UnusedSoftwareSecretCertificateUnwrapper: SoftwareSecretCertificateUnwrapping, @unchecked Sendable {
    private(set) var didUnwrap = false

    func unwrapPrivateKey(fingerprint: String) async throws -> Data {
        didUnwrap = true
        throw CypherAirError.keyOperationUnavailable(category: .operationUnavailableByPolicy)
    }
}
