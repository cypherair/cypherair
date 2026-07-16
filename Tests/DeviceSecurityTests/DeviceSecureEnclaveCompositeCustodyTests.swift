import CryptoKit
import LocalAuthentication
import Security
import XCTest
@testable import CypherAir

/// Device-only evidence for Device-Bound Post-Quantum split custody (campaign
/// #567 Phase 3) against a real Secure Enclave: ML-DSA-65 / ML-KEM-768 keys are
/// generated in the enclave, the composite certificate is built through the
/// external ML-DSA signing bridge (self-verified in Rust), a message encrypted
/// to the certificate decrypts through the external decapsulation bridge plus
/// the vendored RFC 9980 combiner, and a cleartext signature made through the
/// split-custody path verifies against the certificate.
///
/// The test creates and deletes only the composite handles it owns and never
/// touches real user keys. It authenticates one biometric `LAContext` at the
/// start and attaches it to both enclave keys at creation, so a real run needs
/// only one approval. Where Secure Enclave or biometrics are unavailable —
/// simulator or a Mac without enrolled Touch ID — the test skips.
final class DeviceSecureEnclaveCompositeCustodyTests: SecureEnclaveCustodyDeviceTestCase {
    func test_compositeSplitCustodyLifecycle_generateDecryptSign_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()

        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate Device-Bound Post-Quantum custody."
        )
        defer {
            context.invalidate()
        }

        let handleStore = SecureEnclaveCustodyHandleStore(
            keyStore: SystemSecureEnclaveCustodyKeyStore(),
            tier: .classicalP256
        )
        let loadedPair: SecureEnclaveCustodyLoadedHandlePair
        do {
            loadedPair = try handleStore.createLoadedHandlePair(authenticationContext: context)
        } catch SecureEnclaveCustodyHandleError.hardwareUnavailable {
            throw XCTSkip("Secure Enclave post-quantum key generation is unavailable on this hardware")
        }
        defer {
            try? handleStore.deleteHandles(
                signingPublicKeyRaw: loadedPair.signing.binding.publicKeyRaw,
                keyAgreementPublicKeyRaw: loadedPair.keyAgreement.binding.publicKeyRaw
            )
        }

        // Real-enclave component shapes (FIPS 204 / FIPS 203 raw encodings).
        XCTAssertEqual(loadedPair.signing.binding.publicKeyRaw.count, 1952)
        XCTAssertEqual(loadedPair.keyAgreement.binding.publicKeyRaw.count, 1184)

        // Certificate generation: every binding signature runs through the
        // external ML-DSA bridge against the real enclave and is self-verified
        // by the Rust engine before release.
        let engine = PgpEngine()
        let operations = SystemSecureEnclaveCompositeOperations()
        let adapter = PGPSecureEnclaveCompositeGenerationAdapter(engine: engine)
        var material = try await adapter.generateCompositeCertificate(
            name: "Device Composite Evidence",
            email: nil,
            expirySeconds: nil,
            handlePair: loadedPair,
            compositeSigner: operations
        )
        defer {
            material.classicalEddsaSecret.resetBytes(in: 0..<material.classicalEddsaSecret.count)
            material.classicalEcdhSecret.resetBytes(in: 0..<material.classicalEcdhSecret.count)
        }
        XCTAssertEqual(material.metadata.profile, .postQuantum)
        XCTAssertEqual(material.metadata.keyVersion, 6)
        XCTAssertEqual(material.classicalEddsaSecret.count, 32)
        XCTAssertEqual(material.classicalEcdhSecret.count, 32)

        // The stored handles are locatable from the certificate's component
        // public keys — the router's non-prompting lookup path.
        let located = try handleStore.locateHandlePair(
            signingPublicKeyRaw: loadedPair.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: loadedPair.keyAgreement.binding.publicKeyRaw
        )
        XCTAssertEqual(located.handleSetIdentifier, loadedPair.signing.reference.handleSetIdentifier)

        // Decrypt: engine-encrypted message to the composite certificate comes
        // back through real ML-KEM-768 decapsulation + the vendored combiner.
        let plaintext = "device split-custody post-quantum round trip 🔐"
        let ciphertext = try engine.encrypt(
            plaintext: Data(plaintext.utf8),
            recipients: [material.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let decapsulationBridge = PGPExternalMlKem768DecapsulationProviderBridge(
            handle: loadedPair.keyAgreement,
            decapsulator: operations
        )
        let decrypted = try engine.decryptDetailedWithExternalCompositeKeyAgreement(
            ciphertext: ciphertext,
            recipientPublicCert: material.publicKeyData,
            keyAgreementSubkeyFingerprint: material.keyAgreementSubkeyFingerprint,
            classicalEcdhSecret: material.classicalEcdhSecret,
            decapsulationProvider: decapsulationBridge,
            verificationKeys: []
        )
        XCTAssertEqual(String(data: decrypted.plaintext, encoding: .utf8), plaintext)

        // Sign: cleartext signature through the real enclave ML-DSA component
        // plus the Rust-side Ed25519 classical half verifies against the cert.
        let signingBridge = PGPExternalMlDsa65SigningProviderBridge(
            handle: loadedPair.signing,
            compositeSigner: operations
        )
        let signed = try engine.signCleartextWithExternalCompositeSigner(
            text: Data("device split-custody cleartext".utf8),
            publicCert: material.publicKeyData,
            signingKeyFingerprint: material.signingKeyFingerprint,
            classicalEddsaSecret: material.classicalEddsaSecret,
            signer: signingBridge
        )
        let verified = try engine.verifyCleartextDetailed(
            signedMessage: signed,
            verificationKeys: [material.publicKeyData]
        )
        XCTAssertEqual(verified.summaryState, SignatureVerificationState.verified)

        // Negative: a wrong classical component must fail closed at the Rust
        // constructor's certificate-binding check — before any enclave call.
        XCTAssertThrowsError(
            try engine.signCleartextWithExternalCompositeSigner(
                text: Data("must not sign".utf8),
                publicCert: material.publicKeyData,
                signingKeyFingerprint: material.signingKeyFingerprint,
                classicalEddsaSecret: Data(repeating: 0x07, count: 32),
                signer: signingBridge
            )
        )
    }

    /// Device-Bound Post-Quantum · High evidence: the same split-custody
    /// lifecycle against the ML-DSA-87 / ML-KEM-1024 tier, whose enclave keys,
    /// Ed448/X448 classical halves, and RFC 9980 combiner all differ in length
    /// from the base tier.
    func test_compositeHighSplitCustodyLifecycle_generateDecryptSign_onDevice() async throws {
        try requireSecureEnclaveCustodyHardware()

        let context = try await authenticatedBiometricsContext(
            reason: "Authenticate to validate Device-Bound Post-Quantum · High custody."
        )
        defer {
            context.invalidate()
        }

        let handleStore = SecureEnclaveCustodyHandleStore(
            keyStore: SystemSecureEnclaveCustodyKeyStore(),
            tier: .postQuantumHigh
        )
        let loadedPair: SecureEnclaveCustodyLoadedHandlePair
        do {
            loadedPair = try handleStore.createLoadedHandlePair(authenticationContext: context)
        } catch SecureEnclaveCustodyHandleError.hardwareUnavailable {
            throw XCTSkip("Secure Enclave post-quantum key generation is unavailable on this hardware")
        }
        defer {
            try? handleStore.deleteHandles(
                signingPublicKeyRaw: loadedPair.signing.binding.publicKeyRaw,
                keyAgreementPublicKeyRaw: loadedPair.keyAgreement.binding.publicKeyRaw
            )
        }

        // Real-enclave component shapes (FIPS 204 / FIPS 203 raw encodings).
        XCTAssertEqual(loadedPair.signing.binding.publicKeyRaw.count, 2592)
        XCTAssertEqual(loadedPair.keyAgreement.binding.publicKeyRaw.count, 1568)

        let engine = PgpEngine()
        let operations = SystemSecureEnclaveCompositeOperations()
        let adapter = PGPSecureEnclaveCompositeGenerationAdapter(engine: engine)
        var material = try await adapter.generateCompositeCertificate(
            name: "Device Composite High Evidence",
            email: nil,
            expirySeconds: nil,
            handlePair: loadedPair,
            compositeSigner: operations
        )
        defer {
            material.classicalEddsaSecret.resetBytes(in: 0..<material.classicalEddsaSecret.count)
            material.classicalEcdhSecret.resetBytes(in: 0..<material.classicalEcdhSecret.count)
        }
        XCTAssertEqual(material.metadata.profile, .postQuantumHigh)
        XCTAssertEqual(material.metadata.keyVersion, 6)
        XCTAssertEqual(material.classicalEddsaSecret.count, 57)
        XCTAssertEqual(material.classicalEcdhSecret.count, 56)

        let located = try handleStore.locateHandlePair(
            signingPublicKeyRaw: loadedPair.signing.binding.publicKeyRaw,
            keyAgreementPublicKeyRaw: loadedPair.keyAgreement.binding.publicKeyRaw
        )
        XCTAssertEqual(located.handleSetIdentifier, loadedPair.signing.reference.handleSetIdentifier)

        let plaintext = "device split-custody post-quantum · High round trip 🔐"
        let ciphertext = try engine.encrypt(
            plaintext: Data(plaintext.utf8),
            recipients: [material.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let decapsulationBridge = PGPExternalMlKem1024DecapsulationProviderBridge(
            handle: loadedPair.keyAgreement,
            decapsulator: operations
        )
        let decrypted = try engine.decryptDetailedWithExternalCompositeHighKeyAgreement(
            ciphertext: ciphertext,
            recipientPublicCert: material.publicKeyData,
            keyAgreementSubkeyFingerprint: material.keyAgreementSubkeyFingerprint,
            classicalEcdhSecret: material.classicalEcdhSecret,
            decapsulationProvider: decapsulationBridge,
            verificationKeys: []
        )
        XCTAssertEqual(String(data: decrypted.plaintext, encoding: .utf8), plaintext)

        let signingBridge = PGPExternalMlDsa87SigningProviderBridge(
            handle: loadedPair.signing,
            compositeSigner: operations
        )
        let signed = try engine.signCleartextWithExternalCompositeHighSigner(
            text: Data("device split-custody · High cleartext".utf8),
            publicCert: material.publicKeyData,
            signingKeyFingerprint: material.signingKeyFingerprint,
            classicalEddsaSecret: material.classicalEddsaSecret,
            signer: signingBridge
        )
        let verified = try engine.verifyCleartextDetailed(
            signedMessage: signed,
            verificationKeys: [material.publicKeyData]
        )
        XCTAssertEqual(verified.summaryState, SignatureVerificationState.verified)

        // Negative: a wrong classical component must fail closed at the Rust
        // constructor's certificate-binding check — before any enclave call.
        XCTAssertThrowsError(
            try engine.signCleartextWithExternalCompositeHighSigner(
                text: Data("must not sign".utf8),
                publicCert: material.publicKeyData,
                signingKeyFingerprint: material.signingKeyFingerprint,
                classicalEddsaSecret: Data(repeating: 0x07, count: 57),
                signer: signingBridge
            )
        )
    }
}
