import XCTest
import CryptoKit
import Security
import LocalAuthentication
@testable import CypherAir

/// C8: Hardware memory tagging and crypto workflow tests on device.
final class DeviceMIETests: DeviceSecurityTestCase {
    // MARK: - C8.1: MIE Smoke Tests (SE Wrap/Unwrap)

    func test_mie_singleWrapUnwrapCycle_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let fingerprint = uniqueFingerprint()
        var keyData = Data(count: 32)
        let status = keyData.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        XCTAssertEqual(status, errSecSuccess)

        let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
        let bundle = try secureEnclave.wrap(privateKey: keyData, using: handle, fingerprint: fingerprint)
        let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)

        XCTAssertEqual(unwrapped, keyData, "MIE smoke: wrap/unwrap must succeed without tag mismatch")
    }

    func test_mie_50xRapidWrapUnwrap_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        for i in 0..<50 {
            let fingerprint = uniqueFingerprint()
            // Alternate between Ed25519 (32 bytes) and Ed448 (57 bytes) sizes.
            let size = (i % 2 == 0) ? 32 : 57
            var keyData = Data(count: size)
            let status = keyData.withUnsafeMutableBytes { ptr in
                SecRandomCopyBytes(kSecRandomDefault, size, ptr.baseAddress!)
            }
            XCTAssertEqual(status, errSecSuccess, "Iteration \(i): SecRandom failed")

            let handle = try secureEnclave.generateWrappingKey(accessControl: nil)
            let bundle = try secureEnclave.wrap(privateKey: keyData, using: handle, fingerprint: fingerprint)
            let unwrapped = try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)

            XCTAssertEqual(unwrapped, keyData, "Iteration \(i): wrap/unwrap mismatch")
        }
    }

    // MARK: - C8.2: Full PGP Workflow Under MIE (Both Profiles)

    /// C8.2: Complete Profile A (v4, Ed25519+X25519, SEIPDv1) workflow on device.
    /// Exercises OpenSSL: AES-256, X25519 key agreement, Ed25519 signing, SHA-512 hashing.
    /// Pass: all operations complete without EXC_GUARD / GUARD_EXC_MTE_SYNC_FAULT.
    func test_mie_fullPGPWorkflow_profileA_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.2 Profile A MIE: full workflow — 你好世界 🔐".utf8)

        // 1. Key generation (Ed25519+X25519, v4).
        let key = try engine.generateKey(
            name: "C8.2 MIE Test A", email: "mie-a@test.local",
            expirySeconds: nil, profile: .universal
        )
        XCTAssertFalse(key.certData.isEmpty, "Profile A key generation must succeed")
        XCTAssertFalse(key.fingerprint.isEmpty, "Profile A fingerprint must not be empty")

        // 2. Encrypt with signing (AES-256 via SEIPDv1, X25519 key agreement).
        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [key.publicKeyData],
            signingKey: key.certData,
            encryptToSelf: nil
        )
        XCTAssertFalse(ciphertext.isEmpty, "Profile A ciphertext must not be empty")

        // 3. Decrypt (AES-256 decryption, Ed25519 signature verification).
        let decrypted = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [key.certData],
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(decrypted.plaintext, plaintext,
            "Profile A decrypted plaintext must match original")
        XCTAssertEqual(decrypted.legacyStatus, .valid,
            "Profile A signature must verify")

        // 4. Cleartext sign (Ed25519 + SHA-512).
        let signed = try engine.signCleartext(
            text: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(signed.isEmpty, "Cleartext signature must not be empty")

        // 5. Verify cleartext signature.
        let verifyResult = try engine.verifyCleartextDetailed(
            signedMessage: signed,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(verifyResult.legacyStatus, .valid,
            "Profile A cleartext signature must verify")

        // 6. Detached sign.
        let detachedSig = try engine.signDetached(
            data: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(detachedSig.isEmpty, "Detached signature must not be empty")

        // 7. Verify detached signature.
        let detachedVerify = try engine.verifyDetachedDetailed(
            data: plaintext,
            signature: detachedSig,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(detachedVerify.legacyStatus, .valid,
            "Profile A detached signature must verify")
    }

    /// C8.2: Complete Profile B (v6, Ed448+X448, SEIPDv2 AEAD OCB) workflow on device.
    /// Exercises OpenSSL: AES-256-OCB AEAD, X448 key agreement, Ed448 signing, SHA-512.
    /// Pass: all operations complete without tag mismatch crashes.
    func test_mie_fullPGPWorkflow_profileB_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.2 Profile B MIE: full workflow — AEAD OCB 🛡️".utf8)

        // 1. Key generation (Ed448+X448, v6).
        let key = try engine.generateKey(
            name: "C8.2 MIE Test B", email: "mie-b@test.local",
            expirySeconds: nil, profile: .advanced
        )
        XCTAssertFalse(key.certData.isEmpty, "Profile B key generation must succeed")

        // 2. Encrypt with signing (AES-256-OCB AEAD via SEIPDv2, X448).
        let ciphertext = try engine.encrypt(
            plaintext: plaintext,
            recipients: [key.publicKeyData],
            signingKey: key.certData,
            encryptToSelf: nil
        )
        XCTAssertFalse(ciphertext.isEmpty, "Profile B ciphertext must not be empty")

        // 3. Decrypt (AEAD OCB decryption, Ed448 signature verification).
        let decrypted = try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: [key.certData],
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(decrypted.plaintext, plaintext,
            "Profile B decrypted plaintext must match original")
        XCTAssertEqual(decrypted.legacyStatus, .valid,
            "Profile B signature must verify")

        // 4. Cleartext sign (Ed448 + SHA-512).
        let signed = try engine.signCleartext(
            text: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(signed.isEmpty, "Profile B cleartext signature must not be empty")

        // 5. Verify cleartext signature.
        let verifyResult = try engine.verifyCleartextDetailed(
            signedMessage: signed,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(verifyResult.legacyStatus, .valid,
            "Profile B cleartext signature must verify")

        // 6. Detached sign.
        let detachedSig = try engine.signDetached(
            data: plaintext, signerCert: key.certData
        )
        XCTAssertFalse(detachedSig.isEmpty, "Profile B detached signature must not be empty")

        // 7. Verify detached signature.
        let detachedVerify = try engine.verifyDetachedDetailed(
            data: plaintext,
            signature: detachedSig,
            verificationKeys: [key.publicKeyData]
        )
        XCTAssertEqual(detachedVerify.legacyStatus, .valid,
            "Profile B detached signature must verify")
    }

    /// C8.2: Cross-profile encryption format auto-selection under MIE.
    /// Tests: B→A (SEIPDv1), A→B (SEIPDv2), mixed A+B recipients (SEIPDv1).
    func test_mie_crossProfileEncrypt_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.2 Cross-profile MIE test".utf8)

        let keyA = try engine.generateKey(
            name: "Cross A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "Cross B", email: nil, expirySeconds: nil, profile: .advanced
        )

        // B sender → A recipient: should auto-select SEIPDv1.
        let ciphertextBA = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: keyB.certData,
            encryptToSelf: nil
        )
        let resultBA = try engine.decryptDetailed(
            ciphertext: ciphertextBA,
            secretKeys: [keyA.certData],
            verificationKeys: [keyB.publicKeyData]
        )
        XCTAssertEqual(resultBA.plaintext, plaintext, "B→A decrypt must succeed")
        XCTAssertEqual(resultBA.legacyStatus, .valid, "B→A signature must verify")

        // A sender → B recipient: should auto-select SEIPDv2.
        let ciphertextAB = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyB.publicKeyData],
            signingKey: keyA.certData,
            encryptToSelf: nil
        )
        let resultAB = try engine.decryptDetailed(
            ciphertext: ciphertextAB,
            secretKeys: [keyB.certData],
            verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(resultAB.plaintext, plaintext, "A→B decrypt must succeed")
        XCTAssertEqual(resultAB.legacyStatus, .valid, "A→B signature must verify")

        // Mixed recipients (A + B): should produce SEIPDv1.
        let ciphertextMixed = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData, keyB.publicKeyData],
            signingKey: keyA.certData,
            encryptToSelf: nil
        )
        // Both recipients must be able to decrypt.
        let resultMixedA = try engine.decryptDetailed(
            ciphertext: ciphertextMixed,
            secretKeys: [keyA.certData],
            verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(resultMixedA.plaintext, plaintext, "Mixed→A decrypt must succeed")

        let resultMixedB = try engine.decryptDetailed(
            ciphertext: ciphertextMixed,
            secretKeys: [keyB.certData],
            verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(resultMixedB.plaintext, plaintext, "Mixed→B decrypt must succeed")
    }

    /// C8.2: Key export/import round-trip under MIE.
    /// Profile A: Iterated+Salted S2K. Profile B: Argon2id S2K (512 MB).
    func test_mie_keyExportImport_bothProfiles_noTagMismatch() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let passphrase = "mie-export-test-passphrase"
        let plaintext = Data("C8.2 export/import round-trip test".utf8)

        // Profile A: export with Iterated+Salted S2K, then import.
        let keyA = try engine.generateKey(
            name: "Export A", email: nil, expirySeconds: nil, profile: .universal
        )
        let ciphertextA = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let exportedA = try engine.exportSecretKey(
            certData: keyA.certData, passphrase: passphrase, profile: .universal
        )
        XCTAssertFalse(exportedA.isEmpty, "Profile A export must produce data")

        let importedA = try engine.importSecretKey(
            armoredData: exportedA, passphrase: passphrase
        )
        XCTAssertFalse(importedA.isEmpty, "Profile A import must succeed")

        // Decrypt with the imported key to verify round-trip.
        let decryptedA = try engine.decryptDetailed(
            ciphertext: ciphertextA,
            secretKeys: [importedA],
            verificationKeys: []
        )
        XCTAssertEqual(decryptedA.plaintext, plaintext,
            "Profile A: imported key must decrypt correctly")

        // Profile B: export with Argon2id S2K, then import.
        let keyB = try engine.generateKey(
            name: "Export B", email: nil, expirySeconds: nil, profile: .advanced
        )
        let ciphertextB = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyB.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )

        let exportedB = try engine.exportSecretKey(
            certData: keyB.certData, passphrase: passphrase, profile: .advanced
        )
        XCTAssertFalse(exportedB.isEmpty, "Profile B export must produce data")

        let importedB = try engine.importSecretKey(
            armoredData: exportedB, passphrase: passphrase
        )
        XCTAssertFalse(importedB.isEmpty, "Profile B import must succeed")

        let decryptedB = try engine.decryptDetailed(
            ciphertext: ciphertextB,
            secretKeys: [importedB],
            verificationKeys: []
        )
        XCTAssertEqual(decryptedB.plaintext, plaintext,
            "Profile B: imported key must decrypt correctly")
    }

    // MARK: - C8.3: OpenSSL Crypto Operations Under MIE

    /// C8.3: Explicitly exercise every OpenSSL code path used by Sequoia.
    /// Covers: AES-256, SHA-512, Ed25519, X25519, Ed448, X448, AES-256-OCB AEAD, Argon2id.
    /// Pass: all crypto operations succeed with no memory tagging violations.
    func test_mie_opensslCryptoPaths_allAlgorithms_noTagViolations() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let plaintext = Data("C8.3 OpenSSL paths MIE validation".utf8)

        // --- Generate keys for both profiles ---
        let keyA = try engine.generateKey(
            name: "OpenSSL A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "OpenSSL B", email: nil, expirySeconds: nil, profile: .advanced
        )

        // 1. AES-256 via SEIPDv1 (Profile A encrypt + decrypt).
        //    OpenSSL path: AES-256-CFB encryption + MDC (SHA-1 hash).
        let ciphertextA = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let resultA = try engine.decryptDetailed(
            ciphertext: ciphertextA,
            secretKeys: [keyA.certData],
            verificationKeys: []
        )
        XCTAssertEqual(resultA.plaintext, plaintext, "AES-256 SEIPDv1 round-trip failed")

        // 2. SHA-512 via signing (both profiles).
        //    OpenSSL path: SHA-512 hash for signature computation.
        let signedA = try engine.signCleartext(text: plaintext, signerCert: keyA.certData)
        let verifyA = try engine.verifyCleartextDetailed(
            signedMessage: signedA, verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(verifyA.legacyStatus, .valid, "SHA-512 + Ed25519 sign/verify failed")

        let signedB = try engine.signCleartext(text: plaintext, signerCert: keyB.certData)
        let verifyB = try engine.verifyCleartextDetailed(
            signedMessage: signedB, verificationKeys: [keyB.publicKeyData]
        )
        XCTAssertEqual(verifyB.legacyStatus, .valid, "SHA-512 + Ed448 sign/verify failed")

        // 3. Ed25519 via Profile A sign + verify (covered above in step 2).

        // 4. X25519 via Profile A encrypt (covered above in step 1).
        //    OpenSSL path: X25519 ECDH key agreement for session key.

        // 5. Ed448 via Profile B sign + verify (covered above in step 2).

        // 6. X448 via Profile B encrypt.
        //    OpenSSL path: X448 ECDH key agreement for session key.
        let ciphertextB = try engine.encrypt(
            plaintext: plaintext,
            recipients: [keyB.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let resultB = try engine.decryptDetailed(
            ciphertext: ciphertextB,
            secretKeys: [keyB.certData],
            verificationKeys: []
        )
        XCTAssertEqual(resultB.plaintext, plaintext, "AES-256-OCB AEAD + X448 round-trip failed")

        // 7. AES-256-OCB AEAD via SEIPDv2 (Profile B, covered above in step 6).

        // 8. Argon2id via Profile B key export.
        //    OpenSSL path: Argon2id KDF (512 MB memory, 4 lanes).
        let exported = try engine.exportSecretKey(
            certData: keyB.certData, passphrase: "openssltest", profile: .advanced
        )
        XCTAssertFalse(exported.isEmpty, "Argon2id S2K export must succeed")

        let imported = try engine.importSecretKey(
            armoredData: exported, passphrase: "openssltest"
        )
        XCTAssertFalse(imported.isEmpty, "Argon2id S2K import must succeed")

        // 9. Detached signatures (exercises Ed25519/Ed448 + SHA-512 in detached mode).
        let detSigA = try engine.signDetached(data: plaintext, signerCert: keyA.certData)
        let detVerifyA = try engine.verifyDetachedDetailed(
            data: plaintext, signature: detSigA, verificationKeys: [keyA.publicKeyData]
        )
        XCTAssertEqual(detVerifyA.legacyStatus, .valid, "Ed25519 detached sign/verify failed")

        let detSigB = try engine.signDetached(data: plaintext, signerCert: keyB.certData)
        let detVerifyB = try engine.verifyDetachedDetailed(
            data: plaintext, signature: detSigB, verificationKeys: [keyB.publicKeyData]
        )
        XCTAssertEqual(detVerifyB.legacyStatus, .valid, "Ed448 detached sign/verify failed")
    }

    /// C8.3: Armor/dearmor exercises OpenSSL Base64 and binary parsing paths.
    func test_mie_armorDearmor_bothProfiles_noTagViolations() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()

        let keyA = try engine.generateKey(
            name: "Armor A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "Armor B", email: nil, expirySeconds: nil, profile: .advanced
        )

        // Armor public keys and round-trip.
        let armoredA = try engine.armorPublicKey(certData: keyA.publicKeyData)
        XCTAssertFalse(armoredA.isEmpty, "Profile A armored public key must not be empty")
        let dearmoredA = try engine.dearmor(armored: armoredA)
        XCTAssertEqual(dearmoredA, keyA.publicKeyData,
            "Profile A armor/dearmor must round-trip")

        let armoredB = try engine.armorPublicKey(certData: keyB.publicKeyData)
        XCTAssertFalse(armoredB.isEmpty, "Profile B armored public key must not be empty")
        let dearmoredB = try engine.dearmor(armored: armoredB)
        XCTAssertEqual(dearmoredB, keyB.publicKeyData,
            "Profile B armor/dearmor must round-trip")

        // Armor ciphertext and round-trip decrypt.
        let plaintext = Data("Armor round-trip test".utf8)
        let binaryCiphertext = try engine.encryptBinary(
            plaintext: plaintext,
            recipients: [keyA.publicKeyData],
            signingKey: nil,
            encryptToSelf: nil
        )
        let armoredMsg = try engine.armor(data: binaryCiphertext, kind: .message)
        XCTAssertFalse(armoredMsg.isEmpty, "Armored message must not be empty")
        let dearmoredMsg = try engine.dearmor(armored: armoredMsg)
        XCTAssertEqual(dearmoredMsg, binaryCiphertext,
            "Message armor/dearmor must preserve binary content")
    }

    // MARK: - C8.4: 100× Encrypt/Decrypt Cycles Under MIE

    /// C8.4: 100 encrypt/decrypt cycles for Profile A (SEIPDv1) under MIE.
    /// Detects intermittent tag mismatches that single-cycle tests might miss.
    /// Monitor: `log stream --predicate 'eventMessage contains "MTE"'`
    /// Pass: zero tag violations across 100 cycles.
    func test_mie_100xEncryptDecryptCycles_profileA_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "100x A", email: nil, expirySeconds: nil, profile: .universal
        )

        for i in 0..<100 {
            let plaintext = Data("C8.4 Profile A iteration \(i) — \(UUID().uuidString)".utf8)

            let ciphertext = try engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )

            let result = try engine.decryptDetailed(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: [key.publicKeyData]
            )

            XCTAssertEqual(result.plaintext, plaintext,
                "Profile A iteration \(i): plaintext mismatch")
            XCTAssertEqual(result.legacyStatus, .valid,
                "Profile A iteration \(i): signature invalid")
        }
    }

    /// C8.4: 100 encrypt/decrypt cycles for Profile B (SEIPDv2 AEAD OCB) under MIE.
    /// Exercises OpenSSL AES-256-OCB + X448 + Ed448 100 times.
    /// Pass: zero tag violations across 100 cycles.
    func test_mie_100xEncryptDecryptCycles_profileB_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let key = try engine.generateKey(
            name: "100x B", email: nil, expirySeconds: nil, profile: .advanced
        )

        for i in 0..<100 {
            let plaintext = Data("C8.4 Profile B iteration \(i) — \(UUID().uuidString)".utf8)

            let ciphertext = try engine.encrypt(
                plaintext: plaintext,
                recipients: [key.publicKeyData],
                signingKey: key.certData,
                encryptToSelf: nil
            )

            let result = try engine.decryptDetailed(
                ciphertext: ciphertext,
                secretKeys: [key.certData],
                verificationKeys: [key.publicKeyData]
            )

            XCTAssertEqual(result.plaintext, plaintext,
                "Profile B iteration \(i): plaintext mismatch")
            XCTAssertEqual(result.legacyStatus, .valid,
                "Profile B iteration \(i): signature invalid")
        }
    }

    /// C8.4: 100 sign/verify cycles for both profiles under MIE.
    /// Exercises Ed25519 + Ed448 + SHA-512 hashing 200 times total.
    /// Pass: zero tag violations across all cycles.
    func test_mie_100xSignVerifyCycles_bothProfiles_noIntermittentCrashes() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available")

        let engine = PgpEngine()
        let keyA = try engine.generateKey(
            name: "100x Sign A", email: nil, expirySeconds: nil, profile: .universal
        )
        let keyB = try engine.generateKey(
            name: "100x Sign B", email: nil, expirySeconds: nil, profile: .advanced
        )

        for i in 0..<100 {
            let text = Data("C8.4 sign/verify iteration \(i) — \(UUID().uuidString)".utf8)

            // Profile A: Ed25519 cleartext sign + verify.
            let signedA = try engine.signCleartext(text: text, signerCert: keyA.certData)
            let verifyA = try engine.verifyCleartextDetailed(
                signedMessage: signedA, verificationKeys: [keyA.publicKeyData]
            )
            XCTAssertEqual(verifyA.legacyStatus, .valid,
                "Profile A sign/verify iteration \(i) failed")

            // Profile B: Ed448 cleartext sign + verify.
            let signedB = try engine.signCleartext(text: text, signerCert: keyB.certData)
            let verifyB = try engine.verifyCleartextDetailed(
                signedMessage: signedB, verificationKeys: [keyB.publicKeyData]
            )
            XCTAssertEqual(verifyB.legacyStatus, .valid,
                "Profile B sign/verify iteration \(i) failed")
        }
    }
}
