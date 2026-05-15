import XCTest
import SwiftUI
@testable import CypherAir

/// Tests for model types: CypherAirError, Contact, PGPKeyIdentity,
/// PGPKeyProfile, SignatureVerification, and ColorTheme.
final class ModelTests: XCTestCase {

    // MARK: - PGPErrorMapper

    func test_pgpErrorMapper_aeadMapped() {
        let error = PGPErrorMapper.map(.AeadAuthenticationFailed)
        if case .aeadAuthenticationFailed = error {
            // Expected
        } else {
            XCTFail("Expected .aeadAuthenticationFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_noMatchingKeyMapped() {
        let error = PGPErrorMapper.map(.NoMatchingKey)
        if case .noMatchingKey = error {
            // Expected
        } else {
            XCTFail("Expected .noMatchingKey, got \(error)")
        }
    }

    func test_pgpErrorMapper_wrongPassphraseMapped() {
        let error = PGPErrorMapper.map(.WrongPassphrase)
        if case .wrongPassphrase = error {
            // Expected
        } else {
            XCTFail("Expected .wrongPassphrase, got \(error)")
        }
    }

    func test_pgpErrorMapper_unsupportedAlgorithmMapped() {
        let error = PGPErrorMapper.map(.UnsupportedAlgorithm(algo: "RSA"))
        if case .unsupportedAlgorithm(let algo) = error {
            XCTAssertEqual(algo, "RSA")
        } else {
            XCTFail("Expected .unsupportedAlgorithm, got \(error)")
        }
    }

    func test_pgpErrorMapper_keyExpiredMapped() {
        let error = PGPErrorMapper.map(.KeyExpired)
        if case .keyExpired = error {
            // Expected
        } else {
            XCTFail("Expected .keyExpired, got \(error)")
        }
    }

    func test_pgpErrorMapper_badSignatureMapped() {
        let error = PGPErrorMapper.map(.BadSignature)
        if case .badSignature = error {
            // Expected
        } else {
            XCTFail("Expected .badSignature, got \(error)")
        }
    }

    func test_pgpErrorMapper_unknownSignerMapped() {
        let error = PGPErrorMapper.map(.UnknownSigner)
        if case .unknownSigner = error {
            // Expected
        } else {
            XCTFail("Expected .unknownSigner, got \(error)")
        }
    }

    func test_pgpErrorMapper_corruptDataMapped() {
        let error = PGPErrorMapper.map(.CorruptData(reason: "test damage"))
        if case .corruptData(let reason) = error {
            XCTAssertEqual(reason, "test damage")
        } else {
            XCTFail("Expected .corruptData, got \(error)")
        }
    }

    func test_pgpErrorMapper_invalidKeyDataMapped() {
        let error = PGPErrorMapper.map(.InvalidKeyData(reason: "not a key"))
        if case .invalidKeyData(let reason) = error {
            XCTAssertEqual(reason, "not a key")
        } else {
            XCTFail("Expected .invalidKeyData, got \(error)")
        }
    }

    func test_pgpErrorMapper_encryptionFailedMapped() {
        let error = PGPErrorMapper.map(.EncryptionFailed(reason: "no recipients"))
        if case .encryptionFailed(let reason) = error {
            XCTAssertEqual(reason, "no recipients")
        } else {
            XCTFail("Expected .encryptionFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_signingFailedMapped() {
        let error = PGPErrorMapper.map(.SigningFailed(reason: "invalid key"))
        if case .signingFailed(let reason) = error {
            XCTAssertEqual(reason, "invalid key")
        } else {
            XCTFail("Expected .signingFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_armorErrorMapped() {
        let error = PGPErrorMapper.map(.ArmorError(reason: "bad format"))
        if case .armorError(let reason) = error {
            XCTAssertEqual(reason, "bad format")
        } else {
            XCTFail("Expected .armorError, got \(error)")
        }
    }

    func test_pgpErrorMapper_integrityCheckFailedMapped() {
        let error = PGPErrorMapper.map(.IntegrityCheckFailed)
        if case .integrityCheckFailed = error {
            // Expected
        } else {
            XCTFail("Expected .integrityCheckFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_argon2idMemoryExceededMapped() {
        let error = PGPErrorMapper.map(.Argon2idMemoryExceeded(requiredMb: 512))
        if case .argon2idMemoryExceeded(let requiredMb) = error {
            XCTAssertEqual(requiredMb, 512)
        } else {
            XCTFail("Expected .argon2idMemoryExceeded, got \(error)")
        }
    }

    func test_pgpErrorMapper_revocationErrorMapped() {
        let error = PGPErrorMapper.map(.RevocationError(reason: "bad cert"))
        if case .revocationError(let reason) = error {
            XCTAssertEqual(reason, "bad cert")
        } else {
            XCTFail("Expected .revocationError, got \(error)")
        }
    }

    func test_pgpErrorMapper_keyGenerationFailedMapped() {
        let error = PGPErrorMapper.map(.KeyGenerationFailed(reason: "rng failure"))
        if case .keyGenerationFailed(let reason) = error {
            XCTAssertEqual(reason, "rng failure")
        } else {
            XCTFail("Expected .keyGenerationFailed, got \(error)")
        }
    }

    func test_pgpErrorMapper_s2kErrorMapped() {
        let error = PGPErrorMapper.map(.S2kError(reason: "unsupported mode"))
        if case .s2kError(let reason) = error {
            XCTAssertEqual(reason, "unsupported mode")
        } else {
            XCTFail("Expected .s2kError, got \(error)")
        }
    }

    func test_pgpErrorMapper_internalErrorMapped() {
        let error = PGPErrorMapper.map(.InternalError(reason: "unexpected state"))
        if case .internalError(let reason) = error {
            XCTAssertEqual(reason, "unexpected state")
        } else {
            XCTFail("Expected .internalError, got \(error)")
        }
    }

    func test_cypherAirError_errorDescription_notNil() {
        // Every error case should produce a non-nil errorDescription
        let errors: [CypherAirError] = [
            .aeadAuthenticationFailed,
            .noMatchingKey,
            .unsupportedAlgorithm(algo: "RSA"),
            .keyExpired,
            .badSignature,
            .unknownSigner,
            .corruptData(reason: "test"),
            .wrongPassphrase,
            .invalidKeyData(reason: "test"),
            .encryptionFailed(reason: "test"),
            .signingFailed(reason: "test"),
            .armorError(reason: "test"),
            .integrityCheckFailed,
            .argon2idMemoryExceeded(requiredMb: 512),
            .revocationError(reason: "test"),
            .keyGenerationFailed(reason: "test"),
            .s2kError(reason: "test"),
            .internalError(reason: "test"),
            .secureEnclaveUnavailable,
            .authenticationFailed,
            .authenticationCancelled,
            .keychainError("test"),
            .invalidQRCode,
            .unsupportedQRVersion,
            .contactImportRequiresPublicCertificate,
            .fileTooLarge(sizeMB: 200),
            .noKeySelected,
            .noRecipientsSelected,
            .biometricsUnavailable,
            .fileIoError(reason: "test io error"),
            .operationCancelled,
            .insufficientDiskSpace(fileSizeMB: 50, requiredMB: 100, availableMB: 30),
            .duplicateKey,
            .keyTooLargeForQr,
            .contactsUnavailable(.locked),
        ]

        for error in errors {
            XCTAssertNotNil(error.errorDescription,
                            "\(error) should have a non-nil errorDescription")
            XCTAssertFalse(error.errorDescription!.isEmpty,
                           "\(error) should have a non-empty errorDescription")
        }
    }

    // MARK: - Contact: Display Name

    func test_contact_displayName_withNameAndEmail_extractsName() {
        let contact = makeContact(userId: "Alice <alice@example.com>")
        XCTAssertEqual(contact.displayName, "Alice")
    }

    func test_contact_displayName_nilUserId_returnsUnknown() {
        let contact = makeContact(userId: nil)
        // The display name should use the localized "Unknown" fallback
        XCTAssertFalse(contact.displayName.isEmpty)
    }

    func test_contact_displayName_noAngleBrackets_returnsUserId() {
        let contact = makeContact(userId: "just-a-name")
        XCTAssertEqual(contact.displayName, "just-a-name")
    }

    // MARK: - Contact: Email Extraction

    func test_contact_email_extractsFromUserId() {
        let contact = makeContact(userId: "Alice <alice@example.com>")
        XCTAssertEqual(contact.email, "alice@example.com")
    }

    func test_contact_email_noAngleBrackets_returnsNil() {
        let contact = makeContact(userId: "Alice")
        XCTAssertNil(contact.email)
    }

    func test_contact_email_nilUserId_returnsNil() {
        let contact = makeContact(userId: nil)
        XCTAssertNil(contact.email)
    }

    // MARK: - Contact: canEncryptTo

    func test_contact_canEncryptTo_validKey_returnsTrue() {
        let contact = makeContact(hasEncryptionSubkey: true, isRevoked: false, isExpired: false)
        XCTAssertTrue(contact.canEncryptTo)
    }

    func test_contact_canEncryptTo_expired_returnsFalse() {
        let contact = makeContact(hasEncryptionSubkey: true, isRevoked: false, isExpired: true)
        XCTAssertFalse(contact.canEncryptTo)
    }

    func test_contact_canEncryptTo_revoked_returnsFalse() {
        let contact = makeContact(hasEncryptionSubkey: true, isRevoked: true, isExpired: false)
        XCTAssertFalse(contact.canEncryptTo)
    }

    func test_contact_canEncryptTo_noSubkey_returnsFalse() {
        let contact = makeContact(hasEncryptionSubkey: false, isRevoked: false, isExpired: false)
        XCTAssertFalse(contact.canEncryptTo)
    }

    // MARK: - PGPKeyIdentity: Computed Properties

    func test_pgpKeyIdentity_shortKeyId_returnsLast16Chars() {
        let identity = makeIdentity(fingerprint: "abcdef1234567890abcdef1234567890abcdef12")
        XCTAssertEqual(identity.shortKeyId, "34567890abcdef12")
    }

    func test_pgpKeyIdentity_formattedFingerprint_groupsOf4() {
        let identity = makeIdentity(fingerprint: "abcdef1234567890")
        XCTAssertEqual(identity.formattedFingerprint, "abcd ef12 3456 7890")
    }

    func test_identityPresentation_fingerprintGroups_groupsInChunksOfFour() {
        XCTAssertEqual(
            IdentityPresentation.fingerprintGroups("abcdef1234567890"),
            ["abcd", "ef12", "3456", "7890"]
        )
    }

    func test_identityPresentation_fingerprintGroups_preservesShortFinalGroup() {
        XCTAssertEqual(
            IdentityPresentation.fingerprintGroups("abcdef12345"),
            ["abcd", "ef12", "345"]
        )
    }

    func test_identityPresentation_fingerprintAccessibilityGroupLabel_spellsCharacters() {
        XCTAssertEqual(
            IdentityPresentation.fingerprintAccessibilityGroupLabel("ab12"),
            "a b 1 2"
        )
    }

    // MARK: - PGPKeyProfile

    func test_pgpKeyProfile_decode_historicalRawValues() throws {
        let decoder = JSONDecoder()

        XCTAssertEqual(
            try decoder.decode(PGPKeyProfile.self, from: Data(#""universal""#.utf8)),
            .universal
        )
        XCTAssertEqual(
            try decoder.decode(PGPKeyProfile.self, from: Data(#""advanced""#.utf8)),
            .advanced
        )
    }

    func test_pgpKeyProfile_encodeDecode_universal_roundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let profile = PGPKeyProfile.universal
        let data = try encoder.encode(profile)
        let decoded = try decoder.decode(PGPKeyProfile.self, from: data)

        XCTAssertEqual(decoded, .universal)
    }

    func test_pgpKeyProfile_encodeDecode_advanced_roundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let profile = PGPKeyProfile.advanced
        let data = try encoder.encode(profile)
        let decoded = try decoder.decode(PGPKeyProfile.self, from: data)

        XCTAssertEqual(decoded, .advanced)
    }

    func test_pgpKeyProfile_decode_unknownValue_throwsError() {
        let decoder = JSONDecoder()
        let invalidJSON = Data("\"quantum\"".utf8)

        XCTAssertThrowsError(try decoder.decode(PGPKeyProfile.self, from: invalidJSON)) { error in
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("Expected DecodingError.dataCorrupted, got \(error)")
                return
            }
        }
    }

    // MARK: - OpenPGPCertificationKind

    func test_openPGPCertificationKind_decode_historicalRawValues() throws {
        let decoder = JSONDecoder()

        let historicalValues: [(String, OpenPGPCertificationKind)] = [
            ("generic", .generic),
            ("persona", .persona),
            ("casual", .casual),
            ("positive", .positive),
        ]

        for (rawValue, expectedKind) in historicalValues {
            let decoded = try decoder.decode(
                OpenPGPCertificationKind.self,
                from: Data(#""\#(rawValue)""#.utf8)
            )
            XCTAssertEqual(decoded, expectedKind)
        }
    }

    func test_openPGPCertificationKind_encode_preservesHistoricalRawValues() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for kind in OpenPGPCertificationKind.allCases {
            let data = try encoder.encode(kind)
            let rawValue = try decoder.decode(String.self, from: data)

            XCTAssertEqual(rawValue, kind.rawValue)
        }
    }

    func test_contactCertificationArtifactReference_decodesLegacyCertificationKindRawValues() throws {
        let decoder = JSONDecoder()

        for kind in OpenPGPCertificationKind.allCases {
            let json = Data("""
            {
              "artifactId": "artifact-\(kind.rawValue)",
              "keyId": "contact-key",
              "createdAt": 0,
              "certificationKind": "\(kind.rawValue)"
            }
            """.utf8)

            let artifact = try decoder.decode(ContactCertificationArtifactReference.self, from: json)

            XCTAssertEqual(artifact.certificationKind, kind)
        }
    }

    // MARK: - SignatureVerification

    func test_signatureVerification_isWarning_forBad() {
        let verification = SignatureVerification(
            status: .bad, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertTrue(verification.isWarning)
    }

    func test_signatureVerification_isWarning_forUnknown() {
        let verification = SignatureVerification(
            status: .unknownSigner, signerFingerprint: "abc", signerContact: nil
        )
        XCTAssertTrue(verification.isWarning)
    }

    func test_signatureVerification_isWarning_validIsFalse() {
        let verification = SignatureVerification(
            status: .valid, signerFingerprint: "abc", signerContact: nil
        )
        XCTAssertFalse(verification.isWarning)
    }

    func test_signatureVerification_isWarning_notSignedIsFalse() {
        let verification = SignatureVerification(
            status: .notSigned, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertFalse(verification.isWarning)
    }

    func test_detailedSignatureVerification_missingCertificateMapsToUnavailableCertificate() {
        let entry = DetailedSignatureEntry(
            status: .unknownSigner,
            signerPrimaryFingerprint: nil,
            state: .signerCertificateUnavailable,
            verificationCertificateFingerprint: nil
        )

        let detailed = PGPMessageResultMapper.detachedVerifyDetailedResult(
            VerifyDetailedResult(
                legacyStatus: .unknownSigner,
                legacySignerFingerprint: nil,
                summaryState: .signerCertificateUnavailable,
                summaryEntryIndex: 0,
                signatures: [entry],
                content: nil
            ),
            context: PGPMessageVerificationContext(
                verificationKeys: [],
                contacts: [],
                ownKeys: [],
                contactsAvailability: .availableLegacyCompatibility
            )
        )

        XCTAssertEqual(detailed.summaryState, .signerCertificateUnavailable)
        XCTAssertEqual(detailed.signatures[0].verificationState, .signerCertificateUnavailable)
        XCTAssertFalse(detailed.legacyVerification.requiresContactsContext)
        XCTAssertNil(detailed.legacyVerification.contactsUnavailableReason)
    }

    // MARK: - SignatureVerification: statusColor

    func test_signatureVerification_statusColor_validIsGreen() {
        let verification = SignatureVerification(
            status: .valid, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertEqual(verification.statusColor, .green)
    }

    func test_signatureVerification_statusColor_badIsRed() {
        let verification = SignatureVerification(
            status: .bad, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertEqual(verification.statusColor, .red)
    }

    func test_signatureVerification_statusColor_notSignedIsSecondary() {
        let verification = SignatureVerification(
            status: .notSigned, signerFingerprint: nil, signerContact: nil
        )
        XCTAssertEqual(verification.statusColor, .secondary)
    }

    func test_signatureVerification_signerIdentity_prefersVerifiedContact() {
        let contact = makeContact(
            fingerprint: "abcdef1234567890abcdef1234567890",
            userId: "Alice <alice@example.com>"
        )

        let identity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: contact.fingerprint,
            contacts: [contact],
            ownKeys: []
        )

        XCTAssertEqual(identity?.source, .contact)
        XCTAssertEqual(identity?.displayName, "Alice")
        XCTAssertEqual(identity?.secondaryText, "alice@example.com")
        XCTAssertTrue(identity?.isVerifiedContact == true)
    }

    func test_signatureVerification_signerIdentity_resolvesOwnKey() {
        let ownKey = makeIdentity(fingerprint: "1234567890abcdef1234567890abcdef")

        let identity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: ownKey.fingerprint,
            contacts: [],
            ownKeys: [ownKey]
        )

        XCTAssertEqual(identity?.source, .ownKey)
        XCTAssertEqual(identity?.displayName, "Your Key")
        XCTAssertEqual(identity?.secondaryText, ownKey.userId)
    }

    func test_signatureVerification_signerIdentity_unknownFallback_keepsFingerprint() {
        let fingerprint = "fedcba0987654321fedcba0987654321"

        let identity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: fingerprint,
            contacts: [],
            ownKeys: []
        )

        XCTAssertEqual(identity?.source, .unknown)
        XCTAssertEqual(identity?.shortKeyId, "fedcba0987654321")
        XCTAssertEqual(identity?.fingerprint, fingerprint)
    }

    // MARK: - Protected Ordinary Settings

    func test_protectedOrdinarySettings_gracePeriod_validValuePersists() {
        let defaults = makeIsolatedDefaults()
        let coordinator = makeLoadedProtectedOrdinarySettings(defaults: defaults)

        coordinator.setGracePeriod(60)

        let reloaded = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        XCTAssertEqual(reloaded.snapshot?.gracePeriod, 60)
    }

    func test_protectedOrdinarySettings_gracePeriod_invalidValueClampsToDefault() {
        let defaults = makeIsolatedDefaults()
        let coordinator = makeLoadedProtectedOrdinarySettings(defaults: defaults)

        coordinator.setGracePeriod(42)

        XCTAssertEqual(coordinator.snapshot?.gracePeriod, AuthPreferences.defaultGracePeriod)
    }

    func test_protectedOrdinarySettings_startsLockedWithoutReadingPersistence() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: .firstRunDefaults
        )

        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        XCTAssertNil(coordinator.gracePeriodForSession)
        XCTAssertNil(coordinator.hasCompletedOnboarding)
        XCTAssertNil(coordinator.encryptToSelf)
        XCTAssertEqual(coordinator.colorTheme, .systemDefault)
        XCTAssertEqual(persistence.loadCount, 0)
        XCTAssertEqual(persistence.saveCount, 0)
    }

    func test_protectedOrdinarySettings_loadsOnlyAfterUnlockedPostAuthenticationDomain() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: ProtectedOrdinarySettingsSnapshot(
                gracePeriod: 300,
                hasCompletedOnboarding: true,
                colorTheme: .teal,
                encryptToSelf: false,
                guidedTutorialCompletedVersion: GuidedTutorialVersion.current
            )
        )
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        coordinator.loadAfterAppAuthentication(
            protectedSettingsDomainState: .unlocked
        )

        XCTAssertEqual(coordinator.snapshot?.gracePeriod, 300)
        XCTAssertEqual(coordinator.snapshot?.hasCompletedOnboarding, true)
        XCTAssertEqual(coordinator.snapshot?.colorTheme, .teal)
        XCTAssertEqual(coordinator.snapshot?.encryptToSelf, false)
        XCTAssertEqual(persistence.loadCount, 1)
    }

    func test_protectedOrdinarySettings_lockedPostAuthenticationDomainFailsClosed() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: .firstRunDefaults
        )
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        coordinator.loadAfterAppAuthentication(
            protectedSettingsDomainState: .locked
        )

        XCTAssertNil(coordinator.snapshot)
        XCTAssertEqual(coordinator.state, .recoveryRequired)
        XCTAssertEqual(persistence.loadCount, 0)
        XCTAssertEqual(persistence.saveCount, 0)
    }

    func test_protectedOrdinarySettings_recoveryDoesNotReadPersistence() {
        let persistence = SpyProtectedOrdinarySettingsPersistence(
            snapshot: ProtectedOrdinarySettingsSnapshot(
                gracePeriod: 300,
                hasCompletedOnboarding: true,
                colorTheme: .teal,
                encryptToSelf: false,
                guidedTutorialCompletedVersion: GuidedTutorialVersion.current
            )
        )
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: persistence
        )

        coordinator.loadAfterAppAuthentication(
            protectedSettingsDomainState: .recoveryNeeded
        )

        XCTAssertNil(coordinator.snapshot)
        XCTAssertEqual(coordinator.state, .recoveryRequired)
        XCTAssertEqual(persistence.loadCount, 0)
        XCTAssertEqual(persistence.saveCount, 0)
    }

    func test_appConfiguration_appSessionPolicy_defaultsToUserPresence() {
        let defaults = makeIsolatedDefaults()
        let config = AppConfiguration(defaults: defaults)

        XCTAssertEqual(config.appSessionAuthenticationPolicy, .userPresence)
    }

    func test_appConfiguration_appSessionPolicy_persistsBiometricsOnly() {
        let defaults = makeIsolatedDefaults()
        let config = AppConfiguration(defaults: defaults)
        config.appSessionAuthenticationPolicy = .biometricsOnly

        let reloaded = AppConfiguration(defaults: defaults)
        XCTAssertEqual(reloaded.appSessionAuthenticationPolicy, .biometricsOnly)
    }

    func test_appConfiguration_resetRemovesLegacyRequireAuthOnLaunchKey() {
        let defaults = makeIsolatedDefaults()
        defaults.set(false, forKey: "com.cypherair.preference.requireAuthOnLaunch")
        let config = AppConfiguration(defaults: defaults)

        config.resetToFirstRunDefaults()

        XCTAssertNil(defaults.object(forKey: "com.cypherair.preference.requireAuthOnLaunch"))
    }

    func test_protectedOrdinarySettings_guidedTutorial_defaultsToNeverCompleted() {
        let defaults = makeIsolatedDefaults()
        let coordinator = makeLoadedProtectedOrdinarySettings(defaults: defaults)

        XCTAssertEqual(coordinator.snapshot?.guidedTutorialCompletedVersion, 0)
        XCTAssertEqual(coordinator.guidedTutorialCompletionState, .neverCompleted)
    }

    func test_protectedOrdinarySettings_guidedTutorial_currentVersionPersists() {
        let defaults = makeIsolatedDefaults()
        let coordinator = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        coordinator.markGuidedTutorialCompletedCurrentVersion()

        let reloaded = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        XCTAssertEqual(reloaded.snapshot?.guidedTutorialCompletedVersion, GuidedTutorialVersion.current)
        XCTAssertEqual(reloaded.guidedTutorialCompletionState, .completedCurrentVersion)
    }

    func test_protectedOrdinarySettings_guidedTutorial_oldVersionIsRecognized() {
        let defaults = makeIsolatedDefaults()
        defaults.set(GuidedTutorialVersion.current - 1, forKey: "com.cypherair.preference.guidedTutorialCompletedVersion")

        let coordinator = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        XCTAssertEqual(coordinator.guidedTutorialCompletionState, .completedPreviousVersion)
    }

    // MARK: - Contact: Formatted Fingerprint

    func test_contact_formattedFingerprint_groupsOf4() {
        let contact = makeContact(fingerprint: "abcdef1234567890")
        XCTAssertEqual(contact.formattedFingerprint, "abcd ef12 3456 7890")
    }

    // MARK: - Factory Helpers

    private func makeContact(
        fingerprint: String = "abc123",
        userId: String? = "Test <test@example.com>",
        hasEncryptionSubkey: Bool = true,
        isRevoked: Bool = false,
        isExpired: Bool = false
    ) -> Contact {
        Contact(
            fingerprint: fingerprint,
            keyVersion: 4,
            profile: .universal,
            userId: userId,
            isRevoked: isRevoked,
            isExpired: isExpired,
            hasEncryptionSubkey: hasEncryptionSubkey,
            verificationState: .verified,
            publicKeyData: Data(),
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519"
        )
    }

    private func makeIdentity(
        fingerprint: String = "abc123"
    ) -> PGPKeyIdentity {
        PGPKeyIdentity(
            fingerprint: fingerprint,
            keyVersion: 4,
            profile: .universal,
            userId: "Test",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            isDefault: false,
            isBackedUp: false,
            publicKeyData: Data(),
            revocationCert: Data(),
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            expiryDate: nil
        )
    }

    private func makeIsolatedDefaults() -> UserDefaults {
        let suiteName = "com.cypherair.tests.model.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }

    private func makeLoadedProtectedOrdinarySettings(
        defaults: UserDefaults
    ) -> ProtectedOrdinarySettingsCoordinator {
        let coordinator = ProtectedOrdinarySettingsCoordinator(
            persistence: LegacyOrdinarySettingsStore(defaults: defaults)
        )
        coordinator.loadForAuthenticatedTestBypass()
        return coordinator
    }

    private final class SpyProtectedOrdinarySettingsPersistence: ProtectedOrdinarySettingsPersistence {
        private let storedSnapshot: ProtectedOrdinarySettingsSnapshot
        private(set) var loadCount = 0
        private(set) var saveCount = 0

        init(snapshot: ProtectedOrdinarySettingsSnapshot) {
            self.storedSnapshot = snapshot
        }

        func loadSnapshot() -> ProtectedOrdinarySettingsSnapshot {
            loadCount += 1
            return storedSnapshot
        }

        func saveSnapshot(_ snapshot: ProtectedOrdinarySettingsSnapshot) {
            saveCount += 1
        }

        func removePersistentValues() {}
    }

    // MARK: - ColorTheme

    func test_colorTheme_allCases_returnValidActionColors() {
        for theme in ColorTheme.allCases {
            let colors = theme.actionColors
            // Verify all 4 named properties are accessible (compilation check + no crashes)
            _ = colors.encrypt
            _ = colors.decrypt
            _ = colors.sign
            _ = colors.verify
        }
    }

    func test_colorTheme_allCases_haveAccentColor() {
        for theme in ColorTheme.allCases {
            // Verify accentColor is accessible for every theme
            _ = theme.accentColor
        }
    }

    func test_colorTheme_allCases_havePreviewColors() {
        for theme in ColorTheme.allCases {
            XCTAssertFalse(theme.previewColors.isEmpty, "\(theme) has empty previewColors")
        }
    }

    func test_colorTheme_allCases_haveDisplayName() {
        for theme in ColorTheme.allCases {
            XCTAssertFalse(theme.displayName.isEmpty, "\(theme) has empty displayName")
        }
    }

    func test_colorTheme_systemDefault_preservesOriginalColors() {
        let colors = ColorTheme.systemDefault.actionColors
        // System default uses the same original hardcoded SwiftUI colors
        XCTAssertEqual(colors.encrypt, .blue)
        XCTAssertEqual(colors.decrypt, .green)
        XCTAssertEqual(colors.sign, .orange)
        XCTAssertEqual(colors.verify, .purple)
    }

    func test_colorTheme_systemDefault_hasNilAccentColor() {
        XCTAssertNil(ColorTheme.systemDefault.accentColor)
    }

    func test_colorTheme_defaultBlue_hasBlueAccentColor() {
        XCTAssertEqual(ColorTheme.defaultBlue.accentColor, .blue)
    }

    func test_colorTheme_defaultBlue_preservesOriginalColors() {
        let colors = ColorTheme.defaultBlue.actionColors
        XCTAssertEqual(colors.encrypt, .blue)
        XCTAssertEqual(colors.decrypt, .green)
        XCTAssertEqual(colors.sign, .orange)
        XCTAssertEqual(colors.verify, .purple)
    }

    func test_colorTheme_multiColorThemes_areIdentified() {
        XCTAssertTrue(ColorTheme.prideRainbow.isMultiColor)
        XCTAssertTrue(ColorTheme.transPride.isMultiColor)
        XCTAssertTrue(ColorTheme.bisexualPride.isMultiColor)
        XCTAssertTrue(ColorTheme.nonBinary.isMultiColor)

        XCTAssertFalse(ColorTheme.systemDefault.isMultiColor)
        XCTAssertFalse(ColorTheme.defaultBlue.isMultiColor)
        XCTAssertFalse(ColorTheme.purple.isMultiColor)
        XCTAssertFalse(ColorTheme.graphite.isMultiColor)
    }

    func test_protectedOrdinarySettings_colorTheme_persistsToUserDefaults() {
        let defaults = makeIsolatedDefaults()
        let coordinator = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        coordinator.setColorTheme(.purple)

        let reloaded = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        XCTAssertEqual(reloaded.colorTheme, .purple)
    }

    func test_protectedOrdinarySettings_colorTheme_defaultsToSystemDefault() {
        let defaults = makeIsolatedDefaults()
        let coordinator = makeLoadedProtectedOrdinarySettings(defaults: defaults)
        XCTAssertEqual(coordinator.colorTheme, .systemDefault)
    }

    func test_colorTheme_rawValue_roundTrips() {
        for theme in ColorTheme.allCases {
            let raw = theme.rawValue
            let restored = ColorTheme(rawValue: raw)
            XCTAssertEqual(restored, theme, "Round-trip failed for \(theme)")
        }
    }

    func test_certificateSelectionAdapter_selectorInput_preservesBytesAndOccurrence() {
        let option = UserIdSelectionOption(
            occurrenceIndex: 1,
            userIdData: Data("duplicate@example.com".utf8),
            displayText: "duplicate@example.com",
            isCurrentlyPrimary: false,
            isCurrentlyRevoked: true
        )
        let selectorInput = PGPCertificateSelectionAdapter.userIdSelectorInput(for: option)

        XCTAssertEqual(selectorInput.userIdData, option.userIdData)
        XCTAssertEqual(selectorInput.occurrenceIndex, 1)
    }
}
