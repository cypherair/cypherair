import Foundation

@MainActor
struct TutorialConfigurationFactory {
    let store: TutorialSessionStore

    func keyGenerationConfiguration(isActiveModule: Bool) -> KeyGenerationView.Configuration {
        var configuration = KeyGenerationView.Configuration(
            prefilledName: String(
                localized: "guidedTutorial.demoName.alice",
                defaultValue: "Alice Demo"
            ),
            prefilledEmail: "alice@demo.invalid",
            lockedProfile: .advanced,
            lockedExpiryMonths: 24,
            postGenerationBehavior: .suppressPrompt
        )

        if isActiveModule {
            configuration.onGenerated = { [weak store] identity in
                Task { @MainActor in
                    await store?.noteAliceGenerated(identity)
                    store?.navigateToPostGenerationPrompt(identity)
                }
            }
        }

        return configuration
    }

    func addContactConfiguration(isActiveModule: Bool) -> AddContactView.Configuration {
        var configuration = AddContactView.Configuration(
            allowedImportModes: [.paste],
            verificationPolicy: .verifiedOnly
        )

        if isActiveModule {
            configuration.prefilledArmoredText = store.session.artifacts.bobArmoredPublicKey
            configuration.onImported = { [weak store] contact in
                store?.noteBobImported(contact)
                store?.selectTab(.contacts)
                store?.setRoutePath(
                    [
                        .addContact,
                        .contactDetail(contactId: contact.contactId ?? "legacy-contact-\(contact.fingerprint)"),
                    ],
                    for: .contacts
                )
            }
            configuration.onImportConfirmationRequested = { [weak store] request in
                store?.presentImportConfirmation(request)
            }
        }

        return configuration
    }

    func encryptConfiguration(isActiveModule: Bool) -> EncryptView.Configuration {
        var configuration = EncryptView.Configuration(
            signingPolicy: .fixed(true),
            encryptToSelfPolicy: .fixed(false),
            allowsClipboardWrite: false,
            allowsResultExport: false,
            allowsFileInput: false,
            allowsFileResultExport: false,
            fileRestrictionMessage: fileModeRestrictionMessage,
            outputInterceptionPolicy: outputInterceptionPolicy
        )

        if isActiveModule {
            configuration.prefilledPlaintext = String(
                localized: "guidedTutorial.encrypt.prefill",
                defaultValue: "Hi Bob, this is a sandbox message from Alice. It is signed and encrypted inside the guided tutorial."
            )
            configuration.initialRecipientContactIds = store.session.artifacts.bobContact.map {
                [$0.contactId ?? "legacy-contact-\($0.fingerprint)"]
            } ?? []
            configuration.initialRecipientFingerprints = store.session.artifacts.bobContact.map { [$0.fingerprint] } ?? []
            configuration.initialSignerFingerprint = store.session.artifacts.aliceIdentity?.fingerprint
            configuration.onEncrypted = { [weak store] ciphertext in
                store?.noteEncrypted(ciphertext)
            }
        }

        return configuration
    }

    func decryptConfiguration(isActiveModule: Bool) -> DecryptView.Configuration {
        var configuration = DecryptView.Configuration(
            allowsTextFileImport: false,
            allowsFileInput: false,
            allowsFileResultExport: false,
            textFileRestrictionMessage: textImportRestrictionMessage,
            fileRestrictionMessage: fileModeRestrictionMessage,
            outputInterceptionPolicy: outputInterceptionPolicy
        )

        if isActiveModule {
            configuration.prefilledCiphertext = store.session.artifacts.encryptedMessage
            configuration.initialPhase1Result = store.session.artifacts.parseResult
            configuration.onParsed = { [weak store] result in
                store?.noteParsed(result)
            }
            configuration.onDecrypted = { [weak store] plaintext, verification in
                store?.noteDecrypted(plaintext: plaintext, verification: verification)
            }
        }

        return configuration
    }

    func signConfiguration() -> SignView.Configuration {
        SignView.Configuration(
            allowsClipboardWrite: false,
            allowsTextResultExport: false,
            allowsFileInput: false,
            allowsFileResultExport: false,
            fileRestrictionMessage: fileModeRestrictionMessage,
            resultRestrictionMessage: signResultRestrictionMessage,
            outputInterceptionPolicy: outputInterceptionPolicy
        )
    }

    func verifyConfiguration() -> VerifyView.Configuration {
        VerifyView.Configuration(
            allowsCleartextFileImport: false,
            allowsDetachedOriginalImport: false,
            allowsDetachedSignatureImport: false,
            cleartextFileRestrictionMessage: textImportRestrictionMessage,
            detachedFileRestrictionMessage: detachedVerifyRestrictionMessage
        )
    }

    func backupConfiguration(isActiveModule: Bool) -> BackupKeyView.Configuration {
        var configuration = BackupKeyView.Configuration(resultPresentation: .inlinePreview)

        if isActiveModule {
            configuration.onExported = { [weak store] data in
                store?.noteBackupExported(data)
            }
        }

        return configuration
    }

    func keyDetailConfiguration() -> KeyDetailView.Configuration {
        KeyDetailView.Configuration(
            allowsPublicKeySave: false,
            allowsPublicKeyCopy: false,
            allowsRevocationExport: false,
            showsSelectiveRevocationEntry: true,
            allowsSelectiveRevocationLaunch: false,
            selectiveRevocationRestrictionMessage: String(
                localized: "guidedTutorial.restricted.selectiveRevocation",
                defaultValue: "Selective revocation exports are unavailable inside the tutorial sandbox."
            ),
            outputInterceptionPolicy: outputInterceptionPolicy
        )
    }

    func contactDetailConfiguration() -> ContactDetailView.Configuration {
        ContactDetailView.Configuration(
            showsCertificateSignatureEntry: true,
            allowsCertificateSignatureLaunch: false,
            certificateSignatureRestrictionMessage: String(
                localized: "guidedTutorial.restricted.certificateSignatures",
                defaultValue: "Certificate signature workflows are unavailable inside the tutorial sandbox."
            )
        )
    }

    func settingsConfiguration() -> SettingsView.Configuration {
        var configuration = SettingsView.Configuration(
            onAuthModeConfirmationRequested: { [weak store] request in
                store?.presentAuthModeConfirmation(request)
            },
            isOnboardingEntryEnabled: false,
            isGuidedTutorialEntryEnabled: false,
            isThemePickerEnabled: true,
            isAppIconEntryEnabled: false,
            navigationEducationFooter: String(
                localized: "guidedTutorial.settings.restricted.navigation",
                defaultValue: "Onboarding and Guided Tutorial are unavailable inside the tutorial sandbox."
            ),
            appearanceEducationFooter: String(
                localized: "guidedTutorial.settings.restricted.appIcon",
                defaultValue: "App Icon changes affect the real app and are unavailable inside the tutorial sandbox."
            )
        )
        configuration.protectedSettingsHostMode = .tutorialSandbox
        configuration.protectedSettingsHost = ProtectedSettingsHost(mode: .tutorialSandbox)
        configuration.localDataResetAvailability = .disabled(
            footer: String(
                localized: "guidedTutorial.settings.restricted.localDataReset",
                defaultValue: "The tutorial sandbox cannot reset real CypherAir data."
            )
        )
        return configuration
    }

    private var fileModeRestrictionMessage: String {
        String(
            localized: "guidedTutorial.restricted.fileMode",
            defaultValue: "Real file import and export are unavailable in the tutorial sandbox. Use Text mode to keep exploring this page safely."
        )
    }

    private var textImportRestrictionMessage: String {
        String(
            localized: "guidedTutorial.restricted.textImport",
            defaultValue: "Real file import is unavailable in the tutorial sandbox. Paste text directly to keep exploring this page safely."
        )
    }

    private var signResultRestrictionMessage: String {
        String(
            localized: "guidedTutorial.restricted.signResult",
            defaultValue: "Tutorial sandbox output cannot be copied to the clipboard or saved to a real destination."
        )
    }

    private var detachedVerifyRestrictionMessage: String {
        String(
            localized: "guidedTutorial.restricted.detachedVerify",
            defaultValue: "Detached file verification is unavailable in the tutorial sandbox. Use Cleartext mode to keep exploring this page safely."
        )
    }

    private var outputInterceptionPolicy: OutputInterceptionPolicy {
        store.outputInterceptionPolicy ?? .passthrough
    }
}
