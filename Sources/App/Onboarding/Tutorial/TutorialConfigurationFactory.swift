import Foundation

@MainActor
struct TutorialConfigurationFactory {
    let store: TutorialSessionStore

    func keyGenerationConfiguration(isActiveModule: Bool) -> KeyGenerationView.Configuration {
        var configuration = KeyGenerationView.Configuration(
            prefilledName: "Alice Demo",
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
            }
            configuration.onImportConfirmationRequested = { [weak store] request in
                store?.presentImportConfirmation(request)
            }
        }

        return configuration
    }

    func encryptConfiguration(isActiveModule: Bool) -> EncryptView.Configuration {
        var configuration = EncryptView.Configuration(
            allowedModes: [.text],
            signingPolicy: .fixed(true),
            encryptToSelfPolicy: .fixed(false),
            allowsClipboardWrite: false,
            allowsResultExport: false
        )

        if isActiveModule {
            configuration.prefilledPlaintext = String(
                localized: "guidedTutorial.encrypt.prefill",
                defaultValue: "Hi Bob, this is a sandbox message from Alice. It is signed and encrypted inside the guided tutorial."
            )
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
            allowedModes: [.text],
            allowsTextFileImport: false,
            allowsFileResultExport: false
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

    func backupConfiguration(isActiveModule: Bool) -> BackupKeyView.Configuration {
        var configuration = BackupKeyView.Configuration(resultSink: .tutorialArtifact)

        if isActiveModule {
            configuration.onExported = { [weak store] data in
                store?.noteBackupExported(data)
            }
        }

        return configuration
    }

    func settingsConfiguration() -> SettingsView.Configuration {
        SettingsView.Configuration(
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
    }
}
