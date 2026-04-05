import Foundation

@MainActor
struct TutorialConfigurationFactory {
    let store: TutorialSessionStore

    func keyGenerationConfiguration() -> KeyGenerationView.Configuration {
        KeyGenerationView.Configuration(
            prefilledName: "Alice Demo",
            prefilledEmail: "alice@demo.invalid",
            lockedProfile: .advanced,
            lockedExpiryMonths: 24,
            postGenerationBehavior: .suppressPrompt,
            onGenerated: { [weak store] identity in
                Task { @MainActor in
                    await store?.noteAliceGenerated(identity)
                    store?.navigateToPostGenerationPrompt(identity)
                }
            }
        )
    }

    func addContactConfiguration() -> AddContactView.Configuration {
        AddContactView.Configuration(
            allowedImportModes: [.paste],
            prefilledArmoredText: store.session.artifacts.bobArmoredPublicKey,
            verificationPolicy: .verifiedOnly,
            onImported: { [weak store] contact in
                store?.noteBobImported(contact)
            },
            onImportConfirmationRequested: { [weak store] request in
                store?.presentImportConfirmation(request)
            }
        )
    }

    func encryptConfiguration() -> EncryptView.Configuration {
        EncryptView.Configuration(
            allowedModes: [.text],
            prefilledPlaintext: String(
                localized: "guidedTutorial.encrypt.prefill",
                defaultValue: "Hi Bob, this is a sandbox message from Alice. It is signed and encrypted inside the guided tutorial."
            ),
            initialRecipientFingerprints: store.session.artifacts.bobContact.map { [$0.fingerprint] } ?? [],
            initialSignerFingerprint: store.session.artifacts.aliceIdentity?.fingerprint,
            signingPolicy: .fixed(true),
            encryptToSelfPolicy: .fixed(false),
            onEncrypted: { [weak store] ciphertext in
                store?.noteEncrypted(ciphertext)
            }
        )
    }

    func decryptConfiguration(for task: TutorialTaskID) -> DecryptView.Configuration {
        DecryptView.Configuration(
            allowedModes: [.text],
            prefilledCiphertext: store.session.artifacts.encryptedMessage,
            initialPhase1Result: task == .decryptMessage ? store.session.artifacts.parseResult : nil,
            onParsed: { [weak store] result in
                store?.noteParsed(result)
            },
            onDecrypted: { [weak store] plaintext, verification in
                store?.noteDecrypted(plaintext: plaintext, verification: verification)
            }
        )
    }

    func backupConfiguration() -> BackupKeyView.Configuration {
        BackupKeyView.Configuration(
            resultPresentation: .inline,
            onExported: { [weak store] data in
                store?.noteBackupExported(data)
            }
        )
    }

    func settingsConfiguration() -> SettingsView.Configuration {
        SettingsView.Configuration(
            onAuthModeConfirmationRequested: { [weak store] request in
                store?.presentAuthModeConfirmation(request)
            }
        )
    }
}
