import Sealing
import SwiftUI

/// What the lock surface needs beyond the lock controller: the key list and
/// its export for the integrity-failure screen, and the reset flow.
struct AppLockSurfaceServices {
    let keyManagement: KeyManagementService
    let appSessionOrchestrator: AppSessionOrchestrator
    let localDataReset: LocalDataResetService
    let restartCoordinator: LocalDataResetRestartCoordinator
}

/// The face of the shield window while the app is not unlocked: first-run
/// setup, the passphrase prompt, the integrity-failure screen, or the
/// restart notice.
struct AppLockSurfaceView: View {
    let appLockController: AppLockController
    let services: AppLockSurfaceServices
    @State private var resetFlow: LocalDataResetFlow

    init(appLockController: AppLockController, services: AppLockSurfaceServices) {
        self.appLockController = appLockController
        self.services = services
        _resetFlow = State(initialValue: LocalDataResetFlow(
            service: services.localDataReset,
            restartCoordinator: services.restartCoordinator
        ))
    }

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
                .ignoresSafeArea()
            content
        }
        .localDataResetPresentations(flow: resetFlow)
        .environment(services.keyManagement)
        .environment(services.appSessionOrchestrator)
        .task {
            await appLockController.handleForegroundActive()
        }
        .accessibilityIdentifier("appLock.surface")
        .accessibilityAddTraits(.isModal)
    }

    @ViewBuilder
    private var content: some View {
        if services.restartCoordinator.restartRequiredAfterLocalDataReset {
            LocalDataResetRestartRequiredView(
                terminateAction: LocalDataResetRestartAction.terminateCurrentProcess
            )
        } else {
            switch appLockController.lockState {
            case .setupRequired:
                VaultSetupView(appLockController: appLockController)
            case .locked, .unlocking, .failed:
                UnlockView(appLockController: appLockController, resetFlow: resetFlow)
            case .integrityFailure(let report):
                VaultIntegrityFailureView(report: report, resetFlow: resetFlow)
            case .restartRequired:
                RestartRequiredView()
            case .unlocked:
                EmptyView()
            }
        }
    }
}

// MARK: - Unlock

private struct UnlockView: View {
    let appLockController: AppLockController
    let resetFlow: LocalDataResetFlow
    @State private var passphrase = ""
    @State private var isRevealed = false
    @FocusState private var isPassphraseFocused: Bool

    var body: some View {
        ViewThatFits(in: .vertical) {
            unlockContent
            ScrollView {
                unlockContent
            }
        }
        .onAppear {
            isPassphraseFocused = true
        }
        .onChange(of: appLockController.lockState) { _, state in
            if case .failed = state {
                isPassphraseFocused = true
            }
        }
    }

    private var unlockContent: some View {
        VStack(spacing: 28) {
            LockHeader(subtitle: String(localized: "privacy.locked.title", defaultValue: "Locked"))
            VStack(spacing: 14) {
                HStack(spacing: CypherSpacing.compact) {
                    CypherSecureTextField(
                        String(localized: "vault.unlock.field", defaultValue: "Passphrase"),
                        text: $passphrase,
                        isRevealed: isRevealed,
                        submitLabel: .go,
                        onSubmit: submit
                    )
                    .font(isRevealed ? .system(.body, design: .monospaced) : .body)
                    .textFieldStyle(.roundedBorder)
                    .focused($isPassphraseFocused)
                    .disabled(!appLockController.acceptsPassphrase)
                    .accessibilityIdentifier("appLock.passphrase")
                    PassphraseRevealToggle(isRevealed: $isRevealed)
                }
                if let message = failureMessage {
                    Text(message)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("appLock.failure")
                }
                Button(action: submit) {
                    if appLockController.isUnlocking {
                        ProgressView()
                            .frame(minWidth: 200)
                    } else {
                        Label(
                            String(localized: "vault.unlock.action", defaultValue: "Unlock"),
                            systemImage: biometricIconName
                        )
                        .font(.headline)
                        .frame(minWidth: 200)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!canSubmit)
                .accessibilityIdentifier("appLock.unlock")
                Text(String(
                    localized: "vault.unlock.hint",
                    defaultValue: "Your passphrase, then Face ID or Touch ID."
                ))
                .font(.footnote)
                .foregroundStyle(.secondary)
                Button(String(localized: "vault.unlock.forgot", defaultValue: "Forgot Passphrase…")) {
                    resetFlow.request()
                }
                .buttonStyle(.plain)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .disabled(appLockController.isUnlocking)
                .accessibilityIdentifier("appLock.forgotPassphrase")
            }
            .frame(maxWidth: 440)
        }
        .padding(24)
    }

    private var canSubmit: Bool {
        appLockController.acceptsPassphrase && !passphrase.isEmpty
    }

    private func submit() {
        guard canSubmit else { return }
        let entered = SensitiveKeyBox(SensitiveBuffer.utf8(passphrase))
        passphrase = ""
        isRevealed = false
        Task { await appLockController.unlock(passphrase: entered.copied()) }
    }

    private var failureMessage: String? {
        guard case .failed(let failure) = appLockController.lockState else { return nil }
        return failure.message
    }

    private var biometricIconName: String {
        #if os(macOS)
        "touchid"
        #elseif os(visionOS)
        "opticid"
        #else
        "faceid"
        #endif
    }
}

extension AppLockController.UnlockFailure {
    var message: String {
        switch self {
        case .wrongPassphrase:
            String(localized: "vault.unlock.failure.wrongPassphrase", defaultValue: "That passphrase is not right.")
        case .presenceCancelled:
            String(localized: "vault.unlock.failure.cancelled", defaultValue: "Unlock was cancelled.")
        case .presenceFailed:
            String(localized: "vault.unlock.failure.presence", defaultValue: "Face ID or Touch ID did not confirm it is you.")
        case .presenceUnavailable:
            String(
                localized: "vault.unlock.failure.presenceUnavailable",
                defaultValue: "Face ID or Touch ID is not available right now. Unlock the device with its passcode or password, then try again."
            )
        case .enclaveUnavailable:
            String(localized: "vault.unlock.failure.enclave", defaultValue: "The Secure Enclave is not available on this device.")
        case .sealedRootDamaged:
            String(
                localized: "vault.unlock.failure.damaged",
                defaultValue: "The vault on this device is damaged and cannot be opened. Reset All Local Data is the only remedy."
            )
        case .other(let reason):
            String(localized: "vault.unlock.failure.other", defaultValue: "Unlock failed: \(reason)")
        }
    }
}

// MARK: - Setup

private struct VaultSetupView: View {
    let appLockController: AppLockController
    @State private var passphrase = ""
    @State private var confirmation = ""
    @FocusState private var focus: CypherPassphraseEntry.Field?

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: CypherSpacing.compact) {
                    Text(String(localized: "vault.setup.title", defaultValue: "Choose Your Passphrase"))
                        .font(.title2.weight(.semibold))
                    Text(String(
                        localized: "vault.setup.body",
                        defaultValue: "Everything CypherAir X keeps on this device is sealed under this passphrase together with this device's Secure Enclave. It is never stored, and nobody can recover it: if you forget it, the only way forward is a reset that erases everything."
                    ))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 4)
            }
            Section {
                CypherPassphraseEntry(
                    passphrase: $passphrase,
                    confirmation: $confirmation,
                    focus: $focus
                )
            }
            Section {
                Button(action: create) {
                    if appLockController.isUnlocking {
                        ProgressView()
                            .cypherPrimaryActionLabelFrame()
                    } else {
                        Text(String(localized: "vault.setup.action", defaultValue: "Create Vault"))
                            .cypherPrimaryActionLabelFrame()
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!canCreate)
                .accessibilityIdentifier("vault.setup.create")
                if let failure = appLockController.setupFailure {
                    Text(failure.message)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("vault.setup.failure")
                }
            } footer: {
                Text(String(
                    localized: "vault.setup.footer",
                    defaultValue: "Creating the vault asks for Face ID or Touch ID once. Unlocking later takes the passphrase and one confirmation."
                ))
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent(maxWidth: MacPresentationWidth.onboarding)
        .screenReady("vault.setup.ready")
    }

    private var canCreate: Bool {
        appLockController.lockState == .setupRequired
            && PassphraseRequirements(of: passphrase).isSatisfied
            && passphrase == confirmation
    }

    private func create() {
        guard canCreate else { return }
        let chosen = SensitiveKeyBox(SensitiveBuffer.utf8(passphrase))
        focus = nil
        Task {
            await appLockController.createVault(passphrase: chosen.copied())
            if appLockController.lockState == .unlocked {
                passphrase = ""
                confirmation = ""
            }
        }
    }
}

// MARK: - Integrity failure

private struct VaultIntegrityFailureView: View {
    let report: VaultIntegrityReport
    let resetFlow: LocalDataResetFlow
    @Environment(KeyManagementService.self) private var keyManagement
    @State private var backupFingerprint: String?

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: CypherSpacing.compact) {
                    Label(
                        String(localized: "vault.integrity.title", defaultValue: "Protected Data Is Damaged"),
                        systemImage: "exclamationmark.triangle"
                    )
                    .font(.title3.weight(.semibold))
                    Text(String(
                        localized: "vault.integrity.body",
                        defaultValue: "Part of the data sealed on this device could not be opened. Nothing is repaired in place: back up what is still intact, then reset all local data."
                    ))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            Section {
                domainRow(String(localized: "vault.integrity.domain.settings", defaultValue: "Settings"), report.settings)
                domainRow(String(localized: "vault.integrity.domain.contacts", defaultValue: "Contacts"), report.contacts)
                domainRow(String(localized: "vault.integrity.domain.keys", defaultValue: "Keys"), report.keys)
            }
            if report.keys == .intact {
                Section {
                    if portableKeys.isEmpty {
                        Text(String(localized: "vault.integrity.keys.none", defaultValue: "There are no portable keys to back up."))
                            .foregroundStyle(.secondary)
                    }
                    ForEach(portableKeys) { key in
                        LabeledContent {
                            Button(String(localized: "vault.integrity.keys.backUp", defaultValue: "Back Up")) {
                                backupFingerprint = key.fingerprint
                            }
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(key.userId ?? key.shortKeyId)
                                Text(key.fingerprint)
                                    .font(.footnote.monospaced())
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                    }
                } header: {
                    Text(String(localized: "vault.integrity.keys.header", defaultValue: "Portable keys you can still back up"))
                } footer: {
                    Text(String(
                        localized: "vault.integrity.keys.footer",
                        defaultValue: "Device-bound keys cannot be backed up. They are lost with the reset."
                    ))
                }
            }
            Section {
                Button(role: .destructive) {
                    resetFlow.request()
                } label: {
                    Label(
                        String(localized: "settings.resetAll.action", defaultValue: "Reset All Local Data"),
                        systemImage: "trash"
                    )
                }
                .disabled(!resetFlow.isAvailable)
                .accessibilityIdentifier("vault.integrity.reset")
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .sheet(item: Binding(
            get: { backupFingerprint.map(BackupTarget.init(fingerprint:)) },
            set: { backupFingerprint = $0?.fingerprint }
        )) { target in
            NavigationStack {
                BackupKeyView(fingerprint: target.fingerprint)
            }
            #if os(macOS)
            .frame(minWidth: 520, idealWidth: 560, minHeight: 480, idealHeight: 560)
            #endif
        }
        .screenReady("vault.integrity.ready")
    }

    private struct BackupTarget: Identifiable {
        let fingerprint: String
        var id: String { fingerprint }
    }

    private var portableKeys: [PGPKeyIdentity] {
        keyManagement.keys.filter { $0.privateKeyCustodyKind == .softwareSecretCertificate }
    }

    private func domainRow(_ title: String, _ state: DomainIntegrityState) -> some View {
        LabeledContent(title) {
            switch state {
            case .intact:
                Label(String(localized: "vault.integrity.state.intact", defaultValue: "Intact"), systemImage: "checkmark.circle")
                    .foregroundStyle(.green)
            case .missing:
                Label(String(localized: "vault.integrity.state.missing", defaultValue: "Missing"), systemImage: "questionmark.circle")
                    .foregroundStyle(.orange)
            case .damaged:
                Label(String(localized: "vault.integrity.state.damaged", defaultValue: "Damaged"), systemImage: "xmark.circle")
                    .foregroundStyle(.red)
            }
        }
    }
}

// MARK: - Shared pieces

private struct RestartRequiredView: View {
    var body: some View {
        VStack(spacing: 28) {
            LockHeader(subtitle: String(localized: "vault.restartRequired.title", defaultValue: "Restart Required"))
            Text(String(
                localized: "vault.restartRequired.body",
                defaultValue: "CypherAir X could not lock cleanly. Quit and reopen it to continue."
            ))
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 440)
            #if os(macOS)
            Button {
                LocalDataResetRestartAction.terminateCurrentProcess()
            } label: {
                Label(
                    String(localized: "settings.resetAll.restartRequired.quit", defaultValue: "Quit CypherAir X"),
                    systemImage: "power"
                )
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            #endif
        }
        .padding(24)
        .accessibilityIdentifier("appLock.restartRequired")
    }
}

private struct LockHeader: View {
    let subtitle: String

    var body: some View {
        VStack(spacing: 8) {
            Text(AppProductIdentity.localizedDisplayName)
                .font(.title2.weight(.semibold))
            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }
}

private struct PassphraseRevealToggle: View {
    @Binding var isRevealed: Bool

    var body: some View {
        Button {
            isRevealed.toggle()
        } label: {
            Image(systemName: isRevealed ? "eye.slash" : "eye")
        }
        .buttonStyle(.borderless)
        .accessibilityLabel(
            isRevealed
                ? String(localized: "passphrase.hide", defaultValue: "Hide Passphrase")
                : String(localized: "passphrase.show", defaultValue: "Show Passphrase")
        )
    }
}

struct AppPrivacySurfaceView: View {
    var body: some View {
        ZStack {
            Rectangle()
                .fill(.background)
                .ignoresSafeArea()
            Text(AppProductIdentity.localizedDisplayName)
                .font(.title2.weight(.semibold))
        }
        .accessibilityIdentifier("appLock.privacySurface")
    }
}
