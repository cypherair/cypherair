import Sealing
import SwiftUI
import Vault

/// Change the unlock passphrase: the current one, the new one chosen the way
/// every passphrase in the app is chosen, and one presence prompt.
struct ChangePassphraseView: View {
    @Environment(AppLockController.self) private var appLockController
    @Environment(\.dismiss) private var dismiss
    @State private var model = ChangePassphraseModel()
    @FocusState private var focus: CypherPassphraseEntry.Field?
    @FocusState private var isCurrentFocused: Bool

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                CypherSecureTextField(
                    String(localized: "changePassphrase.current", defaultValue: "Current Passphrase"),
                    text: $model.current,
                    submitLabel: .next,
                    onSubmit: { focus = .passphrase }
                )
                .focused($isCurrentFocused)
                .accessibilityIdentifier("changePassphrase.current")
            } header: {
                Text(String(localized: "changePassphrase.current.header", defaultValue: "Confirm it is you"))
            }
            Section {
                CypherPassphraseEntry(
                    passphrase: $model.passphrase,
                    confirmation: $model.confirmation,
                    focus: $focus
                )
            } header: {
                Text(String(localized: "changePassphrase.new.header", defaultValue: "New passphrase"))
            } footer: {
                Text(String(
                    localized: "changePassphrase.footer",
                    defaultValue: "Your keys and contacts stay as they are. The new passphrase is needed from the next unlock on, and nobody can recover it for you."
                ))
            }
            if let errorMessage = model.errorMessage {
                Section {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("changePassphrase.error")
                }
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .navigationTitle(String(localized: "settings.changePassphrase", defaultValue: "Change Passphrase"))
        #if canImport(UIKit)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .interactiveDismissDisabled(model.isSaving)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) {
                    dismiss()
                }
                .disabled(model.isSaving)
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "changePassphrase.save", defaultValue: "Change")) {
                    Task {
                        if await model.save(using: appLockController) {
                            dismiss()
                        }
                    }
                }
                .disabled(!model.canSave)
                .accessibilityIdentifier("changePassphrase.save")
            }
        }
        .onAppear {
            isCurrentFocused = true
        }
        .screenReady("changePassphrase.ready")
    }
}

@MainActor
@Observable
final class ChangePassphraseModel {
    var current = ""
    var passphrase = ""
    var confirmation = ""
    private(set) var isSaving = false
    private(set) var errorMessage: String?

    var canSave: Bool {
        !isSaving
            && !current.isEmpty
            && PassphraseRequirements(of: passphrase).isSatisfied
            && passphrase == confirmation
            && passphrase != current
    }

    /// Returns whether the passphrase changed.
    func save(using appLockController: AppLockController) async -> Bool {
        guard canSave else { return false }
        isSaving = true
        errorMessage = nil
        defer { isSaving = false }
        do {
            try await appLockController.changePassphrase(
                current: SensitiveBuffer.utf8(current),
                new: SensitiveBuffer.utf8(passphrase)
            )
            current = ""
            passphrase = ""
            confirmation = ""
            return true
        } catch let error as VaultError {
            errorMessage = Self.message(for: error)
        } catch {
            errorMessage = error.localizedDescription
        }
        return false
    }

    private static func message(for error: VaultError) -> String {
        switch error {
        case .passphraseRejected:
            String(localized: "changePassphrase.error.wrongCurrent", defaultValue: "The current passphrase is not right.")
        case .authenticationCancelled:
            String(localized: "changePassphrase.error.cancelled", defaultValue: "The change was cancelled. Your passphrase is unchanged.")
        case .authenticationFailed, .authenticationUnavailable:
            String(localized: "changePassphrase.error.presence", defaultValue: "Face ID or Touch ID did not confirm it is you. Your passphrase is unchanged.")
        case .enclaveUnavailable, .locked, .noSealedRoot, .sealedRootCorrupt, .storage, .internalFailure:
            String(localized: "changePassphrase.error.failed", defaultValue: "The passphrase could not be changed. Your passphrase is unchanged.")
        }
    }
}

extension SensitiveBuffer {
    /// The UTF-8 bytes of a passphrase typed into a field.
    static func utf8(_ string: String) -> SensitiveBuffer {
        var data = Data(string.utf8)
        return SensitiveBuffer(consuming: &data)
    }
}

extension SensitiveKeyBox {
    /// A fresh buffer with the same bytes, for a consuming call made from a task.
    func copied() -> SensitiveBuffer {
        buffer.withUnsafeBytes { bytes in
            SensitiveBuffer(count: bytes.count) { $0.copyMemory(from: bytes) }
        }
    }
}
