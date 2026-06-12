import SwiftUI

/// Drill-in explainer for a device-bound Secure Enclave custody key, reached
/// from the Key Type row in key detail: where the private key lives, why it
/// cannot be exported, and what device loss means.
struct DeviceBoundKeyExplainerView: View {
    let fingerprint: String

    @Environment(KeyManagementService.self) private var keyManagement

    private var key: PGPKeyIdentity? {
        keyManagement.keys.first { $0.fingerprint == fingerprint }
    }

    var body: some View {
        List {
            if let key {
                Section {
                    LabeledContent(
                        String(localized: "keydetail.keyType", defaultValue: "Key Type"),
                        value: key.openPGPConfigurationIdentity.familyDisplayName
                    )
                }
            }

            Section {
                Label {
                    Text(String(
                        localized: "keydetail.deviceBound.explainer.custody",
                        defaultValue: "The private key lives in this device's Secure Enclave. Signing and decryption happen inside the Secure Enclave; the app never sees the private key."
                    ))
                } icon: {
                    Image(systemName: "cpu")
                        .foregroundStyle(.blue)
                }

                Label {
                    Text(String(
                        localized: "keydetail.deviceBound.explainer.export",
                        defaultValue: "The private key cannot be exported or backed up. The public key and revocation certificate can be exported."
                    ))
                } icon: {
                    Image(systemName: "square.and.arrow.up.badge.clock")
                        .foregroundStyle(.blue)
                }

                Label {
                    Text(String(
                        localized: "keydetail.deviceBound.explainer.recovery",
                        defaultValue: "If this device is lost or erased, or its biometric access is removed, this key's signing and decryption capability is permanently lost."
                    ))
                } icon: {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }
        }
        .cypherMacReadableContent()
        .accessibilityIdentifier("keydetail.deviceBound.explainer.root")
        .navigationTitle(String(
            localized: "keydetail.deviceBound.explainer.title",
            defaultValue: "Device-Bound Key"
        ))
    }
}
