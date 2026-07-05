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

    /// Family-aware custody statement: split-custody families disclose that the
    /// classical half is device-sealed rather than enclave-resident.
    private var custodyText: String {
        switch key?.openPGPConfigurationIdentity {
        case .deviceBoundPostQuantumV6:
            String(
                localized: "keydetail.deviceBound.explainer.custodySplit",
                defaultValue: "This key uses split custody. The post-quantum half lives in this device's Secure Enclave; the classical half is sealed to this device and used briefly in app memory during operations. Every signature and decryption requires the Secure Enclave — neither half works alone."
            )
        default:
            String(
                localized: "keydetail.deviceBound.explainer.custody",
                defaultValue: "The private key lives in this device's Secure Enclave. Signing and decryption happen inside the Secure Enclave; the app never sees the private key."
            )
        }
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
                    Text(custodyText)
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

                Label {
                    Text(PGPKeyConfiguration.Identity.deviceBoundBiometricRequirement)
                } icon: {
                    Image(systemName: "faceid")
                        .foregroundStyle(.blue)
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
