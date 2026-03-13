import SwiftUI

/// Key generation form: profile selection, name, email, expiry.
struct KeyGenerationView: View {
    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(AppConfiguration.self) private var config
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var email = ""
    @State private var profile: KeyProfile = .universal
    @State private var expiryMonths = 24
    @State private var isGenerating = false
    @State private var error: CypherAirError?
    @State private var showError = false

    private let expiryOptions = [12, 24, 36, 48, 60]

    var body: some View {
        Form {
            Section {
                Picker(
                    String(localized: "keygen.profile", defaultValue: "Profile"),
                    selection: $profile
                ) {
                    Text(KeyProfile.universal.displayName).tag(KeyProfile.universal)
                    Text(KeyProfile.advanced.displayName).tag(KeyProfile.advanced)
                }
                .pickerStyle(.segmented)

                Text(profile.shortDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text(String(localized: "keygen.profile.header", defaultValue: "Encryption Profile"))
            }

            Section {
                TextField(
                    String(localized: "keygen.name", defaultValue: "Name"),
                    text: $name
                )
                .textContentType(.name)

                TextField(
                    String(localized: "keygen.email", defaultValue: "Email (optional)"),
                    text: $email
                )
                .textContentType(.emailAddress)
                .keyboardType(.emailAddress)
                .autocapitalization(.none)
            } header: {
                Text(String(localized: "keygen.identity.header", defaultValue: "Identity"))
            }

            Section {
                Picker(
                    String(localized: "keygen.expiry", defaultValue: "Expires After"),
                    selection: $expiryMonths
                ) {
                    ForEach(expiryOptions, id: \.self) { months in
                        Text(String(localized: "keygen.expiry.months", defaultValue: "\(months) months"))
                            .tag(months)
                    }
                }
            } header: {
                Text(String(localized: "keygen.expiry.header", defaultValue: "Validity"))
            }

            Section {
                Button {
                    generate()
                } label: {
                    if isGenerating {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                    } else {
                        Text(String(localized: "keygen.generate", defaultValue: "Generate Key"))
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || isGenerating)
            }
        }
        .navigationTitle(String(localized: "keygen.title", defaultValue: "Generate Key"))
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
    }

    private func generate() {
        isGenerating = true
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedEmail = email.trimmingCharacters(in: .whitespaces)
        let expirySeconds = UInt64(expiryMonths) * 30 * 24 * 3600

        Task {
            do {
                _ = try keyManagement.generateKey(
                    name: trimmedName,
                    email: trimmedEmail.isEmpty ? nil : trimmedEmail,
                    expirySeconds: expirySeconds,
                    profile: profile,
                    authMode: config.authMode
                )
                dismiss()
            } catch let err as CypherAirError {
                error = err
                showError = true
            } catch {
                self.error = .keyGenerationFailed(reason: error.localizedDescription)
                showError = true
            }
            isGenerating = false
        }
    }
}
