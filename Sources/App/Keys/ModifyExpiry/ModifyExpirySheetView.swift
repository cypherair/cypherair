import SwiftUI

@MainActor
struct ModifyExpiryRequest: Identifiable {
    let id = UUID()
    let fingerprint: String
    let initialDate: Date
    let onComplete: @MainActor () -> Void

    init(
        fingerprint: String,
        initialDate: Date,
        onComplete: @escaping @MainActor () -> Void = {}
    ) {
        self.fingerprint = fingerprint
        self.initialDate = initialDate
        self.onComplete = onComplete
    }
}

struct ModifyExpirySheetView: View {
    let request: ModifyExpiryRequest

    @Environment(KeyManagementService.self) private var keyManagement
    @Environment(\.dismiss) private var dismiss

    @State private var newExpiryDate: Date
    @State private var isModifyingExpiry = false
    @State private var error: CypherAirError?
    @State private var showError = false

    init(request: ModifyExpiryRequest) {
        self.request = request
        _newExpiryDate = State(initialValue: request.initialDate)
    }

    var body: some View {
        Form {
            Section {
                DatePicker(
                    String(localized: "keydetail.expiry.newDate", defaultValue: "New Expiry Date"),
                    selection: $newExpiryDate,
                    in: (Calendar.current.date(byAdding: .day, value: 1, to: Date()) ?? Date())...(Calendar.current.date(byAdding: .year, value: 10, to: Date()) ?? Date()),
                    displayedComponents: .date
                )
            } header: {
                Text(String(localized: "keydetail.expiry.setDate", defaultValue: "Set Expiry Date"))
            }

            Section {
                Button {
                    performModifyExpiry(seconds: nil)
                } label: {
                    Label(
                        String(localized: "keydetail.expiry.removeExpiry", defaultValue: "Remove Expiry (Never Expire)"),
                        systemImage: "infinity"
                    )
                }
            }
        }
        .accessibilityIdentifier("modifyexpiry.root")
        .screenReady("modifyexpiry.ready")
        .navigationTitle(String(localized: "keydetail.expiry.title", defaultValue: "Modify Expiry"))
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "keydetail.expiry.cancel", defaultValue: "Cancel")) {
                    dismiss()
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "keydetail.expiry.save", defaultValue: "Save")) {
                    let seconds = UInt64(max(0, newExpiryDate.timeIntervalSinceNow))
                    performModifyExpiry(seconds: seconds)
                }
                .accessibilityIdentifier("modifyexpiry.save")
                .disabled(isModifyingExpiry)
            }
        }
        .overlay {
            if isModifyingExpiry {
                ProgressView()
            }
        }
        .disabled(isModifyingExpiry)
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
        .authenticationShieldHost()
    }

    private func performModifyExpiry(seconds: UInt64?) {
        isModifyingExpiry = true
        let service = keyManagement
        let fingerprint = request.fingerprint

        Task {
            do {
                _ = try await service.modifyExpiry(
                    fingerprint: fingerprint,
                    newExpirySeconds: seconds
                )
                request.onComplete()
                dismiss()
            } catch {
                self.error = CypherAirError.from(error) { .keychainError($0) }
                showError = true
            }
            isModifyingExpiry = false
        }
    }
}
