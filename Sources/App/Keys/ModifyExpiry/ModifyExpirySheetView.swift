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

    init(request: ModifyExpiryRequest) {
        self.request = request
    }

    var body: some View {
        ModifyExpiryScreenHostView(
            request: request,
            keyManagement: keyManagement,
            dismissAction: { dismiss() }
        )
    }
}

private struct ModifyExpiryScreenHostView: View {
    @State private var model: ModifyExpiryScreenModel

    init(
        request: ModifyExpiryRequest,
        keyManagement: KeyManagementService,
        dismissAction: @escaping @MainActor () -> Void
    ) {
        _model = State(
            initialValue: ModifyExpiryScreenModel(
                request: request,
                keyManagement: keyManagement,
                dismissAction: dismissAction
            )
        )
    }

    var body: some View {
        @Bindable var model = model

        Form {
            Section {
                DatePicker(
                    String(localized: "keydetail.expiry.newDate", defaultValue: "New Expiry Date"),
                    selection: $model.newExpiryDate,
                    in: expiryDateRange,
                    displayedComponents: .date
                )
            } header: {
                Text(String(localized: "keydetail.expiry.setDate", defaultValue: "Set Expiry Date"))
            }

            Section {
                Button {
                    model.removeExpiry()
                } label: {
                    Label(
                        String(localized: "keydetail.expiry.removeExpiry", defaultValue: "Remove Expiry (Never Expire)"),
                        systemImage: "infinity"
                    )
                }
            }
        }
        #if os(macOS)
        .formStyle(.grouped)
        #endif
        .cypherMacReadableContent()
        .accessibilityIdentifier("modifyexpiry.root")
        .screenReady("modifyexpiry.ready")
        .navigationTitle(String(localized: "keydetail.expiry.title", defaultValue: "Modify Expiry"))
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(String(localized: "keydetail.expiry.cancel", defaultValue: "Cancel")) {
                    model.handleDisappear()
                    dismiss()
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(String(localized: "keydetail.expiry.save", defaultValue: "Save")) {
                    model.saveSelectedExpiryDate()
                }
                .accessibilityIdentifier("modifyexpiry.save")
                .disabled(model.isModifyingExpiry)
            }
        }
        .overlay {
            if model.isModifyingExpiry {
                ProgressView()
            }
        }
        .disabled(model.isModifyingExpiry)
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: Binding(
                get: { model.showError },
                set: { if !$0 { model.dismissError() } }
            ),
            presenting: model.error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {
                model.dismissError()
            }
        } message: { err in
            Text(err.localizedDescription)
        }
        .onDisappear {
            model.handleDisappear()
        }
    }

    private var expiryDateRange: ClosedRange<Date> {
        let minimum = Calendar.current.date(byAdding: .day, value: 1, to: Date()) ?? Date()
        let maximum = Calendar.current.date(byAdding: .year, value: 10, to: Date()) ?? Date()
        return minimum...maximum
    }

    @Environment(\.dismiss) private var dismiss
}
