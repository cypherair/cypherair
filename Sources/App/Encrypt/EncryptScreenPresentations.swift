import SwiftUI
import UniformTypeIdentifiers

extension View {
    func encryptScreenPresentations(model: EncryptScreenModel) -> some View {
        modifier(EncryptScreenPresentations(model: model))
    }
}

private struct EncryptScreenPresentations: ViewModifier {
    let model: EncryptScreenModel

    func body(content: Content) -> some View {
        @Bindable var model = model
        let operation = model.operation
        let exportController = model.exportController
        let fileImportRequestToken = model.fileImportRequestToken

        content
            .fileImporter(
                isPresented: $model.showFileImporter,
                allowedContentTypes: [.data],
                allowsMultipleSelection: false
            ) { result in
                model.handleFileImporterResult(result, token: fileImportRequestToken)
            }
            .alert(
                String(localized: "error.title", defaultValue: "Error"),
                isPresented: Binding(
                    get: { operation.isShowingError },
                    set: { if !$0 { model.dismissError() } }
                ),
                presenting: operation.error
            ) { _ in
                Button(String(localized: "error.ok", defaultValue: "OK")) {}
            } message: { err in
                Text(err.localizedDescription)
            }
            .clipboardSafetyNotice(
                isPresented: Binding(
                    get: { operation.isShowingClipboardNotice },
                    set: { if !$0 { model.dismissClipboardNotice() } }
                )
            ) { disableFutureNotices in
                model.dismissClipboardNotice(disableFutureNotices: disableFutureNotices)
            }
            .fileExport(exportController) { result in
                if case .failure(let exportError) = result {
                    model.handleExportError(exportError)
                }
            }
            .confirmationDialog(
                String(localized: "encrypt.unverified.confirm.title", defaultValue: "Use Unverified Recipients?"),
                isPresented: Binding(
                    get: { model.showUnverifiedRecipientsWarning },
                    set: { if !$0 { model.dismissUnverifiedRecipientsWarning() } }
                ),
                titleVisibility: .visible
            ) {
                Button(String(localized: "encrypt.unverified.confirm.action", defaultValue: "Encrypt Anyway")) {
                    model.confirmEncryptWithUnverifiedRecipients()
                }
                Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { }
            } message: {
                Text(model.unverifiedRecipientsWarningMessage)
            }
    }
}
