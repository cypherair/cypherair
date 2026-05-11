import SwiftUI
import UniformTypeIdentifiers

extension View {
    func encryptScreenPresentations(
        model: EncryptScreenModel,
        isRecipientTagPickerPresented: Binding<Bool>
    ) -> some View {
        modifier(
            EncryptScreenPresentations(
                model: model,
                isRecipientTagPickerPresented: isRecipientTagPickerPresented
            )
        )
    }
}

private struct EncryptScreenPresentations: ViewModifier {
    let model: EncryptScreenModel
    @Binding var isRecipientTagPickerPresented: Bool

    func body(content: Content) -> some View {
        @Bindable var model = model
        let operation = model.operation
        let exportController = model.exportController

        content
            .fileImporter(
                isPresented: $model.showFileImporter,
                allowedContentTypes: [.data],
                allowsMultipleSelection: false
            ) { result in
                if case .success(let urls) = result, let url = urls.first {
                    model.handleImportedFile(url)
                }
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
            .alert(
                String(localized: "clipboard.notice.title", defaultValue: "Copied to Clipboard"),
                isPresented: Binding(
                    get: { operation.isShowingClipboardNotice },
                    set: { if !$0 { model.dismissClipboardNotice() } }
                )
            ) {
                Button(String(localized: "clipboard.notice.dismiss", defaultValue: "OK")) {
                    model.dismissClipboardNotice()
                }
                Button(String(localized: "clipboard.notice.dontShow", defaultValue: "Don't Show Again")) {
                    model.dismissClipboardNotice(disableFutureNotices: true)
                }
            } message: {
                Text(String(localized: "clipboard.notice.message", defaultValue: "The encrypted message has been copied. Remember to clear your clipboard after pasting."))
            }
            .fileExporter(
                isPresented: Binding(
                    get: { exportController.isPresented },
                    set: { if !$0 { model.finishExport() } }
                ),
                item: exportController.payload,
                contentTypes: [.data],
                defaultFilename: exportController.defaultFilename
            ) { result in
                model.finishExport()
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
            .sheet(isPresented: $isRecipientTagPickerPresented) {
                RecipientTagPickerSheet(model: model)
            }
    }
}
