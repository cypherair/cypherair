import SwiftUI
import UniformTypeIdentifiers

extension View {
    /// The app's one save-a-file presentation.
    ///
    /// Every exported artifact — public key, revocation certificate, ciphertext,
    /// signed message, detached signature, key backup, self-test report — is
    /// offered through here, so the name the user is shown is always the one the
    /// controller was given. Dismissal and completion both close the export out,
    /// which releases the staging file; callers handle only what is theirs, the
    /// meaning of the result.
    func fileExport(
        _ controller: FileExportController,
        onCompletion: @escaping @MainActor (Result<URL, Error>) -> Void
    ) -> some View {
        fileExporter(
            isPresented: Binding(
                get: { controller.isPresented },
                set: { if !$0 { controller.finish() } }
            ),
            item: controller.payload,
            contentTypes: [.data],
            defaultFilename: controller.payload?.filename.value
        ) { result in
            controller.finish()
            onCompletion(result)
        }
    }
}
