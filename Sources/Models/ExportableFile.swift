import CoreTransferable
import UniformTypeIdentifiers

/// A lightweight wrapper for exporting files via `fileExporter` without loading
/// file contents into memory. Uses `FileRepresentation` to pass the file URL
/// directly, enabling zero-copy export for large files.
///
/// The exported content type is `.data` (generic binary). The actual file type
/// is controlled by the `contentTypes` parameter at the `.fileExporter` call site.
struct ExportableFile: Transferable {
    let url: URL

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .data) { file in
            SentTransferredFile(file.url)
        }
        .suggestedFileName { file in
            file.url.lastPathComponent
        }
    }
}
