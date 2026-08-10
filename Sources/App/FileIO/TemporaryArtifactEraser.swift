import Foundation

/// The one policy for destroying a temporary file the app owns: overwrite its
/// bytes with zeros, then unlink it.
///
/// **What the overwrite is worth.** Every platform CypherAir ships on keeps the
/// app container on APFS, and APFS is copy-on-write: writing over a file's bytes
/// allocates fresh blocks and leaves the previous ones intact until they are
/// reused or trimmed. Overwriting therefore does *not* reliably destroy what was
/// there, and nothing here should be read as claiming it does. It is best-effort
/// hygiene at the same level as zeroing a buffer before it is freed. The
/// guarantees sit elsewhere: the `.completeFileProtection` class every temporary
/// artifact is created under, whose per-file key dies with the file, and above
/// that, not writing plaintext to disk in the first place.
///
/// The engine holds the same policy for the temporary files it owns
/// (`secure_delete_file`, `pgp-mobile/src/streaming.rs`); this is its Swift
/// counterpart, and between them there is one erase policy rather than two.
enum TemporaryArtifactEraser {
    private static let overwriteChunkSize = 64 * 1024

    /// Erase `url` — a single file, or a directory and everything under it —
    /// and remove it.
    ///
    /// Overwriting is best-effort at every step: a file that cannot be opened
    /// for writing (a protected file while the device is locked, a read-only
    /// volume) still gets unlinked, because removing it is worth more than
    /// refusing to. Only the removal itself can fail the call.
    static func erase(at url: URL, fileManager: FileManager = .default) throws {
        overwriteContents(at: url, fileManager: fileManager)
        try fileManager.removeItem(at: url)
    }

    private static func overwriteContents(at url: URL, fileManager: FileManager) {
        switch itemKind(at: url) {
        case .regularFile:
            overwriteFile(at: url)

        case .directory:
            let children = fileManager.enumerator(
                at: url,
                includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey],
                options: []
            )
            while let child = children?.nextObject() as? URL {
                if itemKind(at: child) == .regularFile {
                    overwriteFile(at: child)
                }
            }

        case nil:
            break
        }
    }

    private static func overwriteFile(at url: URL) {
        guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize,
              size > 0,
              let handle = try? FileHandle(forWritingTo: url) else {
            return
        }
        defer { try? handle.close() }

        let zeros = Data(count: min(size, overwriteChunkSize))
        var remaining = size
        while remaining > 0 {
            let count = min(remaining, zeros.count)
            do {
                try handle.write(contentsOf: count == zeros.count ? zeros : zeros.prefix(count))
            } catch {
                break
            }
            remaining -= count
        }
        // Unlinking a file whose zeros are still dirty pages lets the kernel drop
        // them unwritten, which would make the overwrite a no-op even on the
        // filesystems where it can accomplish something.
        try? handle.synchronize()
    }

    private enum ItemKind {
        case regularFile
        case directory
    }

    private static func itemKind(at url: URL) -> ItemKind? {
        guard let values = try? url.resourceValues(
            forKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey]
        ) else {
            return nil
        }
        // Never write through a link. The artifact trees the app builds contain
        // none, and following one would overwrite a file outside the artifact.
        if values.isSymbolicLink == true {
            return nil
        }
        if values.isDirectory == true {
            return .directory
        }
        return values.isRegularFile == true ? .regularFile : nil
    }
}
