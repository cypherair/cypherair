import Darwin
import Foundation

/// The one policy for destroying a temporary file the app owns: the name goes
/// away, and the bytes are overwritten with zeros.
///
/// **The two halves have different deadlines,** which is why this runs in two
/// phases. Unlinking has to be immediate: a workflow that discards its decrypted
/// output must not be able to observe the file afterwards, and that discard
/// happens on the main actor — sometimes inside a scene-phase teardown, where a
/// pass over an unbounded file would stall the transition. The zero pass has no
/// such deadline, so it runs off the caller's executor, on descriptors opened
/// *before* the unlink. The kernel keeps an unlinked inode alive while a
/// descriptor is open, so the bytes are still there to overwrite once the name is
/// gone — and if the process dies first, the kernel reclaims the blocks, leaving
/// nothing behind for the next launch to sweep.
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
/// **It does not ask whether the artifact holds plaintext,** though zeroing
/// ciphertext — a streaming `.gpg` output, the tutorial's SQLCipher store — buys
/// no confidentiality. Asking would mean a hand-kept list of which temporary
/// roots are plaintext-bearing, and the day something plaintext lands under a
/// root marked otherwise, the weaker treatment applies silently, with a green
/// build. A file-hygiene primitive has no way to classify its own input; the
/// cost of not classifying is background I/O nothing waits on.
///
/// The engine holds the same policy for the temporary files it owns
/// (`secure_delete_file`, `pgp-mobile/src/streaming.rs`); this is its Swift
/// counterpart, and between them there is one erase policy rather than two.
enum TemporaryArtifactEraser {
    private static let overwriteChunkSize = 64 * 1024

    /// Erase `url` — a single file, or a directory and everything under it.
    ///
    /// Returns once the path is gone; the zero pass carries on in the
    /// background. Only the removal can fail the call.
    static func erase(at url: URL, fileManager: FileManager = .default) throws {
        let pending = try unlinkRetainingContents(at: url, fileManager: fileManager)
        pending.overwriteInBackground()
    }

    /// Phase one: open every regular file under `url` for writing, then remove
    /// the path.
    ///
    /// Opening is best-effort — a protected file on a locked device, a read-only
    /// volume — and whatever could not be opened is still unlinked, because
    /// removing it is worth more than refusing to.
    static func unlinkRetainingContents(
        at url: URL,
        fileManager: FileManager = .default
    ) throws -> PendingOverwrite {
        let files = openRegularFilesForOverwrite(at: url, fileManager: fileManager)
        do {
            try fileManager.removeItem(at: url)
        } catch {
            for file in files {
                close(file.descriptor)
            }
            throw error
        }
        return PendingOverwrite(files: files)
    }

    /// Phase two: the zero pass over inodes that no longer have a name.
    struct PendingOverwrite: Sendable {
        fileprivate let files: [DoomedFile]

        func overwriteInBackground() {
            guard !files.isEmpty else { return }
            Task.detached(priority: .utility) {
                overwriteNow()
            }
        }

        func overwriteNow() {
            for file in files {
                TemporaryArtifactEraser.overwrite(file)
                close(file.descriptor)
            }
        }
    }

    fileprivate struct DoomedFile: Sendable {
        let descriptor: Int32
        let size: Int
    }

    private static func overwrite(_ file: DoomedFile) {
        let zeros = [UInt8](repeating: 0, count: min(file.size, overwriteChunkSize))
        var remaining = file.size
        zeros.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            while remaining > 0 {
                let written = write(file.descriptor, base, min(remaining, buffer.count))
                if written > 0 {
                    remaining -= written
                } else if written < 0 && errno == EINTR {
                    continue
                } else {
                    return
                }
            }
        }
        // Without this the kernel is free to drop the dirty pages once the last
        // descriptor closes, and the overwrite would never reach storage at all
        // — on the filesystems where it can accomplish anything.
        fsync(file.descriptor)
    }

    private static func openRegularFilesForOverwrite(
        at url: URL,
        fileManager: FileManager
    ) -> [DoomedFile] {
        switch itemKind(at: url) {
        case .regularFile:
            return openForOverwrite(at: url).map { [$0] } ?? []

        case .directory:
            var files: [DoomedFile] = []
            let children = fileManager.enumerator(
                at: url,
                includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey],
                options: []
            )
            while let child = children?.nextObject() as? URL {
                guard itemKind(at: child) == .regularFile,
                      let file = openForOverwrite(at: child) else {
                    continue
                }
                files.append(file)
            }
            return files

        case nil:
            return []
        }
    }

    private static func openForOverwrite(at url: URL) -> DoomedFile? {
        guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize,
              size > 0 else {
            return nil
        }
        let descriptor = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_WRONLY)
        }
        guard descriptor >= 0 else {
            return nil
        }
        return DoomedFile(descriptor: descriptor, size: size)
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
        // Never open through a link, and never descend one: the artifact trees
        // the app builds contain none, and following one would reach a file
        // outside the artifact. `FileManager`'s enumerator does not descend into
        // symlinked directories either, so a link to a directory yields nothing.
        if values.isSymbolicLink == true {
            return nil
        }
        if values.isDirectory == true {
            return .directory
        }
        return values.isRegularFile == true ? .regularFile : nil
    }
}
