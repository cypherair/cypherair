import Foundation

/// Turns a file the system asked the app to open into a document bound for one
/// screen — or into the error that says why it is not.
///
/// Reading and identifying happen here so the coordinator above has one outcome
/// to act on. Two properties hold across every path: the bytes are read once,
/// under whatever sandbox access the file needs; and a copy the system left in
/// the inbox is either moved under the app's own management or gone by the time
/// this returns, including when the file is refused.
struct OpenedDocumentReader {
    /// How much of an opened file the app will hold in memory.
    ///
    /// Every destination but Decrypt receives content rather than a file, and
    /// each of them puts it in front of the reader: a certificate, a key, a
    /// signed message to check. None of those is megabytes, and a text view is
    /// not where a file that size belongs. Encrypted messages are the exception
    /// and take the file route, which has no ceiling.
    static let maxInMemoryByteCount = 8 * 1024 * 1024

    let temporaryArtifactStore: AppTemporaryArtifactStore

    func read(_ url: URL) throws -> OpenedDocumentOutcome {
        var retained = false
        defer {
            if !retained {
                temporaryArtifactStore.eraseOpenedDocumentCopy(at: url)
            }
        }

        let fileName = url.lastPathComponent
        guard let declaredType = OpenedDocumentType(fileName: fileName) else {
            throw CypherAirError.openedFileUnsupportedContent
        }

        let (content, isComplete) = try readContent(of: url)
        let kind: PGPDataKind
        do {
            kind = try PGPDataClassificationAdapter.kind(of: content)
        } catch {
            // Every way the engine can fail to identify the bytes says the same
            // thing to the reader — this is not a file the app opens — so the
            // engine's reason is not carried up into a message about it.
            throw CypherAirError.openedFileUnsupportedContent
        }

        switch try OpenedDocumentDispatch.purpose(of: kind, declaredAs: declaredType) {
        case .contactImport:
            return .contactImport(certificate: try wholeContent(content, isComplete: isComplete))
        case .screen(.decryption):
            retained = true
            return .handoff(
                OpenedDocument(
                    screen: .decryption,
                    fileName: fileName,
                    delivery: .file(try retainedFileURL(for: url))
                )
            )
        case .screen(let screen):
            return .handoff(
                OpenedDocument(
                    screen: screen,
                    fileName: fileName,
                    delivery: .content(try wholeContent(content, isComplete: isComplete))
                )
            )
        }
    }

    /// Let go of a document without reading it, for a refusal decided before its
    /// content mattered.
    ///
    /// The copy the system left in the inbox is the app's to erase whatever the
    /// reason: a refusal that leaves one behind is the unmanaged copy this
    /// handler exists to prevent, and the reader can simply open the file again.
    func discard(_ url: URL) {
        temporaryArtifactStore.eraseOpenedDocumentCopy(at: url)
    }

    private func wholeContent(_ content: Data, isComplete: Bool) throws -> Data {
        guard isComplete else {
            throw CypherAirError.openedFileTooLarge(
                maximumMB: Self.maxInMemoryByteCount / (1024 * 1024)
            )
        }
        return content
    }

    /// Reads up to the in-memory ceiling, and says whether that was the whole
    /// file.
    ///
    /// A file past the ceiling is still identified: the packet that decides sits
    /// at the front, and knowing an oversized file is an encrypted message is
    /// what lets it take the file route instead of being refused for its size.
    private func readContent(of url: URL) throws -> (Data, isComplete: Bool) {
        try SecurityScopedFileAccess.withAccess(to: url) {
            let handle: FileHandle
            do {
                handle = try FileHandle(forReadingFrom: url)
            } catch {
                throw CypherAirError.fileIoError(reason: error.localizedDescription)
            }
            defer { try? handle.close() }

            do {
                let content = try handle.read(upToCount: Self.maxInMemoryByteCount) ?? Data()
                let isComplete = try handle.read(upToCount: 1)?.isEmpty ?? true
                return (content, isComplete)
            } catch {
                throw CypherAirError.fileIoError(reason: error.localizedDescription)
            }
        }
    }

    /// A URL the Decrypt screen may keep reading from.
    ///
    /// A document opened in place stays where it is — it is the reader's own
    /// file, and the app has no business moving or deleting it. A copy the
    /// system left in the inbox moves under the artifact store, which is what
    /// empties the inbox and what puts the file where the sweep and a local data
    /// reset can both reach it.
    private func retainedFileURL(for url: URL) throws -> URL {
        guard temporaryArtifactStore.ownsOpenedDocumentCopy(at: url) else {
            return url
        }

        do {
            return try temporaryArtifactStore.adoptOpenedDocument(at: url).fileURL
        } catch {
            throw CypherAirError.fileIoError(reason: error.localizedDescription)
        }
    }
}
