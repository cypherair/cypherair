import Foundation

/// The directory every domain file lives in. Created with complete file
/// protection, verified per volume; storage outside the app container is
/// never a fallback.
public struct ProtectedDataDirectory: Sendable {
    public let url: URL

    public init(url: URL) throws(StoreError) {
        self.url = url
        do {
            try FileManager.default.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
        } catch {
            throw .io("directory creation failed")
        }
        let supported: Bool
        do {
            supported = try url.resourceValues(forKeys: [.volumeSupportsFileProtectionKey]).allValues[.volumeSupportsFileProtectionKey] as? Bool ?? false
        } catch {
            throw .fileProtectionVerificationFailed
        }
        guard supported else { throw .fileProtectionUnsupported }
    }

    /// The app's Application Support container, `subdirectory` inside it.
    public static func applicationSupport(subdirectory: String = "ProtectedData") throws(StoreError) -> ProtectedDataDirectory {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw .io("no Application Support directory")
        }
        return try ProtectedDataDirectory(url: base.appending(path: subdirectory, directoryHint: .isDirectory))
    }

    func fileURL(domain: String) -> URL {
        url.appending(path: "\(domain).sealed", directoryHint: .notDirectory)
    }

    func temporaryURL(domain: String) -> URL {
        url.appending(path: "\(domain).\(UUID().uuidString).tmp", directoryHint: .notDirectory)
    }

    /// Removes every file in the directory: the domain files and whatever an
    /// interrupted save left behind.
    public func eraseContents() throws(StoreError) {
        let names: [String]
        do { names = try FileManager.default.contentsOfDirectory(atPath: url.path) } catch { throw .io("directory listing failed") }
        for name in names {
            do { try FileManager.default.removeItem(at: url.appending(path: name)) } catch { throw .io("delete failed") }
        }
    }

    /// Removes leftover temporary files from interrupted saves.
    public func sweepTemporaries() {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: url.path) else { return }
        for name in names where name.hasSuffix(".tmp") {
            try? FileManager.default.removeItem(at: url.appending(path: name))
        }
    }

    /// Applies complete protection to `fileURL` and verifies it stuck. The
    /// simulator's volume reports no protection attribute back, so simulator
    /// builds alone accept a missing readback.
    static func protect(_ fileURL: URL) throws(StoreError) {
        do {
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: fileURL.path)
            let readback = try FileManager.default.attributesOfItem(atPath: fileURL.path)[.protectionKey] as? FileProtectionType
            #if targetEnvironment(simulator)
            let verified = readback == .complete || readback == nil
            #else
            let verified = readback == .complete
            #endif
            guard verified else {
                throw StoreError.fileProtectionVerificationFailed
            }
        } catch let error as StoreError {
            throw error
        } catch {
            throw .fileProtectionVerificationFailed
        }
    }
}
