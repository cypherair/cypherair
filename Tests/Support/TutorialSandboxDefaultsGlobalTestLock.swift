import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Cross-process advisory lock that serializes the unit-test classes which
/// mutate the machine-global tutorial-sandbox `UserDefaults` suite
/// (`AppTemporaryArtifactStore.tutorialSandboxDefaultsSuiteName`, i.e.
/// `com.cypherair.tutorial.sandbox`) and its real `~/Library/Preferences`
/// backing plist.
///
/// ## Why a cross-process lock and not a shared static in-process lock
///
/// `CypherAir-UnitTests.xctestplan` declares no `parallelizable` option and the
/// scheme's `TestAction` requests no parallelization, so a single
/// `xcodebuild test -testPlan CypherAir-UnitTests` invocation runs every test
/// class serially inside one runner process. There is therefore no *in-process*
/// parallelism to guard against, and a shared static lock would be a no-op that
/// fixes nothing.
///
/// That suite is a per-user `CFPreferences` domain shared by every process
/// running as the user (redirected into the app's sandbox container), and its
/// plist lives in the real `~/Library/Preferences`. The flake appears when two
/// `xcodebuild test` invocations of this plan run on the same Mac at once: their
/// two runner processes mutate and assert on the same global domain — and delete
/// the same real plist — interleaving destructively. Only a cross-process mutex
/// serializes separate OS processes, so this uses an `flock(2)` advisory lock on
/// a fixed per-user path. The lock file lives under the same
/// sandbox-redirected `Caches` directory that backs the protected `Preferences`
/// domain, so the lock's scope matches the resource it guards exactly.
enum TutorialSandboxDefaultsGlobalTestLock {
    /// An acquired lock. Hold it for the critical section; pass it back to
    /// `release(_:)` to unlock and close the underlying descriptor.
    struct Handle {
        fileprivate let descriptor: Int32
    }

    private static let lockFileURL: URL = {
        let fileManager = FileManager.default
        let directory = (try? fileManager.url(
            for: .cachesDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )) ?? fileManager.temporaryDirectory
        return directory.appendingPathComponent(
            "com.cypherair.tests.tutorial-sandbox-defaults.lock",
            isDirectory: false
        )
    }()

    /// Blocks until this process exclusively holds the machine-global
    /// tutorial-sandbox lock.
    static func acquire() -> Handle {
        let path = lockFileURL.path
        let descriptor = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0o644)
        precondition(
            descriptor >= 0,
            "Could not open the tutorial-sandbox test lock at \(path): errno \(errno)"
        )
        while flock(descriptor, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            let failure = errno
            close(descriptor)
            preconditionFailure(
                "flock(LOCK_EX) failed on the tutorial-sandbox test lock: errno \(failure)"
            )
        }
        return Handle(descriptor: descriptor)
    }

    /// Releases a handle returned by `acquire()`.
    static func release(_ handle: Handle) {
        flock(handle.descriptor, LOCK_UN)
        close(handle.descriptor)
    }
}
