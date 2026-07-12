import XCTest

/// Base class for the unit-test classes that touch the machine-global
/// tutorial-sandbox `UserDefaults` suite (`com.cypherair.tutorial.sandbox`) or
/// its real `~/Library/Preferences` plist — whether directly, by building a
/// `TutorialSandboxContainer` (which calls `removePersistentDomain` on that
/// fixed domain in `init`/`cleanup`/`deinit`), or by driving a real local-data
/// reset or startup temporary-file cleanup (both funnel through
/// `AppTemporaryArtifactStore.cleanupTutorialSandboxDefaultsSuite()`, which
/// always mutates that global domain).
///
/// It holds `TutorialSandboxDefaultsGlobalTestLock` for the duration of every
/// test, so these classes never interleave with their counterparts in a
/// concurrent `xcodebuild test` invocation on the same Mac. The lock is a
/// cross-process `flock`; see `TutorialSandboxDefaultsGlobalTestLock` for why an
/// in-process lock would not help. Within a single (serial) invocation the lock
/// is uncontended, so it adds no cost there; every other test class is untouched
/// and stays as parallel/serial as before.
///
/// The hooks live in the synchronous `setUp()`/`tearDown()`, which XCTest's
/// fixture cascade always reaches — including from subclasses that override only
/// `setUp() async throws` / `tearDown()`, provided they call `super`. The base
/// stays non-isolated so the `@MainActor` subclasses inherit the hooks without
/// an actor-isolation override mismatch.
class TutorialSandboxDefaultsSerializedTestCase: XCTestCase {
    private var globalTutorialDefaultsLock: TutorialSandboxDefaultsGlobalTestLock.Handle?

    override func setUp() {
        super.setUp()
        globalTutorialDefaultsLock = TutorialSandboxDefaultsGlobalTestLock.acquire()
    }

    override func tearDown() {
        if let globalTutorialDefaultsLock {
            TutorialSandboxDefaultsGlobalTestLock.release(globalTutorialDefaultsLock)
            self.globalTutorialDefaultsLock = nil
        }
        super.tearDown()
    }
}
