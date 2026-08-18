import Foundation

/// Storage seam for the only preference strings the app persists —
/// `AppConfiguration`'s two App Access Protection keys.
///
/// Production backs it with `UserDefaults.standard`; the sandboxed worlds
/// (guided tutorial, DEBUG UI-test container) back it with process memory, so
/// no sandbox run can touch a real preferences domain. Local data reset erases
/// the keys through this seam and verifies the erasure through it.
protocol AppPreferenceStorage: AnyObject {
    func string(forKey key: String) -> String?
    func setString(_ value: String, forKey key: String)
    func removeValue(forKey key: String)
}

final class UserDefaultsAppPreferenceStorage: AppPreferenceStorage {
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func string(forKey key: String) -> String? {
        defaults.string(forKey: key)
    }

    func setString(_ value: String, forKey key: String) {
        defaults.set(value, forKey: key)
    }

    func removeValue(forKey key: String) {
        defaults.removeObject(forKey: key)
    }
}

final class InMemoryAppPreferenceStorage: AppPreferenceStorage {
    private var values: [String: String] = [:]

    func string(forKey key: String) -> String? {
        values[key]
    }

    func setString(_ value: String, forKey key: String) {
        values[key] = value
    }

    func removeValue(forKey key: String) {
        values[key] = nil
    }
}
