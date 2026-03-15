import Foundation

/// Type-safe navigation routes for NavigationStack.
enum AppRoute: Hashable {
    // Keys
    case keyGeneration
    case keyDetail(fingerprint: String)
    case backupKey(fingerprint: String)
    case importKey

    // Contacts
    case contactDetail(fingerprint: String)
    case addContact
    case qrDisplay(publicKeyData: Data, displayName: String)
    case qrPhotoImport

    // Encrypt / Decrypt
    case encrypt
    case decrypt

    // Sign / Verify
    case sign
    case verify

    // Settings
    case selfTest
    case about
    case appIcon
}
