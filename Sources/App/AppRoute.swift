import Foundation

enum ContactCertificationRouteIntent: String, Hashable {
    case details
    case certify
}

/// Type-safe navigation routes for NavigationStack.
enum AppRoute: Hashable {
    // Keys
    case keyGeneration
    case postGenerationPrompt(identity: PGPKeyIdentity)
    case keyDetail(fingerprint: String)
    case backupKey(fingerprint: String)
    case selectiveRevocation(fingerprint: String)
    case importKey

    // Contacts
    case contactDetail(contactId: String)
    case contactCertification(contactId: String, keyId: String?, intent: ContactCertificationRouteIntent)
    case contactCertificateSignatures(fingerprint: String)
    case recipientLists
    case recipientListDetail(recipientListId: String)
    case addContact
    case qrDisplay(publicKeyData: Data, displayName: String)

    // Encrypt / Decrypt
    case encrypt
    case decrypt

    // Sign / Verify
    case sign
    case verify

    // Settings
    case selfTest
    case about
    case sourceCompliance
    case license
    case appIcon
    case themePicker
}
