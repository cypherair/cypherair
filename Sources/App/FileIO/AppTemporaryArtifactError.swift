import Foundation

enum AppTemporaryArtifactError: LocalizedError, Equatable {
    case fileProtectionUnsupported(URL)
    case fileProtectionVerificationFailed(URL)

    var errorDescription: String? {
        switch self {
        case .fileProtectionUnsupported:
            "Required temporary-file protection is unavailable on this volume."
        case .fileProtectionVerificationFailed:
            "Temporary-file protection could not be verified."
        }
    }
}
