import Foundation
import LocalAuthentication

enum AuthErrorTraceMetadata {
    static func errorMetadata(_ error: Error, extra: [String: String] = [:]) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        let nsError = error as NSError
        metadata["errorDomain"] = nsError.domain
        metadata["errorCode"] = String(nsError.code)
        metadata["errorDescription"] = sanitizedErrorDescription(nsError.localizedDescription)
        if let underlyingError = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
            metadata["underlyingErrorDomain"] = underlyingError.domain
            metadata["underlyingErrorCode"] = String(underlyingError.code)
        }
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
    }

    private static func sanitizedErrorDescription(_ description: String) -> String {
        description.replacingOccurrences(of: NSHomeDirectory(), with: "~")
    }
}
