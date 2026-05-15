import Foundation
import CoreImage
import CoreImage.CIFilterBuiltins

/// QR code generation and URL scheme parsing.
///
/// SECURITY-CRITICAL: This service parses untrusted external input
/// (cypherair:// URLs from QR codes). Changes require human review.
/// See SECURITY.md Section 7.
@Observable
final class QRService {

    private let contactImportAdapter: PGPContactImportAdapter

    init(contactImportAdapter: PGPContactImportAdapter) {
        self.contactImportAdapter = contactImportAdapter
    }

    // MARK: - QR Generation

    /// Generate a QR code image for a public key.
    /// Format: cypherair://import/v1/<base64url, no padding>
    ///
    /// - Parameter publicKeyData: Binary public key data.
    /// - Returns: A CIImage of the QR code, or nil if generation fails.
    func generateQRCode(for publicKeyData: Data) throws -> CIImage? {
        let urlString: String
        do {
            urlString = try contactImportAdapter.encodeQrUrl(publicKeyData: publicKeyData)
        } catch {
            throw CypherAirError.from(error) { .invalidKeyData(reason: $0) }
        }

        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(urlString.utf8)
        filter.correctionLevel = "M"

        return filter.outputImage
    }

    // MARK: - URL Parsing

    /// Parse a cypherair:// import URL and extract the public key data.
    ///
    /// SECURITY: This processes untrusted external input. The Rust engine
    /// validates the URL format and parses the OpenPGP key, rejecting
    /// invalid data and secret key material.
    ///
    /// - Parameter url: The cypherair:// URL.
    /// - Returns: Binary public key data.
    func parseImportURL(_ url: URL) throws -> Data {
        let urlString = url.absoluteString

        // Validate scheme
        guard url.scheme == "cypherair" else {
            throw CypherAirError.invalidQRCode
        }

        // Validate host/path format
        guard url.host == "import" || urlString.hasPrefix("cypherair://import/") else {
            throw CypherAirError.invalidQRCode
        }

        // Reject absurdly large payloads before passing to Rust.
        // A valid QR-encoded public key URL is ~600 chars; QR capacity at level M is ~2500.
        // 4096 provides generous headroom while blocking multi-MB URL scheme attacks.
        guard urlString.count <= 4096 else {
            throw CypherAirError.invalidQRCode
        }

        // Check version segment (mandatory — empty path is invalid)
        let pathComponents = url.pathComponents.filter { $0 != "/" }
        guard let firstComponent = pathComponents.first else {
            throw CypherAirError.invalidQRCode
        }
        guard firstComponent == "v1" else {
            throw CypherAirError.unsupportedQRVersion
        }

        // Delegate to the FFI adapter for full parsing and validation.
        // Any engine error here means the QR payload is invalid — always map to .invalidQRCode
        // regardless of the specific generated error variant.
        do {
            return try contactImportAdapter.decodeQrUrl(urlString)
        } catch {
            throw CypherAirError.invalidQRCode
        }
    }

    // MARK: - Key Inspection (for UI confirmation)

    /// Validate contact-import data as a public certificate and return normalized metadata.
    func inspectImportablePublicCertificate(keyData: Data) throws -> ImportablePublicCertificateInspection {
        let validation = try contactImportAdapter.validateImportablePublicCertificate(keyData)
        return ImportablePublicCertificateInspection(
            publicCertData: validation.publicCertData,
            metadata: validation.metadata
        )
    }

    /// Parse key metadata for display in the import confirmation view.
    /// This is a read-only inspection — no keys are stored.
    func inspectKeyMetadata(keyData: Data) throws -> PGPKeyMetadata {
        try inspectImportablePublicCertificate(keyData: keyData).metadata
    }

    /// Detect the encryption profile of a public key.
    func detectKeyProfile(keyData: Data) throws -> PGPKeyProfile {
        try inspectImportablePublicCertificate(keyData: keyData).metadata.profile
    }

    // MARK: - QR Decoding from Image

    /// Decode QR codes from a CIImage (e.g., from PHPicker selection).
    /// Uses CIDetector for QR code detection.
    ///
    /// - Parameter image: The image to scan for QR codes.
    /// - Returns: Array of decoded string values from QR codes found.
    func decodeQRCodes(from image: CIImage) async throws -> [String] {
        // Use CIDetector for QR code detection (synchronous, runs on caller's context)
        let detector = CIDetector(
            ofType: CIDetectorTypeQRCode,
            context: nil,
            options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
        )

        guard let features = detector?.features(in: image) else {
            return []
        }

        return features.compactMap { feature in
            (feature as? CIQRCodeFeature)?.messageString
        }
    }
}
