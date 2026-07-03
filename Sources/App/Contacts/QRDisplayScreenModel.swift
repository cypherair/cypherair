import CoreGraphics
import CoreImage
import Foundation

@MainActor
@Observable
final class QRDisplayScreenModel {
    typealias GenerateQRCodeAction = @MainActor (Data) throws -> CIImage?
    typealias RenderQRCodeImageAction = @MainActor (CIImage, CGSize) -> CGImage?
    typealias DetectKeyProfileAction = @MainActor (Data) throws -> PGPKeyProfile

    private let publicKeyData: Data
    private let generateQRCodeAction: GenerateQRCodeAction
    private let renderQRCodeImageAction: RenderQRCodeImageAction
    private let detectKeyProfileAction: DetectKeyProfileAction
    private var hasPrepared = false

    var qrCGImage: CGImage?
    var error: CypherAirError?
    var showError = false
    /// Post-quantum certificates (~30 KB armored) exceed QR capacity by an
    /// order of magnitude; the design (docs/POST_QUANTUM.md §5) requires an
    /// explicit not-available state instead of a generation failure.
    var isUnavailableForKeyType = false

    init(
        publicKeyData: Data,
        qrService: QRService,
        generateQRCodeAction: GenerateQRCodeAction? = nil,
        renderQRCodeImageAction: RenderQRCodeImageAction? = nil,
        detectKeyProfileAction: DetectKeyProfileAction? = nil
    ) {
        self.publicKeyData = publicKeyData
        self.generateQRCodeAction = generateQRCodeAction ?? { publicKeyData in
            try qrService.generateQRCode(for: publicKeyData)
        }
        self.renderQRCodeImageAction = renderQRCodeImageAction ?? Self.renderQRCodeImage
        self.detectKeyProfileAction = detectKeyProfileAction ?? { publicKeyData in
            try qrService.detectKeyProfile(keyData: publicKeyData)
        }
    }

    func prepare() {
        guard !hasPrepared else {
            return
        }

        hasPrepared = true
        generateQR()
    }

    func dismissError() {
        error = nil
        showError = false
    }

    private func generateQR() {
        // The gate must be explicit, not a failed-generation fallback: a
        // detection error falls through to the normal path so classical keys
        // are never blocked by a transient parse problem.
        if let profile = try? detectKeyProfileAction(publicKeyData), profile == .postQuantum {
            isUnavailableForKeyType = true
            return
        }
        do {
            guard let ciImage = try generateQRCodeAction(publicKeyData) else {
                presentError(.corruptData(reason: "QR code generation returned no image"))
                return
            }

            guard let cgImage = renderQRCodeImageAction(ciImage, CGSize(width: 1024, height: 1024)) else {
                presentError(.corruptData(reason: "Failed to render QR code image"))
                return
            }

            qrCGImage = cgImage
        } catch {
            presentError(CypherAirError.from(error) { .corruptData(reason: $0) })
        }
    }

    private func presentError(_ error: CypherAirError) {
        self.error = error
        showError = true
    }

    private static func renderQRCodeImage(_ ciImage: CIImage, size: CGSize) -> CGImage? {
        let context = CIContext()
        let transform = CGAffineTransform(
            scaleX: size.width / ciImage.extent.width,
            y: size.height / ciImage.extent.height
        )
        let scaledImage = ciImage.transformed(by: transform)
        return context.createCGImage(scaledImage, from: scaledImage.extent)
    }
}
