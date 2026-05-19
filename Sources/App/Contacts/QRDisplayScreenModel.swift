import CoreGraphics
import CoreImage
import Foundation

@MainActor
@Observable
final class QRDisplayScreenModel {
    typealias GenerateQRCodeAction = @MainActor (Data) throws -> CIImage?
    typealias RenderQRCodeImageAction = @MainActor (CIImage, CGSize) -> CGImage?

    private let publicKeyData: Data
    private let generateQRCodeAction: GenerateQRCodeAction
    private let renderQRCodeImageAction: RenderQRCodeImageAction
    private var hasPrepared = false

    var qrCGImage: CGImage?
    var error: CypherAirError?
    var showError = false

    init(
        publicKeyData: Data,
        qrService: QRService,
        generateQRCodeAction: GenerateQRCodeAction? = nil,
        renderQRCodeImageAction: RenderQRCodeImageAction? = nil
    ) {
        self.publicKeyData = publicKeyData
        self.generateQRCodeAction = generateQRCodeAction ?? { publicKeyData in
            try qrService.generateQRCode(for: publicKeyData)
        }
        self.renderQRCodeImageAction = renderQRCodeImageAction ?? Self.renderQRCodeImage
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
