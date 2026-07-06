import CoreGraphics
import CoreImage
import Foundation

@MainActor
@Observable
final class QRDisplayScreenModel {
    typealias GenerateQRCodeAction = @MainActor (Data) throws -> CIImage?
    typealias RenderQRCodeImageAction = @MainActor (CIImage, CGSize) -> CGImage?

    /// Why no QR code can be shown for this key. Every failure resolves to a
    /// full-page not-available state — the screen never surfaces alerts or
    /// leaves a spinner running behind one.
    enum Unavailability: Equatable {
        /// The encoder rejected the payload as beyond QR capacity. Post-quantum
        /// certificates (~30 KB armored) always land here, as do any oversized
        /// classical keys — `encode_qr_url` returns `KeyTooLargeForQr` for both.
        case keyTooLarge
        /// Any other generation or rendering failure.
        case generationFailed
    }

    private let publicKeyData: Data
    private let generateQRCodeAction: GenerateQRCodeAction
    private let renderQRCodeImageAction: RenderQRCodeImageAction
    private var hasPrepared = false

    var qrCGImage: CGImage?
    var unavailability: Unavailability?

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

    private func generateQR() {
        do {
            guard let ciImage = try generateQRCodeAction(publicKeyData) else {
                unavailability = .generationFailed
                return
            }

            guard let cgImage = renderQRCodeImageAction(ciImage, CGSize(width: 1024, height: 1024)) else {
                unavailability = .generationFailed
                return
            }

            qrCGImage = cgImage
        } catch {
            let normalized = CypherAirError.from(error) { .corruptData(reason: $0) }
            if case .keyTooLargeForQr = normalized {
                unavailability = .keyTooLarge
            } else {
                unavailability = .generationFailed
            }
        }
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
