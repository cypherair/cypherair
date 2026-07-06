import CoreGraphics
import CoreImage
import XCTest
@testable import CypherAir

private struct QRDisplayScreenModelTestError: LocalizedError {
    let message: String

    var errorDescription: String? {
        message
    }
}

final class QRDisplayScreenModelTests: XCTestCase {
    @MainActor
    func test_prepare_successRendersQRCodeImage() throws {
        let expectedImage = try Self.makeTestCGImage()
        let model = makeModel(
            generateQRCodeAction: { publicKeyData in
                XCTAssertEqual(publicKeyData, Data("public-key".utf8))
                return Self.makeTestCIImage()
            },
            renderQRCodeImageAction: { ciImage, size in
                XCTAssertEqual(ciImage.extent.width, 1)
                XCTAssertEqual(size, CGSize(width: 1024, height: 1024))
                return expectedImage
            }
        )

        model.prepare()
        model.prepare()

        XCTAssertEqual(model.qrCGImage?.width, expectedImage.width)
        XCTAssertEqual(model.qrCGImage?.height, expectedImage.height)
        XCTAssertNil(model.unavailability)
    }

    @MainActor
    func test_prepare_whenQRCodeGenerationReturnsNil_showsGenerationFailedState() {
        let model = makeModel(generateQRCodeAction: { _ in nil })

        model.prepare()

        XCTAssertEqual(model.unavailability, .generationFailed)
        XCTAssertNil(model.qrCGImage)
    }

    @MainActor
    func test_prepare_whenRenderReturnsNil_showsGenerationFailedState() {
        let model = makeModel(renderQRCodeImageAction: { _, _ in nil })

        model.prepare()

        XCTAssertEqual(model.unavailability, .generationFailed)
        XCTAssertNil(model.qrCGImage)
    }

    @MainActor
    func test_prepare_whenGenerationThrows_showsGenerationFailedState() {
        let model = makeModel(
            generateQRCodeAction: { _ in
                throw QRDisplayScreenModelTestError(message: "generation failed")
            }
        )

        model.prepare()

        XCTAssertEqual(model.unavailability, .generationFailed)
        XCTAssertNil(model.qrCGImage)
    }

    @MainActor
    func test_prepare_whenKeyExceedsQRCapacity_showsKeyTooLargeState() {
        // An oversized key gets a full-page not-available state, never an alert
        // over a spinner. Post-quantum certs (~30 KB) always land here too.
        let model = makeModel(
            generateQRCodeAction: { _ in
                throw CypherAirError.keyTooLargeForQr
            }
        )

        model.prepare()

        XCTAssertEqual(model.unavailability, .keyTooLarge)
        XCTAssertNil(model.qrCGImage)
    }

    @MainActor
    func test_prepare_normalKey_rendersNormally() throws {
        let expectedImage = try Self.makeTestCGImage()
        let model = makeModel(
            renderQRCodeImageAction: { _, _ in expectedImage }
        )

        model.prepare()

        XCTAssertNil(model.unavailability)
        XCTAssertNotNil(model.qrCGImage)
    }

    @MainActor
    private func makeModel(
        generateQRCodeAction: QRDisplayScreenModel.GenerateQRCodeAction? = nil,
        renderQRCodeImageAction: QRDisplayScreenModel.RenderQRCodeImageAction? = nil
    ) -> QRDisplayScreenModel {
        QRDisplayScreenModel(
            publicKeyData: Data("public-key".utf8),
            qrService: QRService(contactImportAdapter: PGPContactImportAdapter(engine: PgpEngine())),
            generateQRCodeAction: generateQRCodeAction ?? { _ in Self.makeTestCIImage() },
            renderQRCodeImageAction: renderQRCodeImageAction ?? { _, _ in try? Self.makeTestCGImage() }
        )
    }

    private static func makeTestCIImage() -> CIImage {
        CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: 1, height: 1))
    }

    private static func makeTestCGImage() throws -> CGImage {
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        let bitmapInfo = CGImageAlphaInfo.premultipliedLast.rawValue
        let context = try XCTUnwrap(
            CGContext(
                data: nil,
                width: 1,
                height: 1,
                bitsPerComponent: 8,
                bytesPerRow: 4,
                space: colorSpace,
                bitmapInfo: bitmapInfo
            )
        )
        context.setFillColor(CGColor(gray: 1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: 1, height: 1))
        return try XCTUnwrap(context.makeImage())
    }
}
