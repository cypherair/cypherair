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
        XCTAssertNil(model.error)
        XCTAssertFalse(model.showError)
    }

    @MainActor
    func test_prepare_whenQRCodeGenerationReturnsNil_presentsCorruptDataError() {
        let model = makeModel(generateQRCodeAction: { _ in nil })

        model.prepare()

        assertCorruptData(model.error, reason: "QR code generation returned no image")
        XCTAssertTrue(model.showError)
    }

    @MainActor
    func test_prepare_whenRenderReturnsNil_presentsCorruptDataError() {
        let model = makeModel(renderQRCodeImageAction: { _, _ in nil })

        model.prepare()

        assertCorruptData(model.error, reason: "Failed to render QR code image")
        XCTAssertTrue(model.showError)
    }

    @MainActor
    func test_prepare_whenGenerationThrows_normalizesError() {
        let model = makeModel(
            generateQRCodeAction: { _ in
                throw QRDisplayScreenModelTestError(message: "generation failed")
            }
        )

        model.prepare()

        assertCorruptData(model.error, reason: "generation failed")
        XCTAssertTrue(model.showError)
    }

    @MainActor
    func test_dismissError_clearsPresentedError() {
        let model = makeModel(generateQRCodeAction: { _ in nil })
        model.prepare()

        model.dismissError()

        XCTAssertNil(model.error)
        XCTAssertFalse(model.showError)
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

    private func assertCorruptData(
        _ error: CypherAirError?,
        reason expectedReason: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .corruptData(let reason)? = error else {
            return XCTFail("Expected corruptData, got \(String(describing: error))", file: file, line: line)
        }
        XCTAssertEqual(reason, expectedReason, file: file, line: line)
    }
}
