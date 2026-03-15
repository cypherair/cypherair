import SwiftUI

/// Displays the user's public key as a QR code for sharing.
/// Format: cypherair://import/v1/<base64url binary key, no padding>
struct QRDisplayView: View {
    @Environment(QRService.self) private var qrService

    let publicKeyData: Data
    let displayName: String

    @State private var qrCGImage: CGImage?
    @State private var error: CypherAirError?
    @State private var showError = false

    var body: some View {
        VStack(spacing: 24) {
            if let qrCGImage {
                Image(decorative: qrCGImage, scale: 1.0)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 280, maxHeight: 280)
                    .accessibilityLabel(
                        String(localized: "qr.accessibility", defaultValue: "QR code containing public key")
                    )
            } else {
                ProgressView()
                    .frame(width: 280, height: 280)
            }

            Text(displayName)
                .font(.headline)

            Text(String(localized: "qr.instruction", defaultValue: "Ask your contact to scan this QR code with their camera."))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .padding()
        .navigationTitle(String(localized: "qr.title", defaultValue: "My Public Key"))
        .task {
            generateQR()
        }
        .alert(
            String(localized: "error.title", defaultValue: "Error"),
            isPresented: $showError,
            presenting: error
        ) { _ in
            Button(String(localized: "error.ok", defaultValue: "OK")) {}
        } message: { err in
            Text(err.localizedDescription)
        }
    }

    private func generateQR() {
        do {
            if let ciImage = try qrService.generateQRCode(for: publicKeyData) {
                let context = CIContext()
                let size = CGSize(width: 1024, height: 1024)
                let transform = CGAffineTransform(
                    scaleX: size.width / ciImage.extent.width,
                    y: size.height / ciImage.extent.height
                )
                let scaledImage = ciImage.transformed(by: transform)

                if let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) {
                    qrCGImage = cgImage
                }
            }
        } catch {
            self.error = CypherAirError.from(error) { .corruptData(reason: $0) }
            showError = true
        }
    }
}
