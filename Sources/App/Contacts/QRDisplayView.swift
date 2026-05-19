import SwiftUI

/// Displays the user's public key as a QR code for sharing.
/// Format: cypherair://import/v1/<base64url binary key, no padding>
struct QRDisplayView: View {
    @Environment(QRService.self) private var qrService
    let publicKeyData: Data
    let displayName: String

    var body: some View {
        QRDisplayHostView(
            publicKeyData: publicKeyData,
            displayName: displayName,
            qrService: qrService
        )
    }
}

private struct QRDisplayHostView: View {
    let displayName: String

    @State private var model: QRDisplayScreenModel

    init(
        publicKeyData: Data,
        displayName: String,
        qrService: QRService
    ) {
        self.displayName = displayName
        _model = State(
            initialValue: QRDisplayScreenModel(
                publicKeyData: publicKeyData,
                qrService: qrService
            )
        )
    }

    var body: some View {
        qrContent
            .padding()
            .cypherMacReadableContent(
                maxWidth: MacPresentationWidth.qrContent,
                alignment: .center,
                outerAlignment: .center
            )
            .accessibilityIdentifier("qr.root")
            .screenReady("qr.ready")
            .navigationTitle(String(localized: "qr.title", defaultValue: "My Public Key"))
            .task {
                model.prepare()
            }
            .alert(
                String(localized: "error.title", defaultValue: "Error"),
                isPresented: Binding(
                    get: { model.showError },
                    set: { if !$0 { model.dismissError() } }
                ),
                presenting: model.error
            ) { _ in
                Button(String(localized: "error.ok", defaultValue: "OK")) {}
            } message: { err in
                Text(err.localizedDescription)
            }
    }

    private var qrContent: some View {
        VStack(spacing: 24) {
            if let qrCGImage = model.qrCGImage {
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
    }
}
