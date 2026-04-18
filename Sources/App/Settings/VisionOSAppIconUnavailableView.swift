import SwiftUI

struct VisionOSAppIconUnavailableView: View {
    var body: some View {
        ContentUnavailableView {
            Label(
                String(localized: "settings.appIcon", defaultValue: "App Icon"),
                systemImage: "app"
            )
        } description: {
            Text(
                String(
                    localized: "settings.appIcon.visionosUnavailable",
                    defaultValue: "Apps built natively with the visionOS SDK do not support changing alternate app icons at runtime."
                )
            )
        }
        .navigationTitle(String(localized: "settings.appIcon", defaultValue: "App Icon"))
    }
}
