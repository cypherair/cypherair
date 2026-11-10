import SwiftUI

@main
struct CypherAirApp: App {
    var body: some Scene {
        WindowGroup {
            AppIdentityView()
        }
    }
}

private struct AppIdentityView: View {
    var body: some View {
        VStack(spacing: 8) {
            Text(verbatim: infoString("CFBundleDisplayName"))
                .font(.largeTitle.bold())
            Text("Version \(infoString("CFBundleShortVersionString")) (\(infoString("CFBundleVersion")))")
                .foregroundStyle(.secondary)
        }
        .padding(40)
    }

    private func infoString(_ key: String) -> String {
        Bundle.main.object(forInfoDictionaryKey: key) as? String ?? ""
    }
}
