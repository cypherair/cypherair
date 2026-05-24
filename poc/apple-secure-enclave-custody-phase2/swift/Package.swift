// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AppleSecureEnclaveCustodyPhase2Swift",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "Phase2SecureEnclavePublicKeyProbe",
            targets: ["Phase2SecureEnclavePublicKeyProbe"]
        )
    ],
    targets: [
        .executableTarget(
            name: "Phase2SecureEnclavePublicKeyProbe"
        )
    ]
)
