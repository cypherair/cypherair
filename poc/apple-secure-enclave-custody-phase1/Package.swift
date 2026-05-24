// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AppleSecureEnclaveCustodyPhase1",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "Phase1SecureEnclaveProbe",
            targets: ["Phase1SecureEnclaveProbe"]
        )
    ],
    targets: [
        .executableTarget(
            name: "Phase1SecureEnclaveProbe"
        )
    ]
)
