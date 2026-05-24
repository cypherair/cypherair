// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Phase3SecureEnclaveSigningBridge",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "Phase3SecureEnclaveSigningBridge",
            targets: ["Phase3SecureEnclaveSigningBridge"]
        )
    ],
    targets: [
        .executableTarget(
            name: "Phase3SecureEnclaveSigningBridge"
        )
    ]
)
