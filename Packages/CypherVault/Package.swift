// swift-tools-version: 6.4
import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
]

let package = Package(
    name: "CypherVault",
    platforms: [.iOS(.v27), .macOS(.v27), .visionOS(.v27)],
    products: [
        .library(name: "Vault", targets: ["Vault"]),
        .library(name: "Stores", targets: ["Stores"]),
    ],
    targets: [
        .target(name: "Sealing", swiftSettings: swiftSettings),
        .target(name: "Vault", dependencies: ["Sealing"], swiftSettings: swiftSettings),
        .target(name: "Stores", dependencies: ["Vault", "Sealing"], swiftSettings: swiftSettings),
        .testTarget(name: "SealingTests", dependencies: ["Sealing"], swiftSettings: swiftSettings),
    ]
)
