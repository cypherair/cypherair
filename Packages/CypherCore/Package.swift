// swift-tools-version: 6.4
import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
]

let package = Package(
    name: "CypherCore",
    platforms: [.iOS("27.2"), .macOS("27.2"), .visionOS("27.2")],
    products: [
        .library(name: "CypherCore", targets: ["CypherCore"]),
    ],
    dependencies: [
        .package(path: "../CypherEngine"),
        .package(path: "../CypherVault"),
    ],
    targets: [
        .target(
            name: "CypherCore",
            dependencies: [
                .product(name: "CypherEngine", package: "CypherEngine"),
                .product(name: "Sealing", package: "CypherVault"),
                .product(name: "Vault", package: "CypherVault"),
                .product(name: "Stores", package: "CypherVault"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CypherCoreTests",
            dependencies: [
                "CypherCore",
                .product(name: "Sealing", package: "CypherVault"),
                .product(name: "Vault", package: "CypherVault"),
                .product(name: "Stores", package: "CypherVault"),
                .product(name: "VaultTestSupport", package: "CypherVault"),
            ],
            swiftSettings: swiftSettings
        ),
    ]
)
