// swift-tools-version: 6.4
import PackageDescription

// The engine: the Rust library and its generated Swift bindings, both written
// here by scripts/build-engine.sh and never committed.

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
]

let package = Package(
    name: "CypherEngine",
    // The app's exact deployment target: with `.v27` the linker warns once for
    // every object file in the library.
    platforms: [.iOS("27.2"), .macOS("27.2"), .visionOS("27.2")],
    products: [
        .library(name: "CypherEngine", targets: ["CypherEngine"]),
    ],
    targets: [
        .binaryTarget(name: "CypherEngineFFI", path: "CypherEngineFFI.xcframework"),
        .target(name: "CypherEngine", dependencies: ["CypherEngineFFI"], swiftSettings: swiftSettings),
    ]
)
