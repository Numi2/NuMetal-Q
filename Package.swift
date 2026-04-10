// swift-tools-version: 6.0
import Foundation
import PackageDescription

let applePQEnabled = ProcessInfo.processInfo.environment["NUMETALQ_ENABLE_APPLE_PQ"] == "1"
let applePQSwiftSettings: [SwiftSetting] = applePQEnabled ? [
    .define("NUMETALQ_APPLE_PQ"),
] : []

let package = Package(
    name: "NuMetal-Q",
    platforms: [
        .macOS(.v13),
        .iOS(.v17),
    ],
    products: [
        .library(name: "NuMetal_Q", targets: ["NuMetal_Q"]),
        .executable(name: "NuMetalQAcceptanceDemo", targets: ["NuMetalQAcceptanceDemo"]),
        .executable(name: "NuMetalQBenchmarks", targets: ["NuMetalQBenchmarks"]),
    ],
    targets: [
        .target(
            name: "NuMetalQSealXOF",
            path: "SealXOF",
            publicHeadersPath: "include"
        ),
        .target(
            name: "NuMetal_Q",
            dependencies: ["NuMetalQSealXOF"],
            path: "NuMetal-Q",
            exclude: [
                "NuMetal_Q.docc",
                "NuCluster/README.md",
                "NuField/README.md",
                "NuFold/README.md",
                "NuIR/README.md",
                "NuMetal/README.md",
                "NuSDK/README.md",
                "NuSeal/README.md",
                "NuSupport/README.md",
                "NuVault/README.md",
                "numeqc/README.md",
            ],
            resources: [
                .copy("NuMetal/Compiled"),
                .copy("NuMetal/Shaders"),
            ],
            swiftSettings: applePQSwiftSettings
        ),
        .executableTarget(
            name: "NuMetalQAcceptanceDemo",
            dependencies: ["NuMetal_Q"],
            path: "Examples/NuMetalQAcceptanceDemo",
            swiftSettings: applePQSwiftSettings
        ),
        .executableTarget(
            name: "NuMetalQBenchmarks",
            dependencies: ["NuMetal_Q"],
            path: "Examples/NuMetalQBenchmarks",
            swiftSettings: applePQSwiftSettings
        ),
        .testTarget(
            name: "NuMetal_QTests",
            dependencies: ["NuMetal_Q"],
            path: "Tests/NuMetal_QTests",
            swiftSettings: applePQSwiftSettings
        ),
    ]
)
