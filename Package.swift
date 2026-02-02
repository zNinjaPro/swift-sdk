// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ShieldedPoolSDK",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        // Core cryptographic primitives (Poseidon, Merkle, types)
        .library(
            name: "ShieldedPoolCore",
            targets: ["ShieldedPoolCore"]),
        // Full SDK with Solana integration
        .library(
            name: "ShieldedPoolSDK",
            targets: ["ShieldedPoolSDK"]),
    ],
    dependencies: [
        // BigInt for BN254 field arithmetic (Poseidon hash)
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0"),
        // Solana Swift SDK
        .package(url: "https://github.com/p2p-org/solana-swift.git", from: "5.0.0"),
        // Rapidsnark - Native Groth16 prover (iOS only) - beta version
        .package(url: "https://github.com/iden3/ios-rapidsnark.git", exact: "0.0.1-beta.4"),
        // Circom Witnesscalc - Native witness generation (iOS only) - alpha version
        .package(url: "https://github.com/iden3/circom-witnesscalc-swift.git", exact: "0.0.1-alpha.3"),
    ],
    targets: [
        // Core module - no external Solana dependencies, can be used standalone
        .target(
            name: "ShieldedPoolCore",
            dependencies: [
                "BigInt",
                // Conditional dependencies for iOS ZK proving
                .product(name: "rapidsnark", package: "ios-rapidsnark", condition: .when(platforms: [.iOS])),
                .product(name: "CircomWitnesscalc", package: "circom-witnesscalc-swift", condition: .when(platforms: [.iOS])),
            ],
            path: "Sources/ShieldedPoolCore",
            resources: [
                .process("Resources")
            ]
        ),
        // Full SDK with Solana integration
        .target(
            name: "ShieldedPoolSDK",
            dependencies: [
                "ShieldedPoolCore",
                .product(name: "SolanaSwift", package: "solana-swift"),
            ],
            path: "Sources/ShieldedPoolSDK"
        ),
        // Test targets
        .testTarget(
            name: "ShieldedPoolCoreTests",
            dependencies: ["ShieldedPoolCore"],
            path: "Tests/ShieldedPoolCoreTests",
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "ShieldedPoolSDKTests",
            dependencies: ["ShieldedPoolSDK"],
            path: "Tests/ShieldedPoolSDKTests"
        ),
    ]
)
