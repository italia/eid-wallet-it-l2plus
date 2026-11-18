// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "L2PlusSDK",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "L2PlusSDK", targets: ["L2PlusSDK"]),
    ],
    targets: [
        .binaryTarget(
            name: "OpenSSL",
            path: "ios/Vendor/OpenSSL/OpenSSL.xcframework"
        ),
        .target(
            name: "L2PlusCrypto",
            dependencies: ["OpenSSL"],
            path: "ios/Sources/L2PlusCrypto",
            linkerSettings: [.linkedLibrary("z")]
        ),
        .target(
            name: "L2PlusSDK",
            dependencies: ["L2PlusCrypto"],
            path: "ios/Sources/L2PlusSDK",
            resources: [.copy("Resources/CSCA")]
        ),
    ]
)
