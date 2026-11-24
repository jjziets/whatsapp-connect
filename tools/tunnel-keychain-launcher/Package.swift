// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TunnelKeychainLauncher",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "TunnelKeychainLauncher", targets: ["TunnelKeychainLauncher"]),
        .executable(name: "tunnel-keychain-launcher", targets: ["TunnelKeychainLauncherCLI"])
    ],
    targets: [
        .target(name: "TunnelKeychainLauncher", path: "Sources/TunnelKeychainLauncher", exclude: ["main.swift"]),
        .executableTarget(name: "TunnelKeychainLauncherCLI", dependencies: ["TunnelKeychainLauncher"],
            path: "Sources/TunnelKeychainLauncher", exclude: ["Launcher.swift"], sources: ["main.swift"]),
        .testTarget(name: "TunnelKeychainLauncherTests", dependencies: ["TunnelKeychainLauncher"])
    ]
)
