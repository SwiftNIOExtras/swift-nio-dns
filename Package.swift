// swift-tools-version:6.3

import PackageDescription

let package = Package(
  name: "swift-nio-dns",

  platforms: [ .macOS(.v26), .iOS(.v26), .visionOS(.v26) ],

  products: [
    .library(name: "NIODNS",       targets: [ "NIODNS"       ]),
    .library(name: "NIODNSClient", targets: [ "NIODNSClient" ]),
    .library(name: "NIODNSServer", targets: [ "NIODNSServer" ])
  ],

  dependencies: [
    .package(url: "https://github.com/apple/swift-nio", from: "2.97.0")
  ],

  targets: [
    .target(name: "NIODNS",
            dependencies  : [ .product(name: "NIOCore", package: "swift-nio") ],
            swiftSettings : [ .enableExperimentalFeature("Lifetimes") ]),
    .target(name: "NIODNSClient",
            dependencies: [
              "NIODNS",
              .product(name: "NIOCore",  package: "swift-nio"),
              .product(name: "NIOPosix", package: "swift-nio")
            ]),
    .target(name: "NIODNSServer",
            dependencies: [
              "NIODNS",
              .product(name: "NIOCore",               package: "swift-nio"),
              .product(name: "NIOPosix",              package: "swift-nio"),
              .product(name: "NIOConcurrencyHelpers", package: "swift-nio")
            ]),

    .testTarget(name: "NIODNSTests",
                dependencies: [
                  "NIODNS", .product(name: "NIOEmbedded", package: "swift-nio")
                ]),
    .testTarget(name: "NIODNSClientTests",
                dependencies: [
                  "NIODNSClient", "NIODNSServer",
                  .product(name: "NIOPosix",              package: "swift-nio"),
                  .product(name: "NIOConcurrencyHelpers", package: "swift-nio")
                ]),
    .testTarget(name: "NIODNSServerTests",
                dependencies: [
                  "NIODNSServer", "NIODNSClient",
                  .product(name: "NIOPosix", package: "swift-nio")
                ])
  ],

  swiftLanguageModes: [ .v6 ]
)
