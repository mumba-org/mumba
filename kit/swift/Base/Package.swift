// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import PackageDescription

let package = Package(
    name: "Base",
    products: [
        .library(
            name: "Base",
            targets: ["Base"]),
    ],
    dependencies: [
        .package(url: "../../../runtime/MumbaShims", from: "1.0.0"),
        .package(url: "../ThirdParty/NIO", from: "1.0.0"),
        .package(url: "../PosixShim", from: "1.0.0"),
        //.package(url: "../ThirdParty/Libevent", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "Base",
            dependencies: [
              "NIO"
            ],
            path: "Sources"
        )
    ]
)
