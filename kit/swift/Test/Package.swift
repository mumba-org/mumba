// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import PackageDescription

let package = Package(
    name: "Test",
    products: [
        .executable(
            name: "test.exe",
            targets: ["Test"]
        )
    ],
    dependencies: [
        .package(url: "../Base", from: "1.0.0"),
        .package(url: "../../../runtime/MumbaShims", from: "1.0.0"),
        .package(url: "../ThirdParty/NIO", from: "1.0.0"),
        .package(url: "../PosixShim", from: "1.0.0"),
        .package(url: "../ThirdParty/Libevent", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "Test",
            dependencies: [
              "Base"
            ],
            path: "Source"
        )
    ]
)
