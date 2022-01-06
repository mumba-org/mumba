// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import PackageDescription

let package = Package(
    name: "Container",
    products: [
        .library(
            name: "Container",
            targets: ["Container", "_"]),
    ],
    dependencies: [
        .package(url: "../../../runtime/MumbaShims", from: "1.0.0"),
        .package(url: "../../swift/Javascript", from: "1.0.0"),
        .package(url: "../../swift/Base", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "_"
        ),
        .target(
            name: "Container",
            dependencies: [
                "_", "Javascript", "Base"
            ]
        )
    ]
)
