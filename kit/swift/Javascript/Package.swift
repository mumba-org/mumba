// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import PackageDescription

let package = Package(
    name: "Javascript",
    products: [
        .library(
            name: "Javascript",
            targets: ["Javascript"]),
    ],
    dependencies: [
        .package(url: "../../../runtime/MumbaShims", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "Javascript"
        )
    ]
)
