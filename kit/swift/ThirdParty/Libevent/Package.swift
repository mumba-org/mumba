// swift-tools-version:4.0
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

var targets: [PackageDescription.Target] = [
    //.target(name: "Libevent",
    //        dependencies: ["CLibevent"]),
    .target(
      name: "CLibevent",
      dependencies: ["CLibevent"])
]

let package = Package(
    name: "libevent",
    products: [
        .library(name: "Libevent", targets: ["CLibevent"])
    ],
    dependencies: [
        .package(url: "../../../../runtime/MumbaShims", from: "1.0.0"),
    ],
    targets: targets
)
