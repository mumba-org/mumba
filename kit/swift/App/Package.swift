// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import PackageDescription

let package = Package(
    name: "Mumba",
    targets: [
        Target(
            name: "_"
        ),
        Target(
            name: "Container",
            dependencies: [
	         .Target(name: "Core")
 	        ]
        ),
        Target(
          name: "Graphics",
	      dependencies: [
	        .Target(name: "Core")
 	      ]
        ),
        Target(
          name: "GL"
        ),
        Target(
            name: "Platform",
            dependencies: [
              .Target(name: "Graphics")
            ]
        ),
        Target(
            name: "Gpu",
            dependencies: [
              .Target(name: "Graphics"),
              .Target(name: "Platform"),
              .Target(name: "GL")
            ]
        ),
        Target(
            name: "Compositor",
            dependencies: [
              .Target(name: "Graphics"),
              .Target(name: "Gpu")
            ]
        ),  
        Target(
            name: "Net"
        ),
        Target(
            name: "Media"
        ),
        Target(
            name: "PDF",
            dependencies: [
              .Target(name: "Graphics"),
              .Target(name: "C")
            ]
        ),
        Target(
            name: "Text"
        ),
        Target(
          name: "Application",
          dependencies: [
            .Target(name: "Core"),
            .Target(name: "Graphics"),
            .Target(name: "Net")
          ]
        ),
        Target(
            name: "UI",
            dependencies: [
              .Target(name: "Application"),
              .Target(name: "Graphics"),
              .Target(name: "Compositor"),
              .Target(name: "GL"),
              .Target(name: "Platform"),
              .Target(name: "Gpu"),
              .Target(name: "X11")
            ]
        ),
        Target(
            name: "X11",
            dependencies: [
              .Target(name: "Platform"),
              .Target(name: "Graphics")
            ]
        ),
        //Target(
        //    name: "Web",
        //    dependencies: [
        //        .Target(name: "Javascript"),
        //        .Target(name: "Graphics"),
        //        .Target(name: "Compositor")
        //    ]
        //),
    ],
    dependencies: [
        .Package(url: "../../../runtime/MumbaShims", majorVersion: 1),//,
        .package(url: "../../kit/swift/Base", from: "1.0.0")
       // .Package(url: "../../runtime/MumbaShims/CPython", majorVersion: 1)
    ]
)
