// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum WebScreenOrientationType : Int {
  case WebScreenOrientationUndefined = 0
}

public struct WebScreenInfo {
    public var deviceScaleFactor: Float
    public var depth: Int
    public var depthPerComponent: Int
    public var isMonochrome: Bool
    public var rect: IntRect
    public var availableRect: IntRect
    public var orientationType: WebScreenOrientationType
    public var orientationAngle: UInt16

    init() {
        deviceScaleFactor = 1
        depth = 0
        depthPerComponent = 0
        isMonochrome = false
        orientationType = .WebScreenOrientationUndefined
        orientationAngle = 0
        rect = IntRect()
        availableRect = IntRect()
    }

 }
