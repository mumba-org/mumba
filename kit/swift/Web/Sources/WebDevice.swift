// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public struct WebDeviceEmulationParams {
    
    public enum ScreenPosition : Int {
        case Desktop = 0
        case Mobile
    }

    public var screenPosition: ScreenPosition
    public var screenSize: IntSize 
    public var viewPosition: IntPoint
    public var deviceScaleFactor: Float
    public var viewSize: IntSize
    public var fitToView: Bool
    public var offset: FloatPoint
    public var scale: Float
}