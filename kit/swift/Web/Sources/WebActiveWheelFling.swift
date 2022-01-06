// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum WebGestureDevice : Int {
	case Uninitialized = 0
	case Touchpad
	case Touchscreen
}

public struct WebActiveWheelFlingParameters {
    public var delta: FloatPoint
    public var point: IntPoint
    public var globalPoint: IntPoint
   	public var modifiers: Int
    public var sourceDevice: WebGestureDevice 
    public var cumulativeScroll: IntSize 
    public var startTime: Double
}