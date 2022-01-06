// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum ScrollbarOrientation {
  case Horizontal
  case Vertical
}

public enum ScrollDirection {
  case Backward
  case Forward
}

public enum ScrollbarPart {
  case Thumb
  case Track
}

public struct ScrollAndScaleSet {}

public enum ScrollBlocksOn: Int {
  case OnNone        = 0x0
  case OnStartTouch  = 0x1
  case OnWheelEvent  = 0x2
  case OnScrollEvent = 0x4
}

public protocol ScrollbarLayerInterface {
  func ScrollLayerId() -> Int
  func SetScrollLayer(layerId: Int)
  func Orientation() -> ScrollbarOrientation
}

public typealias ScrollCallback = () -> Void

public struct ScrollOffset {
  public var x: Float
  public var y: Float

  public init() {
    y = 0.0
    x = 0.0
  }

  public init(x: Float, y: Float) {
    self.x = x
    self.y = y
  }
}
