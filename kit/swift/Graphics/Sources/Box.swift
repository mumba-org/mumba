// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct Box {
  public init() {}
}

public struct FloatBox {
  public var x: Float
  public var y: Float
  public var z: Float
  public var width: Float
  public var height: Float
  public var depth: Float
  
  public init(x: Float,
              y: Float,
              z: Float,
              width: Float,
              height: Float,
              depth: Float) {
    self.x = x
    self.y = y
    self.z = z
    self.width = width
    self.height = height
    self.depth = depth
  }

  public init(width: Float, height: Float, depth: Float) {
    self.x = 0.0
    self.y = 0.0
    self.z = 0.0
    self.width = width
    self.height = height
    self.depth = depth
  }

}
