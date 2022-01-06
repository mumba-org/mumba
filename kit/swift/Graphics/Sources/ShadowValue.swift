// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public typealias ShadowValues = [ShadowValue]

public struct ShadowValue {

  public var offset: FloatVec2
  public var blur: Double
  public var color: Color
  public var x: Float { return offset.x }
  public var y: Float { return offset.y }

  public static func getMargin(shadows: ShadowValues) -> FloatInsets {
    return FloatInsets()
  }

  public init() {
    offset = FloatVec2(x: 0, y: 0)
    blur = 0.0
    color = Color()
  }

  public init(offset: FloatVec2, blur: Double, color: Color) {
    self.offset = offset
    self.blur = blur
    self.color = color
  }

  public func scale(scale: Float) -> ShadowValue {
    return ShadowValue()
  }

}
