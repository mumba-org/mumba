// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

public let PI = 3.14159265358979323846

public enum GfxError : Error {
  case SomeError
}

extension Bool {
  public init(_ i: Int32) {
    self.init(i != 0)
  }

  public init(_ i: Int) {
    self.init(i != 0)
  }

  public var intValue: Int32 {
    if self == true {
      return Int32(1)
    } else {
      return Int32(0)
    }
  }
}

extension Float {

  public var roundedInt: Int {
    var rounded : Float = 0.0
    if self >= 0.0 {
      rounded = floorf(self + 0.5)
    } else {
      rounded = ceilf(self - 0.5)
    }
    return Int(rounded)
  }

}

@inline(__always)
public func lerp(_ a: Int, _ b: Int, _ t: Float) -> Int {
  return Int(Float(a + (b - a)) * t)
}

@inline(__always)
public func lerp(_ a: Float, _ b: Float, _ t: Float) -> Float {
  return a + (b - a) * t
}

@inline(__always)
internal func fixedToFloat(_ x: Int) -> Float { 
  return Float(x) * 1.52587890625e-5
}