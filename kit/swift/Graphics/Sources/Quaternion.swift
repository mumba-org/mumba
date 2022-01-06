// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation

public struct Quaternion {

  public var length: Double {
    return x * x + y * y + z * z + w * w
  }
  
  public var x: Double = 0.0
  public var y: Double = 0.0
  public var z: Double = 0.0
  public var w: Double = 1.0

  fileprivate static let epsilon: Double = 1e-5

  public init() {}

  public init(x: Double, y: Double, z: Double, w: Double) {
    self.x = x
    self.y = y
    self.z = z
    self.w = w
  }

  public init(axis: FloatVec3, angle theta: Double) {
    let length = axis.length
    if Double(abs(length)) < Quaternion.epsilon {
      return
    }

    var normalized = axis
    normalized.scale(by: 1.0 / length)

    var t = theta
    t *= 0.5
    let s = sin(t)
    self.x = Double(normalized.x) * s
    self.y = Double(normalized.y) * s
    self.z = Double(normalized.z) * s
    self.w = cos(t)
  }

  public init(from: FloatVec3, to: FloatVec3) {
    let dot = Double(dotProduct(from, to))
    let norm = sqrt(from.lengthSquared * to.lengthSquared)
    var real = norm + dot
    var axis = FloatVec3()
    if real < Quaternion.epsilon * norm {
      real = 0.0
      axis = abs(from.x) > abs(from.z)
                ? FloatVec3(x: -from.y, y: from.x, z: 0.0)
                : FloatVec3(x: 0.0, y: -from.z, z: from.y)
    } else {
      axis = crossProduct(from, to)
    }
    x = Double(axis.x)
    y = Double(axis.y)
    z = Double(axis.z)
    w = real
    self = self.normalized()
  }

  public func slerp(_ q: Quaternion, _ t: Double) -> Quaternion {
    var dot = (self.x * q.x) + (self.y * q.y) + (self.z * q.z) + (self.w * q.w)

    // Clamp dot to -1.0 <= dot <= 1.0.
    dot = min(max(dot, -1.0), 1.0)

    // Quaternions are facing the same direction.
    if abs(dot - 1.0) < Quaternion.epsilon || abs(dot + 1.0) < Quaternion.epsilon {
      return self
    }

    let denom = sqrt(1.0 - dot * dot)
    let theta = acos(dot)
    let w = sin(t * theta) * (1.0 / denom)

    let s1 = cos(t * theta) - dot * w
    let s2 = w

    return (s1 * self) + (s2 * q)
  }

  public func normalized() -> Quaternion {
    if length < Quaternion.epsilon {
      return self
    }
    return self / sqrt(length)
  }
}

public func +(left: Quaternion, right: Quaternion) -> Quaternion {
  return Quaternion(x: right.x + left.x, y: right.y + left.y, z: right.z + left.z, w: right.w + left.w)
}

public func *(left: Quaternion, right: Double) -> Quaternion {
  return Quaternion(x: left.x * right, y: left.y * right, z: left.z * right, w: left.w * right)
}

public func *(left: Double, right: Quaternion) -> Quaternion {
  return Quaternion(x: right.x * left, y: right.y * left, z: right.z * left, w: right.w * left)
}

public func *(left: Quaternion, right: Quaternion) -> Quaternion {
  return Quaternion(
    x: left.w * right.x + left.x * right.w + left.y * right.z - left.z * right.y,
    y: left.w * right.y - left.x * right.z + left.y * right.w + left.z * right.x,
    z: left.w * right.z + left.x * right.y - left.y * right.x + left.z * right.w,
    w: left.w * right.w - left.x * right.x - left.y * right.y - left.z * right.z)
}

public func /(left: Quaternion, right: Double) -> Quaternion {
  let inv = 1.0 / right
  return left * inv
}