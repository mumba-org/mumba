// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation

public protocol Vec2Protocol {
  associatedtype Element: Numeric

  var x: Element { get set }
  var y: Element { get set }
  var length: Float { get }

  mutating func set(x: Element, y: Element)
}

public struct Vec2<T: SignedNumeric> : Vec2Protocol where T: Comparable {

  public typealias Element = T

  public var x: T
  public var y: T
  public var length: Float {
    return 0.0
  }

  static public func += (left: inout Vec2<T>, right: Vec2<T>) {
    left = left + right
  }

  public init() {
    x = 0
    y = 0
  }

  public init(x: T, y: T) {
    self.x = x
    self.y = y
  }

  public init(_ other: Vec2<T>) {
    self.x = other.x
    self.y = other.y
  }

  public init(_ point: Point<T>) {
    self.x = point.x
    self.y = point.y
  }

  public mutating func set(x: T, y: T) {
    self.x = x
    self.y = y
  }

  public mutating func scale(by: T) {
    x = x * by
    y = y * by
  }

  public mutating func scale(x: T, y: T) {
    self.x = self.x * x
    self.y = self.y * y
  }

}

public func +<T: SignedNumeric>(left: Vec2<T>, right: Vec2<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x + right.x, y: left.y + right.y)
}

public func -<T: SignedNumeric>(left: Vec2<T>, right: Vec2<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x - right.x, y: left.y - right.y)
}

public func *<T: SignedNumeric>(left: Vec2<T>, right: Vec2<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x * right.x, y: left.y * right.y)
}

public func +<T: SignedNumeric>(left: Vec2<T>, right: Point<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x + right.x, y: left.y + right.y)
}

public func -<T: SignedNumeric>(left: Vec2<T>, right: Point<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x - right.x, y: left.y - right.y)
}

public func *<T: SignedNumeric>(left: Vec2<T>, right: Point<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x * right.x, y: left.y * right.y)
}

extension Vec2 where T == Int {

  public var length: Float {
    return Float((x * x) + (y * y)).squareRoot()
  }

  public init(_ vec: Vec2<Float>) {
    self.x = Int(vec.x)
    self.y = Int(vec.y)
  }
}

extension Vec2 where T == Float {
  
  public var length: Float {
    return ((x * x) + (y * y)).squareRoot()
  }

  public init(_ vec: Vec2<Int>) {
    self.x = Float(vec.x)
    self.y = Float(vec.y)
  }
}

public protocol Vec3Protocol {  
  associatedtype Element: Numeric
  
  var x: Element { get set}
  var y: Element { get set}
  var z: Element { get set}
}

public struct Vec3<T: SignedNumeric> : Vec3Protocol  where T: Comparable {

  public var x: T
  public var y: T
  public var z: T

  public init() {
    x = 0
    y = 0
    z = 0
  }

  public init(x: T, y: T, z: T) {
    self.x = x
    self.y = y
    self.z = z
  }

  public init(_ other: Vec3<T>) {
    self.x = other.x
    self.y = other.y
    self.z = other.z
  }

  public init(_ point: Point3<T>) {
    self.x = point.x
    self.y = point.y
    self.z = point.z
  }

  public mutating func set(x: T, y: T, z: T) {
    self.x = x
    self.y = y
    self.z = z
  }

  public mutating func scale(by: T) {
    x = x * by
    y = y * by
    z = z * by
  }

  public mutating func scale(x: T, y: T, z: T) {
    self.x = self.x * x
    self.y = self.y * y
    self.z = self.z * z
  }

}

extension Vec3 where T == Float {

  @inlinable
  public var lengthSquared: Double {
    return Double(x * x) + Double(y * y) + Double(z * z)
  }

  @inlinable
  public var length: Float {
    return Float(sqrt(lengthSquared))
  }
  
  @inlinable
  public mutating func cross(_ other: Vec3<T>) {
    let dx = Double(self.x)
    let dy = Double(self.y)
    let dz = Double(self.z)
    let x = Float(dy * Double(other.z) - dz * Double(other.y))
    let y = Float(dz * Double(other.x) - dx * Double(other.z))
    let z = Float(dx * Double(other.y) - dy * Double(other.x))
    self.x = x
    self.y = y
    self.z = z
  }

}

public func +<T: SignedNumeric>(left: Vec3<T>, right: Vec3<T>) -> Vec3<T> {
  return Vec3<T>(x: left.x + right.x, y: left.y + right.y, z: left.z + right.z)
}

public func -<T: SignedNumeric>(left: Vec3<T>, right: Vec3<T>) -> Vec3<T> {
  return Vec3<T>(x: left.x - right.x, y: left.y - right.y, z: left.z - right.z)
}

public func *<T: SignedNumeric>(left: Vec3<T>, right: Vec3<T>) -> Vec3<T> {
  return Vec3<T>(x: left.x * right.x, y: left.y * right.y, z: left.z * right.z)
}

public func +<T: SignedNumeric>(left: Vec3<T>, right: Point3<T>) -> Vec3<T> {
  return Vec3<T>(x: left.x + right.x, y: left.y + right.y, z: left.z + right.z)
}

public func -<T: SignedNumeric>(left: Vec3<T>, right: Point3<T>) -> Vec3<T> {
  return Vec3<T>(x: left.x - right.x, y: left.y - right.y, z: left.z - right.z)
}

public func *<T: SignedNumeric>(left: Vec3<T>, right: Point3<T>) -> Vec3<T> {
  return Vec3<T>(x: left.x * right.x, y: left.y * right.y, z: left.z * right.z)
}

public func crossProduct(_ lhs: Vec3<Float>, _ rhs: Vec3<Float>) -> Vec3<Float> {
  var result = lhs
  result.cross(rhs)
  return result
}

public func dotProduct(_ lhs: Vec3<Float>, _ rhs: Vec3<Float>) -> Float {
  return lhs.x * rhs.x + lhs.y * rhs.y + lhs.z * rhs.z
}

public typealias IntVec2 = Vec2<Int>
public typealias FloatVec2 = Vec2<Float>
public typealias IntVec3 = Vec3<Int>
public typealias FloatVec3 = Vec3<Float>