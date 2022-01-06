// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

public protocol PointProtocol : Equatable {
  associatedtype Element: SignedNumeric, Comparable
  
  var x: Element { get set}
  var y: Element { get set}
}

public struct Point<T: SignedNumeric> : PointProtocol where T: Comparable { //where T : SignedNumeric , T : Comparable {

  public typealias Element = T

  public var offsetFromOrigin: Vec2<T> {
    return Vec2<T>(x: x, y: y)
  }

  public var x: T
  public var y: T

  public init() {
    x = 0
    y = 0
  }

  public init(x: T, y: T) {
    self.x = x
    self.y = y
  }

  public init(_ point: Point<T>) {
    self.x = point.x
    self.y = point.y
  }

  public init(_ vec: Vec2<T>) {
    self.x = vec.x
    self.y = vec.y
  }

  public init(_ point: Point3<T>) {
    self.x = point.x
    self.y = point.y
  }

  public mutating func offset(x deltaX: T, y deltaY: T) {
    x = x + deltaX
    y = y + deltaY
  }

  public mutating func set(x: T, y: T) {
    self.x = x
    self.y = y
  }

  public mutating func scale(by: T) {
    self.x = self.x * by
    self.y = self.y * by
  }

  public mutating func scale(x: T, y: T) {
    self.x = self.x * x
    self.y = self.y * y
  }

}

public func ==<T: SignedNumeric>(left: Point<T>, right: Point<T>) -> Bool {
  return (left.x == right.x) && (left.y == right.y)
}

public func !=<T: SignedNumeric>(left: Point<T>, right: Point<T>) -> Bool {
  return !(left == right)
}

public func +<T: SignedNumeric>(left: Point<T>, right: Point<T>) -> Point<T> {
  return Point<T>(x: left.x + right.x, y: left.y + right.y)
}

public func +<T: SignedNumeric>(left: Point<T>, right: Vec2<T>) -> Point<T> {
  return Point<T>(x: left.x + right.x, y: left.y + right.y)
}

public func +<T: SignedNumeric>(left: Point<T>, right: Point<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x + right.x, y: left.y + right.y)
}

public func +(left: Point<Int>, right: Vec2<Int>) -> Point<Float> {
  return Point<Float>(x: Float(left.x) + Float(right.x), y: Float(left.y) + Float(right.y))
}

public func +(left: Point<Int>, right: Vec2<Float>) -> Point<Float> {
  return Point<Float>(x: Float(left.x) + right.x, y: Float(left.y) + right.y)
}

public func -<T: SignedNumeric>(left: Point<T>, right: Point<T>) -> Point<T> {
  return Point<T>(x: left.x - right.x, y: left.y - right.y)
}

public func -<T: SignedNumeric>(left: Point<T>, right: Point<T>) -> Vec2<T> {
  return Vec2<T>(x: left.x - right.x, y: left.y - right.y)
}

public func -<T: SignedNumeric>(left: Point<T>, right: Vec2<T>) -> Point<T> {
  return Point<T>(x: left.x - right.x, y: left.y - right.y)
}

public func -(left: Point<Float>, right: Vec2<Int>) -> Point<Float> {
  return Point<Float>(x: left.x - Float(right.x), y: left.y - Float(right.y))
}

extension Point where T == Int {
   
  public static func toFloored(point: Point<Float>) -> Point<T> {
    let x = Int(floorf(point.x))
    let y = Int(floorf(point.y))
    return Point<T>(x: x, y: y)
  }

  public static func toFloored(point p: Point<T>, scale: Float) -> Point<T> {
    if scale == 1.0 {
      return p
    }
    // scale
    let scaled = Point<Float>.scale(p: Point<Float>(p), scale)
    let x = Int(floorf(scaled.x))
    let y = Int(floorf(scaled.y))
    return Point<T>(x: x, y: y)
  }

  public static func toRounded(point: Point<Float>) -> Point<T> {
    let x = point.x.roundedInt
    let y = point.y.roundedInt
    return Point<T>(x: x, y: y)
  }

  public static func toCeiled(point: Point<Float>) -> Point<T> {
    let x = Int(ceilf(point.x))
    let y = Int(ceilf(point.y))
    return Point<T>(x: x, y: y)
  }

  public init(_ pointf: Point<Float>) {
    self.x = Int(pointf.x)
    self.y = Int(pointf.y)
  }

   public init(_ vecf: Vec2<Float>) {
    self.x = Int(vecf.x)
    self.y = Int(vecf.y)
  }

  public init(_ point3: Point3<Float>) {
    self.x = Int(point3.x)
    self.y = Int(point3.y)
  }

}

extension Point where T == Float {
  
  public static func scale(p: Point<T>, _ xScale: Float, _ yScale: Float) -> Point<T> {
    var scaledp = p
    scaledp.scale(x: xScale, y: yScale)
    return scaledp
  }

  public static func scale(p: Point<T>, _ scale: Float) -> Point<T> {
    return Point<T>.scale(p: p, scale, scale)
  }

  public static func toFloored(point p: Point<T>, scale: Float) -> Point<T> {
    if scale == 1.0 {
      return p
    }
    // scale
    let scaled = Point<Float>.scale(p: Point<Float>(p), scale)
    let x = floorf(scaled.x)
    let y = floorf(scaled.y)
    return Point<T>(x: x, y: y)
  }

  public init(_ point: Point<Int>) {
    self.x = Float(point.x)
    self.y = Float(point.y)
  }

  public init(_ vec: Vec2<Int>) {
    self.x = Float(vec.x)
    self.y = Float(vec.y)
  }

  public init(_ point3: Point3<Int>) {
    self.x = Float(point3.x)
    self.y = Float(point3.y)
  }

  // public mutating func scale(x xScale: Float, y yScale: Float) {
  //   x = x * xScale
  //   y = y * yScale
  // }

}


public protocol Point3Protocol : Equatable {
  associatedtype Element: SignedNumeric, Comparable
  
  var x: Element { get set }
  var y: Element { get set }
  var z: Element { get set }
}

public struct Point3<T: SignedNumeric> : Point3Protocol where T: Comparable {
  
  public typealias Element = T
  
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

  public init(_ other: Point3<T>) {
    self.x = other.x
    self.y = other.y
    self.z = other.z
  }

  public init(_ other: Point<T>) {
    self.x = other.x
    self.y = other.y
    self.z = 0
  }

  public init(_ other: Vec3<T>) {
    self.x = other.x
    self.y = other.y
    self.z = other.z
  }

  public init(_ other: Vec2<T>) {
    self.x = other.x
    self.y = other.y
    self.z = 0
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

  //public func asPoint() -> Point<T> {
  //  return Point<T>(x: x, y: y)
  //}

}


extension Point3 where T == Int {

  public init(_ other: Point3<Float>) {
    self.x = Int(other.x)
    self.y = Int(other.y)
    self.z = Int(other.z)
  }

  public init(_ other: Point<Float>) {
    self.x = Int(other.x)
    self.y = Int(other.y)
    self.z = 0
  }

}

extension Point3 where T == Float {

  public init(_ other: Point3<Int>) {
    self.x = Float(other.x)
    self.y = Float(other.y)
    self.z = Float(other.z)
  }

  public init(_ other: Point<Int>) {
    self.x = Float(other.x)
    self.y = Float(other.y)
    self.z = 0.0
  }
  
}

public func ==<T: SignedNumeric>(left: Point3<T>, right: Point3<T>) -> Bool {
  return (left.x == right.x) && (left.y == right.y) && (left.z == right.z)
}

public func !=<T: SignedNumeric>(left: Point3<T>, right: Point3<T>) -> Bool {
  return !(left == right)
}

public typealias IntPoint = Point<Int>
public typealias FloatPoint = Point<Float>
public typealias IntPoint3 = Point3<Int>
public typealias FloatPoint3 = Point3<Float>

