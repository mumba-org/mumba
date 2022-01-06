// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc // for floor, ceil
#endif

public protocol SizeProtocol : Equatable {
  
  associatedtype Element: SignedNumeric, Comparable
 
  var isEmpty: Bool { get }
  var area: Element { get }
  var width : Element { get set }
  var height: Element { get set }

  mutating func enlarge(width growWidth: Element, height growHeight: Element)
}

public struct Size<T: SignedNumeric> : SizeProtocol where T: Comparable {

  public typealias Element = T

  public var isEmpty: Bool {
    return width == 0 && height == 0
  }

  public var area: Element {
    var area = width
    area *= height
    return area
  }

  public var width : T
  public var height: T

  public mutating func enlarge(width growWidth: Element, height growHeight: Element) {
    width = width + growWidth
    height = height + growHeight
  }

  public init() {
    width = 0
    height = 0
  }

  public init(width: T, height: T) {
    self.width = width
    self.height = height
  }

  public init(_ size: Size<T>) {
    width = size.width
    height = size.height
  }


}

public func ==<T: SignedNumeric>(left: Size<T>, right: Size<T>) -> Bool {
  return (left.width == right.width) && (left.height == right.height)
}

public func !=<T: SignedNumeric>(left: Size<T>, right: Size<T>) -> Bool {
  return !(left == right)
}

extension Size where T == Int {

  public static func roundedInt(value: Float) -> Int {
    var rounded : Float = 0.0
    if value >= 0.0 {
      rounded = floorf(value + 0.5)
    } else {
      rounded = ceilf(value - 0.5)
    }
    return Int(rounded)
  }

  public static func toFloored(_ size: Size<Float>) -> Size<Int> {
    let w = Int(floorf(size.width))
    let h = Int(floorf(size.height))
    return Size<Int>(width: w, height: h)
  }

  public static func toCeiled(_ size: Size<Float>) -> Size<Int> {
    let w = Int(ceilf(size.width))
    let h = Int(ceilf(size.height))
    return Size<Int>(width: w, height: h)
  }

  public static func scaleToCeiled(_ size: Size<Int>, scale: Float) -> Size<Int> {
    if scale == 1.0 {
      return size
    }
    return Size<Int>.toCeiled(Size<Float>.scale(Size<Float>(size), scale, scale))
  }


  public static func toRounded(size: Size<Float>) -> Size<Int> {
    let w = size.width.roundedInt
    let h = size.height.roundedInt
    return Size<Int>(width: w, height: h)
  }

  public static func scaleToRounded(size: Size<Int>, scaleBy: Float) -> Size<Int> {
    let scaled = Size<Float>.scale(Size<Float>(size), scaleBy)
    return Size<Int>.toRounded(size: scaled)
  }

  public init(_ sizef: Size<Float>) {
    width = Int(sizef.width)
    height = Int(sizef.height)
  }

  public mutating func setToMin(other: Size<Int>) {
    width = width <= other.width ? width : other.width
    height = height <= other.height ? height : other.height
  }

  public mutating func setToMax(other: Size<Int>) {
    width = width >= other.width ? width : other.width
    height = height >= other.height ? height : other.height
  }

}

extension Size where T == Float {

  public static func scale(_ s: Size<Float>, _ xScale: Float, _ yScale: Float) -> Size<Float> {
    var scaleds = s
    scaleds.scale(x: xScale, y: yScale)
    return scaleds
  }

  public static func scale(_ s: Size<Float>, _ scale: Float) -> Size<Float> {
    return Size<Float>.scale(s, scale, scale)
  }

  public static func toFloored(_ size: Size<Float>) -> Size<Float> {
    let w = floorf(size.width)
    let h = floorf(size.height)
    return Size<Float>(width: w, height: h)
  }

  public static func toCeiled(_ size: Size<Float>) -> Size<Float> {
    let w = ceilf(size.width)
    let h = ceilf(size.height)
    return Size<Float>(width: w, height: h)
  }

  public static func scaleToCeiled(_ size: Size<Float>, scale: Float) -> Size<Float> {
    if scale == 1.0 {
      return size
    }
    return Size<Float>.toCeiled(Size<Float>.scale(size, scale, scale))
  }

  public init(_ size: Size<Int>) {
    width = Float(size.width)
    height = Float(size.height)
  }

  public mutating func scale(x xScale: Float, y yScale: Float) {
    width = width * xScale
    height = height * yScale
  }

  public mutating func setToMin(other: Size<Float>) {
    width = width <= other.width ? width : other.width
    height = height <= other.height ? height : other.height
  }

  public mutating func setToMax(other: Size<Float>) {
    width = width >= other.width ? width : other.width
    height = height >= other.height ? height : other.height
  }

  public static func toCeiled(size: Size<Float>, scale: Float) -> Size<Float> {
    if scale == 1.0 {
      return size
    }
    return Size<Float>.toCeiled(Size<Float>.scale(size, scale, scale))
  }

}

public typealias IntSize = Size<Int>
public typealias FloatSize = Size<Float>