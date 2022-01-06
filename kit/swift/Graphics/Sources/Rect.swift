// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

public protocol RectProtocol : Equatable {
  
  associatedtype Element: SignedNumeric, Comparable

  var width: Element { get set }
  var height: Element { get set }
  var x: Element { get set }
  var y: Element { get set }
  var left: Element { get set }
  var right: Element { get set }
  var bottom: Element { get set }
  var top: Element { get set }
  var topRight: Point<Element> { get }
  var bottomLeft: Point<Element> { get }
  var bottomRight: Point<Element> { get }
  var offsetFromOrigin: Vec2<Element> { get }
  var isEmpty: Bool { get }
  var centerPoint: Point<Element> { get }
  var origin: Point<Element> { get }
  var size: Size<Element> { get }

  func contains(rect r: Self) -> Bool
  func contains(point p: Point<Element>) -> Bool
  func contains(x px: Element, y py: Element) -> Bool
  func intersects(rect b: Self) -> Bool
  func intersects(x: Element, y: Element, w: Element, h: Element) -> Bool
  func makeSorted() -> Self
  mutating func inset(left: Element, top: Element, right: Element, bottom: Element)
  mutating func inset(horizontal: Element, vertical: Element)
  mutating func inset(insets: Insets<Element>)
  //mutating func clampToCenteredSize(size: Size<Element>)
  //mutating func adjustToFit(rect r: Self)
  mutating func offset(horizontal h: Element, vertical v: Element)
  mutating func offset(distance v: Vec2<Element>)
  mutating func intersect(rect b: Self)
  mutating func union(other: Self)
}

public struct Rect<T: SignedNumeric> : RectProtocol where T : Comparable {

  public typealias Element = T

  @inlinable
  public static func intersectRects(a: Rect<T>, b: Rect<T>) -> Rect<T> {
    var result = Rect<T>(a)
    result.intersect(rect: b)
    return result
  }

  public var width: T {
    get {
      return size.width
    }
    set {
      size.width = newValue
    }
  }

  public var height: T {
    get {
      return size.height
    }
    set {
      size.height = newValue
    }
  }

  public var x: T {
    get {
      return origin.x
    }
    set {
      origin.x = newValue
    }
  }

  public var y: T {
    get {
      return origin.y
    }
    set {
      origin.y = newValue
    }
  }

  public var left: T {
    get {
      return x
    }
    set {
      x = newValue
    }
  }

  public var right: T {
    get {
      return x + width
    }
    set {
     // TODO: check if this is ok 
     size.width = newValue - x
    }
  }

  public var bottom: T {
    get {
      return y + height
    }
    set {
     // TODO: check if this is ok
     size.height = newValue - y
    }
  }

  public var top: T {
    get {
      return y
    }
    set {
     y = newValue
    }
  }

  public var topRight: Point<T> { 
    return Point<T>(x: right, y: y) 
  }
  
  public var bottomLeft: Point<T> { 
    return Point<T>(x: x, y: bottom) 
  }
  
  public var bottomRight: Point<T> { 
    return Point<T>(x: right, y: bottom) 
  }

  public var offsetFromOrigin: Vec2<T> {
    return Vec2<T>(x: x, y: y)
  }

  public var isEmpty: Bool {
    return size.isEmpty
  }

  public var centerPoint: Point<T> {
    assert(false)
    return Point<T>()
  }

  public var origin: Point<T>
  public var size: Size<T>

  public init() {
    self.size = Size<T>()
    self.origin = Point<T>()
  }

  public init(x: T, y: T, width: T, height: T) {
    self.size = Size<T>(width: width, height: height)
    self.origin = Point<T>(x: x, y: y)
  }

  public init(left: T, top: T, right: T, bottom: T) {
    self.size = Size<T>(width: right - left, height: bottom - top)
    self.origin = Point<T>(x: left, y: top)
  }

  public init(size: Size<T>) {
    self.size = size
    origin = Point<T>()
  }

  public init(_ rect: Rect<T>) {
    self.size = rect.size
    self.origin = rect.origin
  }

  public init(origin: Point<T>, size: Size<T>) {
    self.size = size
    self.origin = origin
  }

  public init(width: T, height: T) {
    size = Size<T>(width: width, height: height)
    origin = Point<T>()
  }

  @inlinable
  public mutating func set(x: T, y: T, width: T, height: T) {
    self.size = Size<T>(width: width, height: height)
    self.origin = Point<T>(x: x, y: y)
  }

  @inlinable
  public mutating func set(size: Size<T>, origin: Point<T>) {
    self.size = size
    self.origin = origin
  }

  @inlinable
  public func contains(rect r: Rect<T>) -> Bool {
    return r.x >= x && r.right <= right && r.y >= y && r.bottom <= bottom
  }

  @inlinable
  public func contains(point p: Point<T>) -> Bool {
    return contains(x: p.x, y: p.y)
  }

  @inlinable
  public func contains(x px: T, y py: T) -> Bool {
    return (px >= x) && (px < right) && (py >= y) && (py < bottom)
  }

  @inlinable
  public func makeSorted() -> Rect<T> {
    return Rect<T>(
      left: min(self.left, self.right), 
      top: min(self.top, self.bottom),
      right: max(self.left, self.right), 
      bottom: max(self.top, self.bottom)
    )
  }

  @inlinable
  public mutating func inset(left: T, top: T, right: T, bottom: T) {
    origin = origin + Vec2<T>(x: left, y: top)
    width = max(width - left - right, 0)
    height = max(height - top - bottom, 0)
  }

  @inlinable
  public mutating func inset(horizontal: T, vertical: T) {
    inset(left: horizontal, top: vertical, right: horizontal, bottom: vertical)
  }

  @inlinable
  public mutating func inset(insets: Insets<T>) {
    inset(left: insets.left, top: insets.top, right: insets.right, bottom: insets.bottom)
  }

  @inlinable
  public func intersects(rect b: Rect<T>) -> Bool {
    return !(isEmpty || b.isEmpty || b.x >= right ||
           b.right <= x || b.y >= bottom || b.bottom <= y)
  }

  @inlinable
  public func intersects(x: T, y: T, w: T, h: T) -> Bool {
    return intersects(rect: Rect<T>(x: x, y: y, width: w, height: h))
  }
 
  @inlinable
  public mutating func offset(horizontal h: T, vertical v: T) {
    origin = origin + Vec2<T>(x: h, y: v)
  }

  @inlinable
  public mutating func offset(distance v: Vec2<T>) {
    offset(horizontal: v.x, vertical: v.y)
  }

  @inlinable
  public mutating func intersect(rect b: Rect<T>) {
    if isEmpty || b.isEmpty {
      (x, y, width, height) = (0, 0, 0, 0)
      return
    }

    var rx = max(x, b.x)
    var ry = max(y, b.y)
    var rr = min(right, b.right)
    var rb = min(bottom, b.bottom)

    if rx >= rr || ry >= rb {
      (rx, ry, rr, rb) = (0, 0, 0, 0)  // non-intersecting
    }

    (x, y, width, height) = (rx, ry, rr - rx, rb - ry)
  }

  public mutating func union(other: Rect<T>) {
    assert(false)
  }

}

extension Rect where T == Int {
  
  //@inlinable
  //public static func convertToPixel(scaleFactor: Float, rectInDip: Rect<Float>) -> Rect<Int> {
  //  return Rect<Int>.toEnclosingRect(rect:
  //    Rect<Float>(origin: Point<Float>.scale(p: Point<Float>(point: rectInDip.origin), scaleFactor),
  //          size: Size<Float>.scale(Size<Float>(size: rectInDip.size), scaleFactor)))
  //}

  @inlinable
  public static func convertToPixel(scaleFactor: Float, rectInDip: Rect<Int>) -> Rect<Int> {
    return Rect<Int>.toEnclosingRect(rect:
      Rect<Float>(origin: Point<Float>.scale(p: Point<Float>(rectInDip.origin), scaleFactor),
            size: Size<Float>.scale(Size<Float>(rectInDip.size), scaleFactor)))
  }

  @inlinable
  public static func toEnclosingRect(rect: Rect<Float>) -> Rect<Int> {
    let minX = floorf(rect.x)
    let minY = floorf(rect.y)
    let maxX = rect.right
    let maxY = rect.bottom

    let width: T = rect.width == 0 ? 0 : max(Int(ceilf(ceilf(maxX) - minX)), 0)
    let height: T = rect.height == 0 ? 0 : max(Int(ceilf(ceilf(maxY) - minY)), 0)
    return Rect<Int>(x: Int(minX), y: Int(minY), width: width, height: height)
  }


  @inlinable
  public static func toRoundedRect(_ rect: Rect<Int>, scale: Float) -> Rect<Int> {
    return Rect.toRoundedRect(rect, xscale: scale, yscale: scale)
  }

  @inlinable
  public static func toRoundedRect(_ rect: Rect<Int>, xscale: Float , yscale: Float) -> Rect<Int> {
    if xscale == 1.0 && yscale == 1.0 {
      return rect
    }

    let x = Int(round(Float(rect.x) * xscale))
    let y = Int(round(Float(rect.y) * yscale))
    let r = rect.width == 0
                ? x
                : Int(round(Float(rect.right) * xscale))
    let b = rect.height == 0
                ? y
                : Int(round(Float(rect.bottom) * yscale))

    return Rect<Int>(x: x, y: y, width: r - x, height: b - y)
  }

  @inlinable
  public static func toFloored(r: Rect<Float>) -> Rect<T> {
    return Rect<T>(x: Int(floorf(r.x)), y: Int(floorf(r.y)), width: Int(floorf(r.width)), height: Int(floorf(r.height)))
  }

  public var centerPoint: Point<T> {
    return Point<T>(x: x + width / 2, y: y + height / 2)
  }

  public init(_ rect: Rect<Float>) {
    self.size = IntSize(rect.size)
    self.origin = IntPoint(rect.origin)
  }

  @inlinable
  public mutating func adjustToFit(rect r: Rect<T>) {
    var newX: T = x
    var newY: T = y
    var newWidth: T = width
    var newHeight: T = height
    adjustAlongAxis(r.x, r.width, &newX, &newWidth)
    adjustAlongAxis(r.y, r.height, &newY, &newHeight)
    set(x: newX, y: newY, width: newWidth, height: newHeight)
  }

  @inlinable
  public mutating func clampToCenteredSize(size: Size<T>) {
    let newWidth: Int = min(width, size.width)
    let newHeight: Int = min(height, size.height)
    let newX: Int = x + (width - newWidth) / 2
    let newY: Int = y + (height - newHeight) / 2
    set(x: newX, y: newY, width: newWidth, height: newHeight)
  }
  
  // public mutating func union(other: Rect<T>) {
  //   assert(false)
  // }


}

extension Rect where T == Float {
  
  public var centerPoint: Point<T> {
    return Point<T>(x: x + width / 2.0, y: y + height / 2.0)
  }

  @inlinable
  public static func floor(rect r: Rect<Float>) -> Rect<T> {
    return Rect<T>(x: floorf(r.x), y: floorf(r.y), width: floorf(r.width), height: floorf(r.height))
  }

  @inlinable
  public static func scale(rect r: Rect<T>, x xscale: Float, y yscale: Float) -> Rect<T> {
    return Rect<T>(x: r.x * xscale, y: r.y * yscale,
        width: r.width * xscale, height: r.height * yscale)
  }

  @inlinable
  public static func scale(rect r: Rect<T>, factor scale: Float) -> Rect<T> {
    return Rect<T>.scale(rect: r, x: scale, y: scale)
  }

  @inlinable
  public static func scale(rect r: Rect<Int>, factor scale: Float) -> Rect<T> {
    return Rect<T>.scale(rect: Rect<T>(r), x: scale, y: scale)
  }

  public init(_ rect: Rect<Int>) {
    self.size = FloatSize(rect.size)
    self.origin = FloatPoint(rect.origin)
  }

  @inlinable
  public mutating func scale(by scaleFactor: Float) {
    origin.x = origin.x * scaleFactor
    origin.y = origin.y * scaleFactor
    size.width = size.width * scaleFactor
    size.height = size.height * scaleFactor
  }

  @inlinable 
  public func scaleToEnclosingRect(rect: Rect<Int>,
                                   scaleX: Float,
                                   scaleY: Float) -> Rect<Int> {
    if scaleX == 1.0 &&  scaleY == 1.0 {
      return rect
    }

    let x = Int(floorf(Float(rect.x) * scaleX))
    let y = Int(floorf(Float(rect.y) * scaleY))
    let r = rect.width == 0 ? x : Int(ceilf(Float(rect.right) * scaleX))
    let b = rect.height == 0 ? y : Int(ceilf(Float(rect.bottom) * scaleY))
    return Rect<Int>(x: x, y: y, width: r - x, height: b - y)
  }

  @inlinable
  public mutating func adjustToFit(rect r: Rect<T>) {
    var newX: T = x
    var newY: T = y
    var newWidth: T = width
    var newHeight: T = height
    adjustAlongAxis(r.x, r.width, &newX, &newWidth)
    adjustAlongAxis(r.y, r.height, &newY, &newHeight)
    set(x: newX, y: newY, width: newWidth, height: newHeight)
  }

  @inlinable
  public mutating func clampToCenteredSize(size: Size<T>) {
    let newWidth: Float = min(width, size.width)
    let newHeight: Float = min(height, size.height)
    let newX: Float = x + (width - newWidth) / 2
    let newY: Float = y + (height - newHeight) / 2
    set(x: newX, y: newY, width: newWidth, height: newHeight)
  }

  // @inlinable
  // public func contains(rect r: Rect<T>) -> Bool {
  //   return r.x >= x && r.right <= right && r.y >= y && r.bottom <= bottom
  // }

  // @inlinable
  // public func contains(point p: Point<T>) -> Bool {
  //   return contains(x: p.x, y: p.y)
  // }

  // @inlinable
  // public func contains(x px: T, y py: T) -> Bool {
  //   return (px >= x) && (px < right) && (py >= y) && (py < bottom)
  // }

  // @inlinable
  // public mutating func inset(left: T, top: T, right: T, bottom: T) {
  //   origin = origin + Vec2<T>(x: left, y: top)
  //   width = max(width - left - right, 0)
  //   height = max(height - top - bottom, 0)
  // }

  // @inlinable
  // public mutating func inset(horizontal: T, vertical: T) {
  //   inset(left: horizontal, top: vertical, right: horizontal, bottom: vertical)
  // }

  // @inlinable
  // public mutating func inset(insets: Insets<T>) {
  //   inset(left: insets.left, top: insets.top, right: insets.right, bottom: insets.bottom)
  // }

  // @inlinable
  // public mutating func clampToCenteredSize(size: Size<T>) {
  //   let newWidth = min(width, size.width)
  //   let newHeight = min(height, size.height)
  //   let newX = x + (width - newWidth) / 2
  //   let newY = y + (height - newHeight) / 2
  //   set(x: newX, y: newY, width: newWidth, height: newHeight)
  // }

  // @inlinable
  // public mutating func adjustToFit(rect r: Rect<T>) {
  //   var newX = x
  //   var newY = y
  //   var newWidth = width
  //   var newHeight = height
  //   adjustAlongAxis(r.x, r.width, &newX, &newWidth)
  //   adjustAlongAxis(r.y, r.height, &newY, &newHeight)
  //   set(x: newX, y: newY, width: newWidth, height: newHeight)
  // }
  
  // @inlinable
  // public func intersects(rect b: Rect<T>) -> Bool {
  //   return !(isEmpty || b.isEmpty || b.x >= right ||
  //          b.right <= x || b.y >= bottom || b.bottom <= y)
  // }

  // @inlinable
  // public func intersects(x: T, y: T, w: T, h: T) -> Bool {
  //   return intersects(rect: Rect<T>(x: x, y: y, width: w, height: h))
  // }

  // @inlinable
  // public mutating func offset(horizontal h: T, vertical v: T) {
  //   origin = origin + Vec2<T>(x: h, y: v)
  // }
 
  // @inlinable
  // public mutating func offset(distance v: Vec2<T>) {
  //   offset(horizontal: v.x, vertical: v.y)
  // }

  // @inlinable
  // public mutating func intersect(rect b: Rect<T>) {
  //   if isEmpty || b.isEmpty {
  //     (x, y, width, height) = (0, 0, 0, 0)
  //     return
  //   }

  //   var rx = max(x, b.x)
  //   var ry = max(y, b.y)
  //   var rr = min(right, b.right)
  //   var rb = min(bottom, b.bottom)

  //   if rx >= rr || ry >= rb {
  //     (rx, ry, rr, rb) = (0, 0, 0, 0)  // non-intersecting
  //   }

  //   (x, y, width, height) = (rx, ry, rr - rx, rb - ry)
  // }
  
  // public mutating func union(other: Rect<T>) {
  //   assert(false)
  // }
}

@inlinable
internal func adjustAlongAxis(_ dstOrigin: Int, _ dstSize: Int, _ origin: inout Int, _ size: inout Int) {
  size = min(dstSize, size)
  if origin < dstOrigin {
    origin = dstOrigin
  } else {
    origin = min(dstOrigin + dstSize, origin + size) - size
  }
}

@inlinable
internal func adjustAlongAxis(_ dstOrigin: Float, _ dstSize: Float, _ origin: inout Float, _ size: inout Float) {
  size = min(dstSize, size)
  if origin < dstOrigin {
    origin = dstOrigin
  } else {
    origin = min(dstOrigin + dstSize, origin + size) - size
  }
}


@inlinable
public func ==<T: SignedNumeric>(left: Rect<T>, right: Rect<T>) -> Bool {
  return (left.origin == right.origin) && (left.size == right.size)
}

@inlinable
public func !=<T: SignedNumeric>(left: Rect<T>, right: Rect<T>) -> Bool {
  return !(left == right)
}

@inlinable
public func +<T: SignedNumeric>(left: Rect<T>, right: Vec2<T>) -> Rect<T> {
  return Rect<T>(x:left.x + right.x , y: left.y + right.y, width: left.width, height: left.height)
}

@inlinable
public func -<T: SignedNumeric>(left: Rect<T>, right: Vec2<T>) -> Rect<T> {
  return Rect(x: left.x - right.x , y: left.y - right.y, width: left.width, height: left.height)
}

@inlinable
public func +=<T: SignedNumeric>(left: Rect<T>, offset: Vec2<T>) -> Rect<T> {
  var origin = left.origin
  origin = origin + offset
  return Rect<T>(origin: origin, size: left.size)
}

@inlinable
public func -=<T: SignedNumeric>(left: Rect<T>, offset: Vec2<T>) -> Rect<T> {
  var origin = left.origin
  origin = origin - offset
  return Rect<T>(origin: origin, size: left.size)
}

@inlinable
public func lerp(_ left: Rect<Float>, _ right: Rect<Float>, by t: Float) -> Rect<Float> {
  return Rect<Float>(
      left: lerp(left.left, right.left, t),
      top: lerp(left.top, right.top, t),
      right: lerp(left.right, right.right, t),
      bottom: lerp(left.bottom, right.bottom, t)
    )
}

@inlinable
public func lerp(_ left: Rect<Int>, _ right: Rect<Int>, by t: Float) -> Rect<Int> {
  return Rect<Int>(
      left: lerp(left.left, right.left, t),
      top: lerp(left.top, right.top, t),
      right: lerp(left.right, right.right, t),
      bottom: lerp(left.bottom, right.bottom, t)
    )
}

public func scaleToEnclosingRect(rect: Rect<Int>,
                                 xScale: Float,
                                 yScale: Float) -> Rect<Int> {
  if xScale == 1.0 && yScale == 1.0 {
    return rect
  }
  let x = Int(floor(Float(rect.x) * xScale))
  let y = Int(floor(Float(rect.y) * yScale))
  let w = Int(ceil(Float(rect.width) * xScale))
  let h = Int(ceil(Float(rect.height) * yScale))
  return Rect<Int>(x: x, y: y, width: w, height: h)
}

public func unionRects(_ a: Rect<Int>, _ b: Rect<Int>) -> Rect<Int> {
  var result = a
  result.union(other: b)
  return result
}

public typealias IntRect = Rect<Int>
public typealias FloatRect = Rect<Float>