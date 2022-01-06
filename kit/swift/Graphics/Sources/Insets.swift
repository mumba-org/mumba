// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol InsetsProtocol {
  
  associatedtype Element: Numeric

  var top: Element { get set }
  var left: Element { get set }
  var bottom: Element { get set }
  var right: Element { get set }
  var width: Element { get }
  var height: Element { get }
  var isEmpty: Bool { get }

  mutating func set(top: Element, left: Element, bottom: Element, right: Element)
}

public struct Insets<T: Numeric> : InsetsProtocol {
  
  public typealias Element = T

  public var width: T {
    return left + right
  }

  public var height: T {
    return top + bottom
  }

  public var isEmpty: Bool { 
    return width == 0 && height == 0
  }

  public var top: T
  public var left: T
  public var bottom: T
  public var right: T

  static public func += (left: inout Insets<T>, right: Insets<T>) {
    left = left + right
  }

  public init() {
    top = 0
    left = 0
    bottom = 0
    right = 0
  }

  public init(top: T, left: T, bottom: T, right: T) {
    self.top = top
    self.left = left
    self.bottom = bottom
    self.right = right
  }

  public init(all: T) {
    self.top = all
    self.left = all
    self.bottom = all
    self.right = all
  }

  public init(vertical: T, horizontal: T) {
    self.top = vertical
    self.left = horizontal
    self.bottom = vertical
    self.right = horizontal
  }

  public mutating func set(top: T, left: T, bottom: T, right: T) {
    self.top = top
    self.left = left
    self.bottom = bottom
    self.right = right
  }

}

extension Insets where T == Int {

  public init(_ insets: Insets<Float>) {
    self.top = Int(insets.top)
    self.left = Int(insets.left)
    self.bottom = Int(insets.bottom)
    self.right = Int(insets.right)
  }
  
  public func scale(_ s: Float) -> Insets<T> {
    return scale(s, s)
  }

  public func scale(_ xscale: Float, _ yscale: Float) -> Insets<T> {
    return Insets<T>(top: top * Int(yscale), 
                     left: left * Int(xscale), 
                     bottom: bottom * Int(yscale),
                     right: right * Int(xscale))
  }

}

extension Insets where T == Float {

  public init(_ insets: Insets<Int>) {
    self.top = Float(insets.top)
    self.left = Float(insets.left)
    self.bottom = Float(insets.bottom)
    self.right = Float(insets.right)
  }

  public func scale(_ scale: Float) -> Insets<T> {
    return Insets<T>(top: scale * top, 
                     left: scale * left, 
                     bottom: scale * bottom,
                     right: scale * right)
  }
  
}

public prefix func -(i: Insets<Int>) -> Insets<Int> {
  return Insets<Int>(top:-i.top, left: -i.left, bottom: -i.bottom, right: -i.right)
}

public prefix func -(i: Insets<Float>) -> Insets<Float> {
  return Insets<Float>(top:-i.top, left: -i.left, bottom: -i.bottom, right: -i.right)
}

public func +<T: Numeric>(left: Insets<T>, right: Insets<T>) -> Insets<T> {
  return Insets<T>(top: left.top + right.top, left: left.left + right.left, bottom: left.bottom + right.bottom, right: left.right + right.right)
}

public typealias IntInsets = Insets<Int>
public typealias FloatInsets = Insets<Float>