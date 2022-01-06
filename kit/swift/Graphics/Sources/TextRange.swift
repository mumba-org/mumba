// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

public protocol CharacterRange : Equatable {
  associatedtype Element

  var start: Element { get set }
  var end: Element { get set }
  var isValid: Bool { get }
  var length: Element { get }
  var isReversed: Bool { get }
  var isEmpty: Bool { get }
  // to avoid collision with glibc min/max
  var minimum: Element { get }
  var maximum: Element { get }

  func intersects(range: Self) -> Bool
  func contains(range: Self) -> Bool
  func intersect(range: Self) -> Self
}

extension CharacterRange where Element : Comparable { 
  public static func ==(left: Self, right: Self) -> Bool {
    return left.start == right.start && left.end == right.end 
  }
}

extension CharacterRange where Element : Comparable {
  public var isReversed: Bool { return start > end }
  public var isEmpty: Bool { return start == end }
}

public struct TextRange : CharacterRange {
  
  public static let InvalidRange: TextRange = TextRange(start: Int.min, end: Int.max)
  
  public var start: Int
  public var end: Int
  public var minimum: Int { 
    return min(start, end) 
  }

  public var maximum: Int { 
    return max(start, end) 
  }

  public var isValid: Bool {
    return self != TextRange.InvalidRange
  }

  public var isNull: Bool {
    return end == 0 && start == 0
  }

  public var length: Int {
    let length = end - start
    return length >= 0 ? length : -length
  }

  public init() {
    start = 0
    end = 0
  }

  public init(start: Int, end: Int) {
    self.start = start
    self.end = end
  }

  public init(pos: Int) {
    self.start = pos
    self.end = pos
  }

  public init(range: CountableClosedRange<Int>) {
    self.start = range.first!
    self.end = range.last!
  }

  public func intersects(range: TextRange) -> Bool {
    return isValid && range.isValid &&
      !(range.maximum < minimum || range.minimum >= maximum)
  }
  
  public func contains(range: TextRange) -> Bool {
    return isValid && range.isValid &&
      minimum <= range.minimum && range.maximum <= maximum
  }
  
  public func intersect(range: TextRange) -> TextRange {
    let lmin = max(minimum, range.minimum)
    let lmax = min(maximum, range.maximum)

    if lmin >= lmax {  // No intersection.
      return TextRange.InvalidRange
    }

    return TextRange(start: lmin, end: lmax)
  }
}

public struct TextRangef : CharacterRange {
  
  public static let InvalidRange: TextRangef = TextRangef(start: .nan, end: .nan)
  
  public var start: Float
  public var end: Float
  public var minimum: Float { 
    return min(start, end) 
  }
  public var maximum: Float { 
    return max(start, end) 
  }
  public var isValid: Bool {
    return self != TextRangef.InvalidRange
  }

  public var length: Float {
    let length = end - start
    return length >= 0 ? length : -length
  }

  public var floored: TextRange {
    let rstart = start > 0.0 ? Int(floor(start)) : 0
    let rend = end > 0.0 ? Int(floor(end)) : 0
    return TextRange(start: rstart, end: rend)
  }
  
  public var ceiled: TextRange {
    let rstart = start > 0.0 ? Int(ceil(start)) : 0
    let rend = end > 0.0 ? Int(ceil(end)) : 0
    return TextRange(start: rstart, end: rend)
  }
  
  public var rounded: TextRange {
    let rstart = start > 0.0 ? Int(floor(start + 0.5)) : 0
    let rend = end > 0.0 ? Int(floor(end + 0.5)) : 0
    return TextRange(start: rstart, end: rend)
  }

  public init() {
    start = 0.0
    end = 0.0
  }

  public init(start: Float, end: Float) {
    self.start = start
    self.end = end
  }

  public init(from: TextRange) {
    self.start = Float(from.start)
    self.end = Float(from.end)
  }

  public init(pos: Float) {
    self.start = pos
    self.end = pos
  }

  public func intersects(range: TextRangef) -> Bool {
    return isValid && range.isValid &&
      !(range.maximum < minimum || range.minimum >= maximum)
  }
  
  public func contains(range: TextRangef) -> Bool {
    return isValid && range.isValid &&
      minimum <= range.minimum && range.maximum <= maximum
  }
  
  public func intersect(range: TextRangef) -> TextRangef {
    let lmin = max(minimum, range.minimum)
    let lmax = min(maximum, range.maximum)

    if lmin >= lmax {  // No intersection.
      return TextRangef.InvalidRange
    }

    return TextRangef(start: lmin, end: lmax)
  }

  public func intersect(range: TextRange) -> TextRangef {
    let rangef = TextRangef(from: range)
    return intersect(range: rangef)
  }

}