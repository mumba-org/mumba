// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO: this has exactly the same functionality as TextRange does..
// so we need to substitute TextRange for this!

import Graphics

public enum TextSpanType : Int {
  case Composition
  case Suggestion
  case MisspellingSuggestion
}

public enum TextSpanThickness : Int {
  case None
  case Thin
  case Thick
}

public struct TextSpan {
  
 public var type: TextSpanType = TextSpanType.Composition
 public var start: Int = 0
 public var end: Int = 0
 public var underlineColor: Color = Color.Transparent
 public var thickness: TextSpanThickness = TextSpanThickness.None
 public var backgroundColor: Color = Color.Transparent
 public var suggestionHighlightColor: Color = Color.Transparent
 public var suggestions: [String] = []
 public var lenght: Int { return end - start }
 public var isEmpty: Bool { return lenght == 0 }

 public static func fromBounds(start: Int, end: Int) -> TextSpan {
   // FIXIT: this is probably not the intended implementation
   return TextSpan(start: start, end: end)
 }

 public init() {}

 public init(start: Int, end: Int) {
   self.start = start
   self.end = end
 }

 public init(type: TextSpanType, start: Int, end: Int) {
   self.type = type
   self.start = start
   self.end = end
 }

 public func contains(position p: Int) -> Bool {
   return (p - start) < lenght
 }

 public func contains(span: TextSpan) -> Bool {
   return span.start >= start && span.end <= end
 }

 public func overlapsWith(span: TextSpan) -> Bool {
  let overlapStart = max(start, span.start)
  let overlapEnd = min(end, span.end)

  return overlapStart < overlapEnd
 }

 public func overlap(span: TextSpan) -> TextSpan? {
  let overlapStart = max(start, span.start)
  let overlapEnd = min(end, span.end)

  return overlapStart < overlapEnd 
    ? TextSpan.fromBounds(start: overlapStart, end: overlapEnd)
    : nil
 }

 public func intersectsWith(position p: Int) -> Bool {
  return (p - start) <= lenght
 }

 public func intersection(span: TextSpan) -> TextSpan? {
  let intersectStart = max(start, span.start)
  let intersectEnd = min(end, span.end)

  return intersectStart <= intersectEnd
    ? TextSpan.fromBounds(start: intersectStart, end: intersectEnd)
    : nil
 }

}

extension TextSpan : Equatable {
 
 public static func ==(lhs: TextSpan, rhs: TextSpan) -> Bool {
  return lhs.start == rhs.start && lhs.end == rhs.end
 }

}