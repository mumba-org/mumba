// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum WebTextInputType : Int {
  case None = 0
  case Text = 1
  case Password = 2
  case Search = 3
  case Email = 4
  case Number = 5
  case Telephone = 6
  case URL = 7
  case Date = 8
  case DateTime = 9
  case TimeLocal = 10
  case Month = 11
  case Time = 12
  case Week = 13
  case TextArea = 14
  case ContentEditable = 15
  case DateTimeField = 16
}

public enum WebTextInputMode : Int {
  case Default = 0
  case None = 1
  case Text = 2
  case Tel = 3
  case Url = 4
  case Email = 5
  case Numeric = 6
  case Decimal = 7
  case Search = 8
}

public struct WebTextInputInfo {
  public var type: WebTextInputType = .None
  public var flags: Int = 0
  public var value: String = String()
  public var selectionStart: Int = 0
  public var selectionEnd: Int = 0
  public var compositionStart: Int = 0
  public var compositionEnd: Int = 0
  public var inputMode: WebTextInputMode = .Default

  public init() {}
  public init(type: WebTextInputType,
    flags: Int,
    value: String,
    selectionStart: Int,
    selectionEnd: Int,
    compositionStart: Int,
    compositionEnd: Int,
    inputMode: WebTextInputMode) {
    self.flags = flags
    self.value = value
    self.selectionStart = selectionStart
    self.selectionEnd = selectionEnd
    self.compositionStart = compositionStart
    self.compositionEnd = compositionEnd
    self.inputMode = inputMode
  }
}

public enum WebImeTextSpanThickness : Int {
  case none
  case thin
  case thick
}

public enum WebImeTextSpanType : Int {
  // Creates a composition marker.
  case composition
  // Creates a suggestion marker that isn't cleared after the user picks a
  // replacement.
  case suggestion
  // Creates a suggestion marker that is cleared after the user picks a
  // replacement, and will be ignored if added to an element with spell
  // checking disabled.
  case misspellingSuggestion
}

public struct WebImeTextSpan {

  public var type: WebImeTextSpanType
  public var startOffset: Int
  public var endOffset: Int
  public var thickness: WebImeTextSpanThickness
  public var underlineColor: Color = Color()
  public var backgroundColor: Color
  public var suggestionHighlightColor: Color
  public var suggestions: [String]

  public init() {
    type = .composition
    startOffset = 0
    endOffset = 0
    thickness = WebImeTextSpanThickness.thin
    backgroundColor = Color()
    suggestionHighlightColor = Color()
    suggestions = []
  }

  public init(
      type: WebImeTextSpanType,
      start: Int,
      end: Int,
      thickness: WebImeTextSpanThickness,
      background: Color,
      suggestionHighlight: Color = Color(),
      suggestions: [String] = []) {
    self.type = type
    self.startOffset = start
    self.endOffset = end
    self.thickness = thickness
    self.backgroundColor = background
    self.suggestionHighlightColor = suggestionHighlight
    self.suggestions = suggestions
  }
}

@inlinable
public func ==(left: WebTextInputInfo, right: WebTextInputInfo) -> Bool {
  return 
    (left.type == right.type) && 
    (left.flags == right.flags) &&
    (left.value == right.value) &&
    (left.selectionStart == right.selectionStart) &&
    (left.selectionEnd == right.selectionEnd) &&
    (left.compositionStart == right.compositionStart) &&
    (left.compositionEnd == right.compositionEnd) &&
    (left.inputMode == right.inputMode)
}

@inlinable
public func !=(left: WebTextInputInfo, right: WebTextInputInfo) -> Bool {
  return !(left == right)
}