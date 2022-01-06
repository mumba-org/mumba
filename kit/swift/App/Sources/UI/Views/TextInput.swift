// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum TextInputType : Int {
   case None = 0
   case Text
   case Password
   case Search
   case Email
   case Number
   case Telephone
   case Url
   case Date
   case DateTime
   case DateTimeLocal
   case Month
   case Time
   case Week
   case TextArea
   case ContentEditable
   case DateTimeField
}

public enum TextInputMode : Int {
  case Default = 0
  case Verbatim
  case Latin
  case LatinName
  case LatinProse
  case FullWidthLatin
  case Kana
  case Katakana
  case Numeric
  case Tel
  case Email
  case Url
}

public enum TextInputFlags: Int {
  case Invalid                  = -1
  case None                     = 0
  case AutocompleteOn           = 1
  case AutocompleteOff          = 2
  case AutocorrectOn            = 4
  case AutocorrectOff           = 8
  case SpellcheckOn             = 16
  case SpellcheckOff            = 32
  case AutocapitalizeNone       = 64
  case AutocapitalizeCharacters = 128
  case AutocapitalizeWords      = 256
  case AutocapitalizeSentences  = 512
}

public struct TextInputState {
  public var type: TextInputType = .None
  public var mode: TextInputMode = .Default 
  public var flags: TextInputFlags = .None
  public var value: String = String()
  public var selectionStart: Int = 0
  public var selectionEnd: Int = 0
  public var compositionStart: Int = -1
  public var compositionEnd: Int = -1 
  public var canComposeInline: Bool = true
  public var showImeIfNeeded: Bool = false
  public var replyToRequest: Bool = false
}

@inlinable
public func ==(left: TextInputState, right: TextInputState) -> Bool {
  return 
    (left.type == right.type) && 
    (left.mode == right.mode) && 
    (left.flags == right.flags) &&
    (left.value == right.value) &&
    (left.selectionStart == right.selectionStart) &&
    (left.selectionEnd == right.selectionEnd) &&
    (left.compositionStart == right.compositionStart) &&
    (left.compositionEnd == right.compositionEnd) &&
    (left.canComposeInline == right.canComposeInline) &&
    (left.showImeIfNeeded == right.showImeIfNeeded) &&
    (left.replyToRequest == right.replyToRequest)
}

@inlinable
public func !=(left: TextInputState, right: TextInputState) -> Bool {
  return !(left == right)
}