// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum TextDirection : Int {
  case Unknown = 0
  case RightToLeft = 1
  case LeftToRight = 2
}

// Should provide only static functions
public final class i18n {

  // TODO: swiftfy this
  public static let RightToLeftMark: UInt16 = 0x200f
  public static let LeftToRightMark: UInt16 = 0x200e


  public static func initialize() -> Bool {
    return false
  }

  public static func isRTL() -> Bool {
    return false
  }

  public static func getFirstStrongCharacterDirection(text: String) -> TextDirection {
    // TODO: implement it!

    //const UChar* string = text.c_str();
    //size_t length = text.length();
    //size_t position = 0;
    //while (position < length) {
    //  UChar32 character;
    //  size_t next_position = position;
    //  U16_NEXT(string, next_position, length, character);
    //  TextDirection direction = GetCharacterDirection(character);
    //  if (direction != UNKNOWN_DIRECTION)
    //    return direction;
    //  position = next_position;
    //}
    return .LeftToRight
  }

  public static func getLastStrongCharacterDirection(text: String) -> TextDirection {
    return .LeftToRight
  }

}