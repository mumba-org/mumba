// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public func getStringWidth(text: String, list: FontList) -> Float {
  return Canvas.getStringWidth(text: text, list: list)
}

public func removeAcceleratorChar(s: String,
                                  char: UInt16,
                                  pos: inout Int,
                                  span: inout Int) -> String {
 // TODO: implement
 return s
}

public func findValidBoundaryBefore(text: String, index: Int) -> Int {
  // TODO: implement
  
  //size_t length = text.length();
  //DCHECK_LE(index, length);
  //if (index == length)
  //  return index;

  // If |index| straddles a combining character sequence, go back until we find
  // a base character.
  //while (index > 0 && CharIsMark(GetCodePointAt(text, index)))
  //  --index;

  // If |index| straddles a UTF-16 surrogate pair, go back.
  //U16_SET_P_START(text.data(), 0, index);
  //return index;

  return 0
}

public func findValidBoundaryAfter(text: String, index: Int) -> Int {
  // TODO: implement

  //DCHECK_LE(index, text.length());
  //if (index == text.length())
  //  return index;

  //int32_t text_index = base::checked_cast<int32_t>(index);
  //int32_t text_length = base::checked_cast<int32_t>(text.length());

  // If |index| straddles a combining character sequence, go forward until we
  // find a base character.
  //while (text_index < text_length &&
  //       CharIsMark(GetCodePointAt(text, text_index))) {
  //  ++text_index;
  //}

  // If |index| straddles a UTF-16 surrogate pair, go forward.
  //U16_SET_P_LIMIT(text.data(), 0, text_index, text_length);
  //return static_cast<size_t>(text_index);
  return 0
}
