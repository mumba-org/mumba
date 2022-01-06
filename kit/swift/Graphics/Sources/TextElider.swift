// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public let EllipsisUTF16: [UInt16] = [0x2026, 0]

public class StringSlicer {

    // The text to be sliced.
  var text: String
  // Ellipsis string to use.
  var ellipsis: String
  // If true, the middle of the string will be elided.
  var elideInMiddle: Bool
  // If true, the beginning of the string will be elided.
  var elideAtBeginning: Bool
  
  public init(text: String,
              ellipsis: String,
              elideInMiddle: Bool,
              elideAtBeginning: Bool) {
   self.text = text
   self.ellipsis = ellipsis
   self.elideAtBeginning = elideAtBeginning
   self.elideInMiddle = elideInMiddle
  }

 public func cutString(length: Int, insertEllipsis: Bool) -> String {
     
  let ellipsisText = insertEllipsis ? ellipsis : String()
  let textchars = text.characters

  if elideAtBeginning {
    //return ellipsisText + text.substr(findValidBoundaryBefore(text: text, index: text.characters.count - length))
    let index = text.index(text.startIndex, offsetBy: findValidBoundaryBefore(text: text, index: textchars.count - length))
    return ellipsisText + String(textchars.suffix(from: index))
  }

  if !elideInMiddle {
    //return text.substr(0, findValidBoundaryBefore(text: text, index: length)) + ellipsisText
    let index = text.index(text.startIndex, offsetBy: findValidBoundaryBefore(text: text, index: length))
    return String(textchars.prefix(upTo: index)) + ellipsisText
  }

  // We put the extra character, if any, before the cut.
  let halfLength = length / 2
  
  let prefixLength = text.index(text.startIndex, offsetBy: findValidBoundaryBefore(text: text, index: length - halfLength))  
  let suffixStart = text.index(text.startIndex, offsetBy: findValidBoundaryAfter(text: text, index: textchars.count - halfLength))
    
  return String(textchars.prefix(upTo: prefixLength)) + ellipsisText + String(textchars.suffix(from: suffixStart))
 }

}


public func elideRectangleText(text: String,
                               list:  FontList,
                               width: Float,
                               height: Int,
                               behavior: WordWrapBehavior,
                               lines: inout [String]) -> Int {
 assert(false)
 return 0
}

public func elideText(text: inout String,
                      list:  FontList,
                      width: Float,
                      behavior: ElideBehavior) -> String {
 assert(false)
 return text
}
