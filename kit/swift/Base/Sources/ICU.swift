// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public typealias UBiDiLevel = UInt8

public typealias UBlockCode = Int
public typealias UErrorCode = Int
public typealias UScriptCode = Int32

public let UScriptInvalidCode: UScriptCode = -1
public let UScriptCommon: UScriptCode = 0
public let UScriptInherited: UScriptCode = 1

public let UBlockGeometricShapes: UBlockCode = 54
public let UBlockMiscellaneousSymbols: UBlockCode = 55

public enum UBiDiDirection : Int {
  case LTR = 0
  case RTL
  case Mixed
  case Neutral
}

// ??
public class ICUStringCharacterIterator {
  
  public var currentIndex: Int {
    return 0
  }

  public init(text: String) {

  }

  public func setIndex32(_ i: Int) {

  }

}

// TODO: see if we dont have a more native way to do this
// by using the swift string unicode features

public class UTF16CharIterator {

  public private(set) var arrayPos: Int32
  public private(set) var charPos: Int32
  
  public var character: UInt16 {
    return char
  }
  
  public var isEnd: Bool {
     return arrayPos == len
  }
  
  var glyphs: [UInt16]
  var len: Int32
  var nextPos: Int32
  var char: UInt16

  public init(string: String) {
    // apparently thats the only way we can use 
    // to access the utf16 glyphs from the string
    glyphs = []
    glyphs.reserveCapacity(string.utf16.count)

    for glyph in string.utf16 {
      glyphs.append(glyph)
    }

    len = Int32(string.utf16.count)
    arrayPos = 0
    nextPos = 0
    charPos = 0
    char = 0    
    //_ICUU16SetCPStart(self.string, 0, len)

    if len > 0 {
      readChar()
    }

  }

  // warn: we are not reseting/using start
  public init(string: String, start: Int, length: Int) {
    
    glyphs = []
    glyphs.reserveCapacity(string.utf16.count)

    for glyph in string.utf16 {
      glyphs.append(glyph)
    }

    len = Int32(length)
    arrayPos = 0
    nextPos = 0
    charPos = 0
    char = 0

    //_ICUU16SetCPStart(self.string, Int32(start), len)
    
    if len > 0 {
      readChar()
    }

  }

  public func advance() -> Bool {
    if arrayPos >= len {
      return false
    }

    arrayPos = nextPos
    charPos += 1
    
    if nextPos < len {
      readChar()
    }

    return true
  }
  
  func readChar() {
    char = glyphs.withUnsafeBufferPointer { buf -> UInt16 in 
      return _ICUU16Next(buf.baseAddress, nextPos, len)
    }
    nextPos += 1
  }

}