// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class BiDiLineIterator {

  var reference: UBiDiRef?

  public init() {}

  public func open(text: String, direction: TextDirection) -> Bool {
    // NOTE: this should be temporary
    var textUTF16Array = ContiguousArray(text.utf16)
    return textUTF16Array.withUnsafeMutableBufferPointer {
      let ref = _ICUBiDiOpen($0.baseAddress, Int32(text.utf16.count), Int32(direction.rawValue))
      if ref != nil {
        reference = ref
        return true
      } else {
        return false
      }
    }
  }

  public func countRuns() -> Int {
    if let bidiRef = reference {
      return Int(_ICUBiDiCountRuns(bidiRef))
    }
    return 0
  }

  public func getVisualRun(index: Int, start: inout Int, length: inout Int) -> UBiDiDirection {
    if let bidiRef = reference {
        var starti32: Int32 = 0
        var leni32: Int32 = 0 
        let dir = _ICUBiDiGetVisualRun(bidiRef, Int32(index), &starti32, &leni32)
        return UBiDiDirection(rawValue: Int(dir))!
    }
    return .LTR
  }

  public func getLogicalRun(start: Int, end: inout Int, level: inout UBiDiLevel) {
    if let bidiRef = reference {
      var endi32: Int32 = 0
      _ICUBiDiGetLogicalRun(bidiRef, Int32(start), &endi32, &level)
      end = Int(endi32)
    }
  }

}