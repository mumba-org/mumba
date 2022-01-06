// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

// Its bad that this need to be a class, but we need to use it as a reference
// to the callback.. without using the callback trick, we would need to 
// pre-allocate a good ammount of memory before passing the pointer to be filled
// by the C api, which would be a much worse solution

// Also: textContent might be big so passing it by value as a inner element of a struct 
// might become expensive (but maybe the Swift compiler just moves it around.. idk)

public class WebSurroundingText {

  public var isEmpty: Bool {
    return textContent.count == 0
  }
  
  public var textContent: String = String()
  public var startOffsetInTextContent: UInt32 = 0
  public var endOffsetInTextContent: UInt32 = 0

  public init(frame: WebLocalFrame, maxLength: UInt32) {
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _WebLocalFrameGetWebSurroundingText(frame.reference, CInt(maxLength), selfPtr, {
        (handle: UnsafeMutableRawPointer?, contentBuf: UnsafePointer<UInt16>?, contentLen: CInt, start: CInt, end: CInt) in

        let this = unsafeBitCast(handle, to: WebSurroundingText.self)
        if contentBuf != nil {
          this.textContent = String(decodingCString: contentBuf!, as: UTF16.self)
          this.startOffsetInTextContent = UInt32(start)
          this.endOffsetInTextContent = UInt32(end)
        }
    })
  }

}