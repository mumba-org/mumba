// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims

public class PDFBitmap {

  public var width: Int {
    return Int(_PDFBitmapGetWidth(reference))
  }

  public var height: Int {
    return Int(_PDFBitmapGetHeight(reference))
  }

  public var size: IntSize {
    var w: Int32 = 0, h: Int32 = 0
		_PDFBitmapGetSize(reference, &w, &h)
		return IntSize(width: Int(w), height: Int(h))    
  }

  public var stride: Int {
    return Int(_PDFBitmapGetStride(reference))
  }

  var reference: PDFBitmapRef

  public init(width: Int, height: Int) {
    reference = _PDFBitmapCreate(Int32(width), Int32(height))
  }

  public init(size: IntSize) {
    reference = _PDFBitmapCreate(Int32(size.width), Int32(size.height))
  }

  init(reference: PDFBitmapRef) {
    self.reference = reference
  }

  deinit {
    _PDFBitmapDestroy(reference)
  }

  // public func copy() -> Bitmap {
  //   return Bitmap(reference: _PDFBitmapCopy(reference))
  // }

  public func withBitmap(_ cb: (_: Bitmap) -> Void) {
    let copy = Bitmap(reference: _PDFBitmapCopy(reference))
    cb(copy)
  }

  public func withUnsafeBufferPointer<R>(
    _ body: (inout UnsafeBufferPointer<Void>) throws -> R
  ) rethrows -> R {
    let buf = _PDFBitmapGetConstBuffer(reference)
    let bufLen = height * stride
    var pb: UnsafeBufferPointer<Void> = UnsafeBufferPointer(start: buf!.bindMemory(to: Void.self, capacity: bufLen), count: bufLen)
    return try body(&pb)
  }

  public func withUnsafeMutableBufferPointer<R>(
    _ body: (inout UnsafeMutableBufferPointer<Void>) throws -> R
  ) rethrows -> R {
    let buf = _PDFBitmapGetBuffer(reference)
    let bufLen = height * stride
    var pb: UnsafeMutableBufferPointer<Void> = UnsafeMutableBufferPointer(start: buf!.bindMemory(to: Void.self, capacity: bufLen), count: bufLen)
    return try body(&pb)
  }

}