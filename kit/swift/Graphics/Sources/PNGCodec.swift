// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct PNGCodec : ImageCodec {

  public init() {}
  
  // NOTE: the caller should dealocate the buffer with a call to free()
  public func decode(
    _ input: ContiguousArray<UInt8>,
    format: ColorFormat, 
    output: inout UnsafeMutablePointer<UInt8>?,
    size: inout Int,
    width: inout Int, 
    height: inout Int) -> Bool {
    var cw: CInt = 0
    var ch: CInt = 0
    var sz: CInt = 0
    input.withUnsafeBufferPointer {
      output = _PNGCodecDecodeAsRawBytes($0.baseAddress, CInt(input.count), CInt(format.rawValue), &sz, &cw, &ch)
    }
    if output != nil {
      width = Int(cw)
      height = Int(ch)
      size = Int(sz)
    }
    return output != nil
  }

  public func decode(
    _ input: UnsafePointer<UInt8>?,
    inputSize: Int,
    format: ColorFormat, 
    output: inout UnsafeMutablePointer<UInt8>?,
    size: inout Int,
    width: inout Int, 
    height: inout Int) -> Bool {
    
    var cw: CInt = 0
    var ch: CInt = 0
    var sz: CInt = 0

    output = _PNGCodecDecodeAsRawBytes(input, CInt(inputSize), CInt(format.rawValue), &sz, &cw, &ch)
    
    if output != nil {
      width = Int(cw)
      height = Int(ch)
      size = Int(sz)
    }
    return output != nil
  }

  public func decode(_ input: ContiguousArray<UInt8>) -> Bitmap? {
    var bitmapRef: BitmapRef?
    input.withUnsafeBufferPointer {
      bitmapRef = _PNGCodecDecodeAsBitmap($0.baseAddress, CInt(input.count))
    }
    return bitmapRef != nil ? Bitmap(reference: bitmapRef!) : nil
  }

  public func decode(_ input: UnsafePointer<UInt8>?, size: Int) -> Bitmap? {
    let bitmapRef = _PNGCodecDecodeAsBitmap(input, CInt(size))
    return bitmapRef != nil ? Bitmap(reference: bitmapRef!) : nil
  }

  public func decodeImage(_ input: UnsafePointer<UInt8>?, size: Int) -> ImageSkia? {
    let imageRef = _PNGCodecDecodeAsImage(input, CInt(size))
    return imageRef != nil ? ImageSkia(reference: imageRef!) : nil
  }

}