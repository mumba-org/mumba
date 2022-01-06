// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum ColorFormat : Int {
  // 4 bytes per pixel, in RGBA order in memory regardless of endianness.
  case RGBA = 0
  // 4 bytes per pixel, in BGRA order in memory regardless of endianness.
  // This is the default Windows DIB order.
  case BGRA = 1
  // SkBitmap format. For Encode() kN32_SkColorType (4 bytes per pixel) and
  // kAlpha_8_SkColorType (1 byte per pixel) formats are supported.
  // kAlpha_8_SkColorType gets encoded into a grayscale PNG treating alpha as
  // the color intensity. For Decode() kN32_SkColorType is always used.
  case SkBitmap = 2
}

public protocol ImageCodec {
  
  func decode(
    _ input: ContiguousArray<UInt8>, 
    format: ColorFormat, 
    output: inout UnsafeMutablePointer<UInt8>?,
    size: inout Int,
    width: inout Int, 
    height: inout Int) -> Bool

  func decode(
    _ input: UnsafePointer<UInt8>?,
    inputSize: Int,
    format: ColorFormat, 
    output: inout UnsafeMutablePointer<UInt8>?,
    size: inout Int,
    width: inout Int, 
    height: inout Int) -> Bool
  
  func decode(_ input: ContiguousArray<UInt8>) -> Bitmap?
  
  func decode(_ input: UnsafePointer<UInt8>?, size: Int) -> Bitmap?
}