// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum AlphaType : Int {
  case Unknown
  case Opaque
  case Premul
  case Unpremul
}

public class Bitmap {

  public var width: Float {
    return _BitmapGetWidth(reference)
  }

  public var height: Float {
    return _BitmapGetHeight(reference)
  }

  public var size: FloatSize {
    var size = FloatSize()
		_BitmapGetSize(reference, &size.width, &size.height)
		return size
  }

  public var isImmutable: Bool {
    get {
      return _BitmapIsImmutable(reference) == 0 ? false : true
    }
    set {
      if newValue && !isImmutable {
        _BitmapSetImmutable(reference)
      }
    }
  }

  public var isEmpty: Bool {
    return _BitmapIsEmpty(reference) == 0 ? false : true
  }

  public var isDrawable: Bool {
    return _BitmapIsDrawable(reference) == 0 ? false : true
  }

  public var isNull: Bool {
    return _BitmapIsNull(reference) == 0 ? false : true
  }

  public var drawsNothing: Bool {
    return isEmpty || isNull
  }

  // PDF module need to access this directly
  public var reference: BitmapRef

  public init() {
    reference = _BitmapCreate(0, 0)
  }

  public init(width: Float, height: Float) {
    reference = _BitmapCreate(width, height)
  }

  public init(size: FloatSize) {
    reference = _BitmapCreate(size.width, size.height)
  }

  public init(reference: BitmapRef) {
    self.reference = reference
  }

  deinit {
    //_BitmapDestroy(reference)
  }

  public func getColor(at p: FloatPoint) -> Color {
    return getColorAt(x: p.x, y: p.y)
  }
  // TODO: oportunidade de se criar um subscript bm.color[0, 0]
  public func getColorAt(x: Float, y: Float) -> Color {
    let colorCode = _BitmapGetColorAt(reference, x, y)
    return Color(Int(colorCode))
  }

  public func allocatePixels(width: Float, height: Float) {
    _BitmapAllocatePixels(reference, width, height)
  }

  public func allocatePixels(width: Float, height: Float, alpha: AlphaType) {
    _BitmapAllocatePixelsAlpha(reference, width, height, Int32(alpha.rawValue))
  }

  public func erase(color: Color) {
    _BitmapEraseARGB(reference, color.a, color.r, color.g, color.b) 
  }

  public func erase(a: UInt8, r: UInt8, g: UInt8, b: UInt8) {
    _BitmapEraseARGB(reference, a, r, g, b)
  }

  public func extractSubset(subset s: FloatRect) -> Bitmap {
   let ptr = _BitmapExtractSubset(reference, s.x, s.y, s.width, s.height)
   return Bitmap(reference: ptr!)
  }

  //public func lockPixels() {
  //  _BitmapLockPixels(reference)
  //}

  //public func unlockPixels() {
  //  _BitmapUnlockPixels(reference)
  //}
  
  //withUnsafeMutableBufferPointer<R>(
  //  _ body: (UnsafeMutableBufferPointer<Element>) throws -> R
  //) rethrows -> R {
  //  _sanityCheck(
  //    _isNative || count == 0,
 //     "Array is bridging an opaque NSArray; can't get a pointer to the elements"
 //   )
 //   defer { _fixLifetime(self) }
 //   return try body(UnsafeMutableBufferPointer(
 //     start: firstElementAddressIfContiguous, count: count))
 // }

  // TODO: We are forcing the 32 bit version of the pixels
  //public func withUnsafeMutablePixelBuffer(
  //  _ body: (UnsafeMutableBufferPointer<UInt32>)) {
    //var buf = UnsafeMutablePointer<UInt32>()
  
  public func withUnsafeMutablePixelBuffer<R>(
    _ body: (inout UnsafeMutableBufferPointer<UInt32>) throws -> R
  ) rethrows -> R {
    var size: Int = 0
    let buf = _BitmapGetBufferAt(reference, 0, 0, &size)
    var pb: UnsafeMutableBufferPointer<UInt32> = UnsafeMutableBufferPointer(start: buf!.bindMemory(to: UInt32.self, capacity: size), count: size)
    return try body(&pb)
  }

  public func getPixels() -> UnsafeMutableRawPointer? {
    var size: Int = 0
    return _BitmapGetBufferAt(reference, 0, 0, &size)
  }

  //public func withUnsafeBufferPointer() {

  //}

}

extension Bitmap {
  
  public static func createButtonBackground(color: Color, image: Bitmap, mask: Bitmap) -> Bitmap {
    let ref = _BitmapCreateButtonBackground(color.a, color.r, color.g, color.b, image.reference, mask.reference)
    return Bitmap(reference: ref!)
  }

  public static func createBlendedBitmap(first: Bitmap, second: Bitmap, alpha: Double) -> Bitmap {
    let ref = _BitmapCreateBlendedBitmap(first.reference, second.reference, alpha)
    return Bitmap(reference: ref!)
  }

}
