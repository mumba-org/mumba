// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

//public enum RepresentationType {
  //  case Cocoa
  //  case CocoaTouch
  //  case Skia
  //  case PNG
  //}

public class ImageFilter {

}

public protocol Image {
  //var type: Image.RepresentationType { get }
  var bitmap: Bitmap { get }
  var scale: Float { get set}
  var width: Float { get }
  var height: Float { get }
  var pixelWidth: Float { get }
  var pixelHeight: Float { get }
  var size: FloatSize { get }
  var isEmpty: Bool { get }
  var isNull: Bool { get }

  func hasBitmapFor(scale: Float) -> Bool
  func getBitmapFor(scale: Float) -> Bitmap?
  func toImageSkia() -> ImageSkia
}

public protocol ImageSource {
  var hasRepresentationAtAllScales: Bool { get }
  func getBitmapFor(scale: Float) -> Bitmap
}

extension ImageSource {
  
  public var hasRepresentationAtAllScales: Bool {
    return false
  }

}

public class ImageSkia : Image {

  public var width: Float {
    return size.width
  }
  
  public var height: Float {
    return size.height
  }

  public var pixelWidth: Float {
    return bitmap.width
  }
  
  public var pixelHeight: Float {
    return bitmap.height
  }
  
  public private(set) var size: FloatSize  
  
  public var bitmap: Bitmap {
    if _bitmap == nil {
      _bitmap = Bitmap(reference: _ImageGetBitmap(reference))
    }
    return _bitmap!
  }

  public var isEmpty: Bool {
    if let bm = _bitmap {
      return bm.isEmpty
    }
    return _ImageIsEmpty(reference) == 0 ? true : false
  }

  public var isNull: Bool {
    return bitmap.isNull
  }

  public var scale: Float

  public var reference: ImageRef

  var _bitmap: Bitmap?


  public init() {
    reference = _ImageCreate(0.0, 0.0)
    size = FloatSize(width: 0, height: 0.0)
    scale = 1.0
  }

  public init(scale: Float) {
    reference = _ImageCreate(0.0, 0.0)
    size = FloatSize(width: 0.0, height: 0.0)
    self.scale = scale
  }

  public init(scale: Float, width: Float, height: Float) {
    reference = _ImageCreate(width, height)
    size = FloatSize(width: width, height: height)
    self.scale = scale
  }

  public init(scale: Float, size: FloatSize) {
    reference = _ImageCreate(size.width, size.height)
    self.size = size
    self.scale = scale
  }

  public init(bitmap: Bitmap) {
    reference = _ImageCreateFromBitmap(bitmap.reference)
    size = FloatSize(width: bitmap.width, height: bitmap.height)
    _bitmap = bitmap
    scale = 1.0
  }

  public init(source: ImageSource, size: FloatSize) {
    scale = 1.0
    let bitmap = source.getBitmapFor(scale: scale)
    reference = _ImageCreateFromBitmap(bitmap.reference)
    _bitmap = bitmap
    self.size = size
  }

  public init(bytes: UnsafeRawPointer?, width: Int, height: Int, premultiplied: Bool, originClean: Bool, alpha: AlphaType, colorSpace: ColorSpace) {
    scale = 1.0
    reference = _ImageCreateFromBytes(
      bytes, 
      UInt32(width), 
      UInt32(height), 
      Int32(premultiplied ? 1 : 0), 
      Int32(originClean ? 1 : 0),
      Int32(alpha.rawValue),
      colorSpace.primaries.rawValue,
      colorSpace.transfer.rawValue,
      colorSpace.matrix.rawValue,
      colorSpace.range.rawValue,
      colorSpace.iccProfileId)
    size = FloatSize(width: Float(width), height: Float(height))
  }

  public convenience init(bitmap: Bitmap, scale: Float) {
    self.init(bitmap: bitmap)
    self.scale = scale
  }

  public init(reference: ImageRef) {
    self.reference = reference
    var w: Float = 0.0, h: Float = 0.0
    _ImageGetSize(reference, &w, &h)
    size = FloatSize(width: w, height: h)
    scale = 1.0
  }

  deinit {
    _ImageDestroy(reference)
    _bitmap = nil
  }

  // from the original: getRepresentation(scaleFactor).bitmap()
  //public func asBitmap(scale: Float) -> Bitmap? {
  //  return Bitmap(reference: _ImageGetBitmap(reference))
  //}

  public func hasBitmapFor(scale: Float) -> Bool {
    if scale == self.scale {
      return true
    }
    return false
  }

  public func getBitmapFor(scale: Float) -> Bitmap? {
    if scale == self.scale {
      return bitmap
    }
    return nil
  }

  public func backedBySameObjectAs(other: ImageSkia) -> Bool {
    return other.bitmap === self.bitmap
  }

  public func toImageSkia() -> ImageSkia {
    return self
  }

}