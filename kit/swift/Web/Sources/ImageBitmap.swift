// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class ImageData {

  public var size: IntSize {
    var w: CInt = 0
    var h: CInt = 0
    _WebImageDataGetSize(reference, &w, &h)
    return IntSize(width: Int(w), height: Int(h))
  }

  public var width: Int {
    return Int(_WebImageDataGetWidth(reference))
  }

  public var height: Int {
    return Int(_WebImageDataGetHeight(reference))
  }

  public var imageDataStorageFormat: ImageDataStorageFormat {
    return ImageDataStorageFormat(rawValue: Int(_WebImageDataGetImageDataStorageFormat(reference)))!
  }

  public var data: Uint8ClampedArray {
    let ref = _WebImageDataGetData(reference)
    return Uint8ClampedArray(reference: ref!)
  }
  
  var ownedReference: WebImageDataOwnedRef?
  var reference: WebImageDataRef

  public init(size: IntSize, settings: ImageDataColorSettings) {
    ownedReference = _WebImageDataCreateSize(CInt(size.width), CInt(size.height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))
    reference = _WebImageDataFromOwned(ownedReference!)
  }

  public init(bytes: Uint8ClampedArray, size: IntSize, settings: ImageDataColorSettings) {
    ownedReference = _WebImageDataCreateUint8Array(bytes.reference, CInt(size.width), CInt(size.height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))
    reference = _WebImageDataFromOwned(ownedReference!)
  }

  public init(bytes: UnsafePointer<UInt8>?, bytesSize: Int, size: IntSize, settings: ImageDataColorSettings) {
    ownedReference = _WebImageDataCreateBytes(bytes, CInt(bytesSize), CInt(size.width), CInt(size.height), CInt(settings.colorSpace.rawValue), CInt(settings.storageFormat.rawValue))
    reference = _WebImageDataFromOwned(ownedReference!)
  }

  init(reference: WebImageDataRef) {
    self.reference = reference
  }

  init(owned: WebImageDataOwnedRef) {
    self.ownedReference = owned
    reference = _WebImageDataFromOwned(ownedReference!)
  }

  deinit {
    if ownedReference != nil {
      _WebImageDataDestroy(ownedReference!)
    }
  }

  public func cropRect(rect: IntRect, flipY: Bool = false) -> ImageData {
    return ImageData(reference: _WebImageDataCropRect(reference, CInt(rect.x), CInt(rect.y), flipY ? 1 : 0)!)
  }

}

public class ImageBitmap {
  
  // ??
  public var paintImageForCurrentFrame: Image? {
    return nil
  }

  public var width: Int {
    return Int(_WebImageBitmapGetWidth(reference))
  }

  public var height: Int {
    return Int(_WebImageBitmapGetHeight(reference))
  }
  
  public var size: IntSize {
    var w: CInt = 0
    var h: CInt = 0
    _WebImageBitmapGetSize(reference, &w, &h)
    return IntSize(width: Int(w), height: Int(h))
  }

  public var isNeutered: Bool {
    return _WebImageBitmapIsNeutered(reference) != 0
  }

  public var originClean: Bool {
    return _WebImageBitmapIsOriginClean(reference) != 0
  }

  public var isPremultiplied: Bool {
    return _WebImageBitmapIsPremultiplied(reference) != 0
  }
  
  var ownedReference: WebImageBitmapOwnedRef?
  var reference: WebImageBitmapRef

  public init(image: ImageSkia) {
    ownedReference = _WebImageBitmapCreateFromImage(image.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(image: HtmlImageElement, document: WebDocument, rect: IntRect?) {
    if let r = rect {
      ownedReference = _WebImageBitmapCreateFromHTMLImageElementWithRect(image.reference, document.reference, CInt(r.width), CInt(r.height))
      reference = _WebImageBitmapFromOwned(ownedReference!)
      return
    }
    ownedReference = _WebImageBitmapCreateFromHTMLImageElement(image.reference, document.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(svg: SvgImageElement, document: WebDocument, rect: IntRect?) {
    if let r = rect {
      ownedReference = _WebImageBitmapCreateFromSVGImageElementWithRect(svg.reference, document.reference, CInt(r.width), CInt(r.height))
      reference = _WebImageBitmapFromOwned(ownedReference!)
      return
    }
    ownedReference = _WebImageBitmapCreateFromSVGImageElement(svg.reference, document.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(video: HtmlVideoElement, document: WebDocument, rect: IntRect?) {
    if let r = rect {
      ownedReference = _WebImageBitmapCreateFromHTMLVideoElementWithRect(video.reference, document.reference, CInt(r.width), CInt(r.height))
      reference = _WebImageBitmapFromOwned(ownedReference!)
      return
    }
    ownedReference = _WebImageBitmapCreateFromHTMLVideoElement(video.reference, document.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(canvas: HtmlCanvasElement, rect: IntRect?) {
    if let r = rect {
      ownedReference = _WebImageBitmapCreateFromHTMLCanvasElementWithRect(canvas.reference, CInt(r.width), CInt(r.height))
      reference = _WebImageBitmapFromOwned(ownedReference!)
      return
    }
    ownedReference = _WebImageBitmapCreateFromHTMLCanvasElement(canvas.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(canvas: OffscreenCanvas, rect: IntRect?) {
    if let r = rect {
      ownedReference = _WebImageBitmapCreateFromOffscreenCanvasWithRect(canvas.reference, CInt(r.width), CInt(r.height))
      reference = _WebImageBitmapFromOwned(ownedReference!)
      return
    }
    ownedReference = _WebImageBitmapCreateFromOffscreenCanvas(canvas.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(data: ImageData, rect: IntRect?) {
    if let r = rect {
      ownedReference = _WebImageBitmapCreateFromImageDataWithRect(data.reference, CInt(r.width), CInt(r.height))
      reference = _WebImageBitmapFromOwned(ownedReference!)
      return
    }
    ownedReference = _WebImageBitmapCreateFromImageData(data.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(bitmap: ImageBitmap, rect: IntRect?) {
    if let r = rect {
      ownedReference = _WebImageBitmapCreateFromImageBitmapWithRect(bitmap.reference, CInt(r.width), CInt(r.height))
      reference = _WebImageBitmapFromOwned(ownedReference!)
      return
    }
    ownedReference = _WebImageBitmapCreateFromImageBitmap(bitmap.reference)
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(bytes: Uint8ClampedArray, 
              rect: IntRect, 
              isPremultiplied: Bool,
              isOriginClean: Bool,
              pixelFormat: CanvasPixelFormat,
              colorSpace: CanvasColorSpace) {
    ownedReference = _WebImageBitmapCreateFromUint8Array(
      bytes.reference, 
      CInt(rect.width), 
      CInt(rect.height), 
      isPremultiplied ? 1 : 0, 
      isOriginClean ? 1 : 0,
      CInt(pixelFormat.rawValue),
      CInt(colorSpace.rawValue))
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  public init(bytes: UnsafePointer<UInt8>?, 
              byteSize: Int, 
              rect: IntRect, 
              isPremultiplied: Bool,
              isOriginClean: Bool,
              pixelFormat: CanvasPixelFormat,
              colorSpace: CanvasColorSpace) {
    ownedReference = _WebImageBitmapCreateFromBytes(
      bytes, 
      CInt(byteSize),
      CInt(rect.width), 
      CInt(rect.height), 
      isPremultiplied ? 1 : 0, 
      isOriginClean ? 1 : 0,
      CInt(pixelFormat.rawValue),
      CInt(colorSpace.rawValue))
    reference = _WebImageBitmapFromOwned(ownedReference!)
  }

  init(reference: WebImageBitmapRef) {
    self.reference = reference
  }

  deinit {
    if ownedReference != nil {
      _WebImageBitmapDestroy(ownedReference!)
    }
  }

  // FIXME: we need a new type to represent the inner WTF::Uint8Array
  //        instead of the DOMArray which is GC'ed
  //        find a name for it that doesnt make it so confusing

  // public func copyBitmapData() -> Uint8Array {
  //   return Uint8Array(reference: _WebImageBitmapCopyBitmapData(reference)!)
  // }

  // public func copyBitmapData(disposition: AlphaDisposition,
  //                            colorType: DataColorType = .RGBAColorType) -> Uint8Array {
  //   return Uint8Array(reference: _WebImageBitmapCopyBitmapDataWithOptions(reference, CInt(disposition.rawValue), CInt(colorType.rawValue))!)
  // }

  public func close() {
    _WebImageBitmapClose(reference)
  }
}