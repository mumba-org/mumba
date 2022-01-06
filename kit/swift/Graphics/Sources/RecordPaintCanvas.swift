// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public final class RecordPaintCanvas: PaintCanvas {
  
  public var saveCount: Int {
    return nativeCanvas.saveCount
  }
  
  public var localClipBounds: FloatRect? {
    return nativeCanvas.localClipBounds
  }

  public var deviceClipBounds: IntRect? {
    return nativeCanvas.deviceClipBounds
  }

  public var isClipEmpty: Bool {
    return nativeCanvas.isClipEmpty
  }

  public var isClipRect: Bool {
    return nativeCanvas.isClipRect
  }

  public var totalMatrix: Mat {
    return nativeCanvas.totalMatrix
  }

  public var nativeCanvas: SkiaCanvas {
    if let c = maybeCanvas {
      return c
    }
    let enclosingRect = IntRect.toFloored(r: recordingBounds)
    maybeCanvas = NoDrawSkiaCanvas(width: enclosingRect.width, height: enclosingRect.height)
    maybeCanvas!.clipRect(rect: recordingBounds, clip: ClipOp.intersect, antiAlias: false)
    return maybeCanvas!
  }

  let list: DisplayItemList
  var recordingBounds: FloatRect
  var maybeCanvas: NoDrawSkiaCanvas?

  public init(list: DisplayItemList, bounds: FloatRect) {
    self.list = list
    recordingBounds = bounds
  }

  public func flush() {}

  public func save() -> Int {
    list.push(DisplayItem.save)
    return nativeCanvas.save()
  }

  public func saveLayer(bounds: FloatRect?, flags paintFlags: PaintFlags?) -> Int {
    if let flags = paintFlags {
      if flags.isSimpleOpacity {
        let alpha = flags.color.a
        return saveLayerAlpha(bounds: bounds, alpha: alpha, preserveLcdTextRequests: false)
      }
      list.push(DisplayItem.saveLayer(bounds: bounds, flags: flags))
      let paint = flags.toPaint()
      return nativeCanvas.saveLayer(paint: paint, bounds: bounds)
    }
    list.push(DisplayItem.saveLayer(bounds: bounds, flags: paintFlags))
    return nativeCanvas.saveLayer(paint: nil, bounds: bounds)
  }
  
  public func saveLayerAlpha(bounds: FloatRect?, alpha: UInt8, preserveLcdTextRequests: Bool) -> Int {
    list.push(DisplayItem.saveLayerAlpha(bounds: bounds, alpha: alpha, preserveLcdTextRequests: preserveLcdTextRequests))
    return nativeCanvas.saveLayerAlpha(alpha: alpha, bounds: bounds)
  }
  
  public func restore() {
    list.push(DisplayItem.restore)
    nativeCanvas.restore()
  }
  
  public func restoreToCount(saveCount: Int) {
    if maybeCanvas == nil {
      return
    }

    let diff = nativeCanvas.saveCount - saveCount
    for _ in 0..<diff {
      restore()
    }
  }
  
  public func translate(x: Float, y: Float) {
    list.push(DisplayItem.translate(x: x, y: y))
    nativeCanvas.translate(x: x, y: y)
  }
  
  public func scale(x: Float, y: Float) {
    list.push(DisplayItem.scale(x: x, y: y))
    nativeCanvas.scale(x: x, y: y)
  }
  
  public func rotate(degrees: Float) {
    list.push(DisplayItem.rotate(degrees: degrees))
    nativeCanvas.rotate(radians: degrees)
  }
  
  public func concat(matrix: Mat) {
    list.push(DisplayItem.concat(matrix: matrix))
    nativeCanvas.concat(matrix: matrix)
  }
  
  public func setMatrix(_ matrix: Mat) {
    list.push(DisplayItem.setMatrix(matrix))
    nativeCanvas.setMatrix(matrix: matrix)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp, antiAlias: Bool) {
    list.push(DisplayItem.clipRect(rect, clip: clip, antiAlias: antiAlias))
    nativeCanvas.clipRect(rect: rect, clip: clip, antiAlias: antiAlias)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp) {
    clipRect(rect, clip: clip, antiAlias: false)
  }
 
  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool) {
    if rrect.isRect {
      clipRect(rrect.bounds, clip: clip, antiAlias: antiAlias)
      return
    }
    list.push(DisplayItem.clipRRect(rrect, clip: clip, antiAlias: antiAlias))
    nativeCanvas.clipRRect(rrect: rrect, clip: clip, antiAlias: antiAlias)
  }
  
  public func clipPath(_ path: Path, clip: ClipOp, antiAlias: Bool) {
    if !path.isInverseFillType && nativeCanvas.totalMatrix.rectStaysRect {
      // TODO(enne): do these cases happen? should the caller know that this isn't
      // a path?
      let rect = FloatRect()
      if path.isRect(rect) {
        clipRect(rect, clip: clip, antiAlias: antiAlias)
        return
      }

      var rrect = FloatRRect()

      if path.isOval(rect) {
        rrect.setOval(rect)
        clipRRect(rrect, clip: clip, antiAlias: antiAlias)
        return
      }

      if path.isRRect(rrect) {
        clipRRect(rrect, clip: clip, antiAlias: antiAlias)
        return
      }
    }

    list.push(DisplayItem.clipPath(path, clip: clip, antiAlias: antiAlias))
    nativeCanvas.clipPath(path: path, clip: clip, antiAlias: antiAlias)
  }
 
  public func clipPath(_ path: Path, clip: ClipOp) {
    clipPath(path, clip: clip, antiAlias: false)
  }

  public func drawColor(_ color: Color, mode: BlendMode) {
    list.push(DisplayItem.drawColor(color, blend: mode))
  }
 
  public func drawColor(_ color: Color) {
    list.push(DisplayItem.drawColor(color, blend: BlendMode.SrcOver))
  }
 
  public func clear(color: Color) {
    list.push(DisplayItem.drawColor(color, blend: BlendMode.Src))
  }

  public func clearRect(_ rect: IntRect) {
    let flags = PaintFlags()
    flags.color = Color.Black
    list.push(DisplayItem.drawIRect(rect, flags: flags))
  }

  public func clearRect(_ rect: FloatRect) {
    let flags = PaintFlags()
    flags.color = Color.Black
    list.push(DisplayItem.drawRect(rect, flags: flags))
  }
 
  public func drawLine(x0: Float, y0: Float, x1: Float, y1: Float, flags: PaintFlags) {
    let start = FloatPoint(x: x0, y: y0)
    let end = FloatPoint(x: x1, y: y1)
    list.push(DisplayItem.drawLine(start: start, end: end, flags: flags))
  }

  public func drawLine(start: FloatPoint, end: FloatPoint, flags: PaintFlags) {
    list.push(DisplayItem.drawLine(start: start, end: end, flags: flags))
  }
 
  public func drawRect(_ rect: FloatRect, flags: PaintFlags) {
    list.push(DisplayItem.drawRect(rect, flags: flags))
  }
 
  public func drawIRect(_ rect: IntRect, flags: PaintFlags) {
    list.push(DisplayItem.drawIRect(rect, flags: flags))
  }
 
  public func drawOval(_ oval: FloatRect, flags: PaintFlags) {
    list.push(DisplayItem.drawOval(oval, flags: flags))
  }
 
  public func drawRRect(_ rrect: FloatRRect, flags: PaintFlags) {
    list.push(DisplayItem.drawRRect(rrect, flags: flags))
  }
 
  public func drawDRRect(outer: FloatRRect, inner: FloatRRect, flags: PaintFlags) {
    if outer.isEmpty {
      return
    }
    if inner.isEmpty {
      drawRRect(outer, flags: flags)
      return
    }
    list.push(DisplayItem.drawDRRect(outer: outer, inner: inner, flags: flags))
  }
 
  public func drawRoundRect(_ rect: FloatRect, x: Float, y: Float, flags: PaintFlags) {
    if x > 0 && y > 0 {
      let rrect = FloatRRect(rect: rect, x: x, y: y)
      //rrect.setRectXY(rect, x, y)
      drawRRect(rrect, flags: flags)
    } else {
      drawRect(rect, flags: flags)
    }
  }
 
  public func drawPath(_ path: Path, flags: PaintFlags) {
    list.push(DisplayItem.drawPath(path, flags: flags))
  }
 
  // Note: originally it was cc::PaintImage
  // but PaintImage is supposed to be used
  // inside a scope.. so we should only create
  // a instance for PaintImage in the c++ side 
  // in the moment it will be used
  public func drawImage(_ image: ImageSkia, left: Float, top: Float, flags: PaintFlags?) {
    list.push(DisplayItem.drawImage(image, left: left, top: top, flags: flags))
  }
 
  // Note: originally it was cc::PaintImage
  public func drawImageRect(_ image: ImageSkia, src: FloatRect, dst: FloatRect, 
    constraint: SrcRectConstraint, flags: PaintFlags?) {
    list.push(DisplayItem.drawImageRect(image, src: src, dest: dst, constraint: constraint, flags: flags))
  }
 
  public func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float, flags: PaintFlags?) {
    if bitmap.drawsNothing {
      return
    }
    // TODO(khushalsagar): Remove this and have callers use PaintImages holding
    // bitmap-backed images, since they can maintain the PaintImage::Id.
    // drawImage(PaintImageBuilder.withDefault()
    //               .set_id(PaintImage.getNextId())
    //               .set_image(Image.makeFromBitmap(bitmap),
    //                         PaintImage.getNextContentId())
    //               .takePaintImage(),
    //           left, top, flags)
    let image = ImageSkia(bitmap: bitmap)
    drawImage(image, left: left, top: top, flags: flags)
  }
  
  public func drawTextBlob(_ blob: PaintTextBlob, x: Float, y: Float, flags: PaintFlags) {
    //print("RecordPaintCanvas.drawTextBlob")
    list.push(DisplayItem.drawTextBlob(blob, x: x, y: y, flags: flags))
  }
 
  public func drawPicture(record: PaintRecord) {
    list.push(DisplayItem.drawRecord(record))
  }
 
  public func recordCustomData(id: UInt32) {
    list.push(DisplayItem.customData(data: id))
  }
}
