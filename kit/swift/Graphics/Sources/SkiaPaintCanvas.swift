// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class SkiaPaintCanvas : PaintCanvas {

  struct ContextFlushes {
    var enable: Bool = false
  }

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
    if let canvas = _nativeCanvas {
      return canvas
    }
    _nativeCanvas = SkiaCanvas()
    return _nativeCanvas!
  }

  public var imageProvider: ImageProvider?
  var contextFlushes: ContextFlushes = ContextFlushes()
  var _nativeCanvas: SkiaCanvas?

  public init() {
    self._nativeCanvas = SkiaCanvas()
  }

  public init(canvas: SkiaCanvas?) {
    self._nativeCanvas = canvas
  }

  public init(bitmap: Bitmap) {
    self._nativeCanvas = SkiaCanvas(bitmap: bitmap)
  }
  
  // not implemented
  public init(canvas: SkiaCanvas?,
              colorSpace: ColorSpace) {
   assert(false)
  }

  public func flush() {
    nativeCanvas.flush()
  }

  public func save() -> Int {
    return nativeCanvas.save()
  }

  public func saveLayer(bounds: FloatRect?, flags paintFlags: PaintFlags?) -> Int {
    if let flags = paintFlags {
      let paint = flags.toPaint()
      return nativeCanvas.saveLayer(paint: paint, bounds: bounds)
    }
   
    return nativeCanvas.saveLayer(paint: nil, bounds: bounds)
  }
  
  public func saveLayerAlpha(bounds: FloatRect?, alpha: UInt8, preserveLcdTextRequests: Bool) -> Int {
    if preserveLcdTextRequests {
      let paint = Paint()
      paint.alpha = alpha
      return nativeCanvas.saveLayerPreserveLCDTextRequests(paint: paint, bounds: bounds)
    }
    return nativeCanvas.saveLayerAlpha(alpha: alpha, bounds: bounds)
  }
  
  public func restore() {
    nativeCanvas.restore()
  }
  
  public func restoreToCount(saveCount: Int) {
    nativeCanvas.restoreTo(count: saveCount)
  }
  
  public func translate(x: Float, y: Float) {
    nativeCanvas.translate(x: x, y: y)
  }
  
  public func scale(x: Float, y: Float) {
    nativeCanvas.scale(x: x, y: y)
  }
  
  public func rotate(degrees: Float) {
    nativeCanvas.rotate(radians: degrees)
  }
  
  public func concat(matrix: Mat) {
    nativeCanvas.concat(matrix: matrix)
  }
  
  public func setMatrix(_ matrix: Mat) {
    nativeCanvas.setMatrix(matrix: matrix)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp, antiAlias: Bool) {
    nativeCanvas.clipRect(rect: rect, clip: clip, antiAlias: antiAlias)
  }
  
  public func clipRect(_ rect: FloatRect, clip: ClipOp) {
    clipRect(rect, clip: clip, antiAlias: false)
  }
 
  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool) {
    nativeCanvas.clipRRect(rrect: rrect, clip: clip, antiAlias: antiAlias)
  }
  
  public func clipPath(_ path: Path, clip: ClipOp, antiAlias: Bool) {
    nativeCanvas.clipPath(path: path, clip: clip, antiAlias: antiAlias)
  }
 
  public func clipPath(_ path: Path, clip: ClipOp) {
    clipPath(path, clip: clip, antiAlias: false)
  }

  public func drawColor(_ color: Color, mode: BlendMode) {
    nativeCanvas.drawColor(color: color, transferMode: mode)
  }
 
  public func drawColor(_ color: Color) {
    nativeCanvas.drawColor(color: color, transferMode: .SrcOver)
  }
 
  public func clear(color: Color) {
    nativeCanvas.clear(color: color)
  }

  public func clearRect(_ rect: IntRect) {
    nativeCanvas.clearRect(rect)
  }

  public func clearRect(_ rect: FloatRect) {
    nativeCanvas.clearRect(rect)
  }
 
  public func drawLine(x0: Float, y0: Float, x1: Float, y1: Float, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawLine(p1: FloatPoint(x: x0, y: y0), p2: FloatPoint(x: x1, y: y1), paint: paint)
    flushAfterDrawIfNeeded()
  }

  public func drawLine(start: FloatPoint, end: FloatPoint, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawLine(p1: start, p2: end, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawRect(_ rect: FloatRect, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawRect(rect: rect, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawIRect(_ rect: IntRect, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawIRect(rect: rect, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawOval(_ oval: FloatRect, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawOval(rect: oval, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawRRect(_ rrect: FloatRRect, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawRRect(rrect: rrect, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawDRRect(outer: FloatRRect, inner: FloatRRect, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawDRRect(outer: outer, inner: inner, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawRoundRect(_ rect: FloatRect, x: Float, y: Float, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawRoundRect(rect: rect, x: x, y: y, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawPath(_ path: Path, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawPath(path: path, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawImage(_ image: ImageSkia, left: Float, top: Float, flags: PaintFlags?) {
    let params = PlaybackParams(imageProvider: imageProvider, originalCtm: nativeCanvas.totalMatrix)
    let drawImageOp = DisplayItem.drawImage(image, left: left, top: top, flags: nil)
    
    DisplayItem.rasterWithFlags(item: drawImageOp, flags: flags, canvas: nativeCanvas, params: params)
  
    flushAfterDrawIfNeeded()
  }
 
  public func drawImageRect(_ image: ImageSkia, src: FloatRect, dst: FloatRect, 
    constraint: SrcRectConstraint, flags: PaintFlags?) {
    
    let params = PlaybackParams(imageProvider: imageProvider, originalCtm: nativeCanvas.totalMatrix)
    let drawImageRectOp = DisplayItem.drawImageRect(image, src: src, dest: dst, constraint: constraint, flags: flags)
    
    DisplayItem.rasterWithFlags(item: drawImageRectOp, flags: flags, canvas: nativeCanvas, params: params)

    flushAfterDrawIfNeeded()
  }
 
  public func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float, flags: PaintFlags?) {
    if let paint = flags?.toPaint() {
      nativeCanvas.drawBitmap(bitmap: bitmap, left: left, top: top, paint: paint)
    } else {
      nativeCanvas.drawBitmap(bitmap: bitmap, left: left, top: top, paint: nil)
    }
    
    flushAfterDrawIfNeeded()
  }
  
  public func drawTextBlob(_ blob: PaintTextBlob, x: Float, y: Float, flags: PaintFlags) {
    let paint = flags.toPaint()
    nativeCanvas.drawTextBlob(text: blob, x: x, y: y, paint: paint)
    flushAfterDrawIfNeeded()
  }
 
  public func drawPicture(record: PaintRecord) {
    // TODO: implement
    let didDrawOpCb: PlaybackParams.didDrawOpCallback? = nil//contextFlushes.enable ? SkiaPaintCanvas.flushAfterDrawIfNeeded : nil
    
    let params = PlaybackParams(
      imageProvider: imageProvider,
      originalCtm: nativeCanvas.totalMatrix, 
      customCallback: nil, 
      didDrawOpCallback: didDrawOpCb)
    record.playback(canvas: nativeCanvas, params: params)
  }
 
  public func recordCustomData(id: UInt32) {}

  func flushAfterDrawIfNeeded() {
    //  TODO: implement
  }

}