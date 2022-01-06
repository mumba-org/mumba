// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol PaintCanvas : class {

  var saveCount: Int { get }
  var localClipBounds: FloatRect? { get }
  var deviceClipBounds: IntRect? { get }
  var isClipEmpty: Bool { get }
  var isClipRect: Bool { get }
  var totalMatrix: Mat { get }
  var fillStyle: String { get set }
  // FIXME
  var nativeCanvas: SkiaCanvas { get }

  func flush()
  func save() -> Int
  func saveLayer(bounds: FloatRect?, flags: PaintFlags?) -> Int
  func saveLayerAlpha(bounds: FloatRect?, alpha: UInt8, preserveLcdTextRequests: Bool) -> Int
  func restore()
  func restoreToCount(saveCount: Int)
  func translate(x: Float, y: Float)
  func scale(x: Float, y: Float)
  func rotate(degrees: Float)
  func concat(matrix: Mat) 
  func setMatrix(_ matrix: Mat)
  func clipRect(_ rect: FloatRect, clip: ClipOp, antiAlias: Bool)
  func clipRect(_ rect: FloatRect, clip: ClipOp)
  func clipRect(_ rect: FloatRect, antiAlias: Bool)
  func clipRect(_ rect: FloatRect)
  func clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool)
  func clipRRect(_ rrect: FloatRRect, antiAlias: Bool)
  func clipRRect(_ rrect: FloatRRect, clip: ClipOp)
  func clipRRect(_ rrect: FloatRRect)
  func clipPath(_ path: Path, clip: ClipOp, antiAlias: Bool)
  func clipPath(_ path: Path, clip: ClipOp)
  func clipPath(_ path: Path, antiAlias: Bool)
  func drawColor(_ color: Color, mode: BlendMode)
  func drawColor(_ color: Color)
  func clear(color: Color)
  func clearRect(_ rect: IntRect)
  func clearRect(_ rect: FloatRect)
  func fillRect(_ rect: IntRect)
  func drawLine(x0: Float, y0: Float, x1: Float, y1: Float, flags: PaintFlags)
  func drawLine(start: FloatPoint, end: FloatPoint, flags: PaintFlags)
  func drawRect(_ rect: FloatRect, flags: PaintFlags)
  func drawIRect(_ rect: IntRect, flags: PaintFlags)
  func drawOval(_ oval: FloatRect, flags: PaintFlags)
  func drawRRect(_ rrect: FloatRRect, flags: PaintFlags)
  func drawDRRect(outer: FloatRRect, inner: FloatRRect, flags: PaintFlags)
  func drawRoundRect(_ rect: FloatRect, x: Float, y: Float, flags: PaintFlags)
  func drawPath(_ path: Path, flags: PaintFlags)
  func drawImage(_ image: ImageSkia, left: Float, top: Float, flags: PaintFlags?)
  func drawImage(_ image: ImageSkia, left: Float, top: Float)
  func drawImageRect(_ image: ImageSkia, src: FloatRect, dst: FloatRect, 
    constraint: SrcRectConstraint, flags: PaintFlags?)
  func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float, flags: PaintFlags?)
  func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float)
  func drawTextBlob(_ blob: PaintTextBlob, x: Float, y: Float, flags: PaintFlags)
  func drawPicture(record: PaintRecord)
  func recordCustomData(id: UInt32)
  func commit(_ cb: @escaping () -> Void)
}

extension PaintCanvas {

  public var fillStyle: String {
    get { return String() }
    set {}
  }
  
  public func clipRect(_ rect: FloatRect, antiAlias: Bool) {
    clipRect(rect, clip: ClipOp.intersect, antiAlias: antiAlias)
  }

  public func clipRect(_ rect: FloatRect) {
    clipRect(rect, clip: ClipOp.intersect, antiAlias: false)
  }

  public func clipRRect(_ rrect: FloatRRect, antiAlias: Bool) {
    clipRRect(rrect, clip: ClipOp.intersect, antiAlias: antiAlias)
  }
  
  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp) {
    clipRRect(rrect, clip: clip, antiAlias: false)
  }
  
  public func clipRRect(_ rrect: FloatRRect) {
    clipRRect(rrect, clip: ClipOp.intersect, antiAlias: false)
  }

  public func clipPath(_ path: Path, antiAlias: Bool) {
    clipPath(path, clip: ClipOp.intersect, antiAlias: antiAlias)
  }

  public func drawImage(_ image: ImageSkia, left: Float, top: Float) {
    drawImage(image, left: left, top: top, flags: nil)
  }
  public func drawBitmap(_ bitmap: Bitmap, left: Float, top: Float) {
    drawBitmap(bitmap, left: left, top: top, flags: nil)
  }

  // used mostly for offscreen canvas, so for all the others it does nothing of value
  public func commit(_ cb: @escaping () -> Void) {}
  public func fillRect(_ rect: IntRect) {}
}