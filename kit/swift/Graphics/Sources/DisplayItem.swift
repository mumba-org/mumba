// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum DisplayItem {
  case clipPath(_ path: Path, clip: ClipOp, antiAlias: Bool)
  case clipRect(_ rect: FloatRect, clip: ClipOp, antiAlias: Bool)
  case clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool)
  case concat(matrix: Mat)
  case customData(data: UInt32)
  case drawColor(_ color: Color, blend: BlendMode)
  case drawDRRect(outer: FloatRRect, inner: FloatRRect, flags: PaintFlags)
  case drawBitmap(_ bitmap: Bitmap, left: Float, top: Float, flags: PaintFlags?)
  case drawImage(_ image: ImageSkia, left: Float, top: Float, flags: PaintFlags?)
  case drawImageRect(_ image: ImageSkia, 
    src: FloatRect, 
    dest: FloatRect, 
    constraint: SrcRectConstraint,
    flags: PaintFlags?)
  case drawIRect(_ rect: IntRect, flags: PaintFlags)
  case drawLine(start: FloatPoint, end: FloatPoint, flags: PaintFlags)
  case drawOval(_ oval: FloatRect, flags: PaintFlags)
  case drawPath(_ path: Path, flags: PaintFlags)
  case drawRecord(_ record: PaintRecord)
  case drawRect(_ rect: FloatRect, flags: PaintFlags)
  case drawRRect(_ rect: FloatRRect, flags: PaintFlags)
  case drawTextBlob(_ text: PaintTextBlob, x: Float, y: Float, flags: PaintFlags)
  case noop
  case restore
  case rotate(degrees: Float)
  case save
  case saveLayer(bounds: FloatRect?, flags: PaintFlags?)
  case saveLayerAlpha(bounds: FloatRect?, alpha: UInt8, preserveLcdTextRequests: Bool)
  case scale(x: Float, y: Float)
  case setMatrix(_ matrix: Mat)
  case translate(x: Float, y: Float)
}

extension DisplayItem {
  
  public static func rasterWithFlags(item: DisplayItem, flags inputFlags: PaintFlags?, canvas: SkiaCanvas, params: PlaybackParams) {
    switch item {
      case .drawImage(let image, let left, let top, .some(let flags)):
        _DisplayItemImageRasterWithFlags()
      case .drawImage(let image, let left, let top, .none):
        _DisplayItemImageRasterWithFlags()
      case .drawImageRect(let image, let src, let dest, let srcRectConstraint, .some(let flags)):
        _DisplayItemImageRectRasterWithFlags()
      case .drawImageRect(let image, let src, let dest, let srcRectConstraint, .none):
        _DisplayItemImageRectRasterWithFlags()
      default:
       break  
    }
  }

}