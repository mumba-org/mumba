// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor
import Web

public class PaintRecorder {

  private(set) public var canvas: Canvas
  private let context: PaintContext
  private var cache: PaintCache?
  private var localList: DisplayItemList?
  private var recordCanvas: PaintCanvas
  private var recordingSize: IntSize

  public init(
    context: PaintContext, 
    recordingSize: IntSize,
    scaleX: Float,
    scaleY: Float,
    cache: PaintCache?) {
    self.context = context
    self.cache = cache
    self.recordingSize = recordingSize
  
    if self.cache != nil {
      self.localList = DisplayItemList(hint: .toBeReleasedAsPaintOpBuffer)
    }

    self.recordCanvas = RecordPaintCanvas(list: self.cache != nil ? localList! : context.list, bounds: FloatRect(size: FloatSize(recordingSize)))

    // NOTE: this is a test
    //self.recordCanvas = WebPaintCanvas()
    canvas = Canvas(canvas: self.recordCanvas, imageScale: context.deviceScaleFactor)

    if self.cache != nil {
      localList!.startPaint()
    } else {
      context.list.startPaint()
    }
    if context.isPixelCanvas {
      canvas.save()
      canvas.scale(x: scaleX, y: scaleY)
    }
  }

  public convenience init(context: PaintContext, recordingSize: IntSize) {
    self.init(context: context,
              recordingSize: IntSize.scaleToRounded(
                size: recordingSize,
                scaleBy: context.isPixelCanvas ? context.deviceScaleFactor : 1.0),
              scaleX: context.deviceScaleFactor,
              scaleY: context.deviceScaleFactor,
              cache: nil)
  }

  deinit {
    if context.isPixelCanvas {
      canvas.restore()
    }
    // If using cache, append what we've saved there to the PaintContext.
    // Otherwise, the content is already stored in the PaintContext, and we can
    // just close it.
    if cache != nil {
      localList!.endPaintOfUnpaired(rect: IntRect())
      localList!.finalize()
      cache!.paintOpBuffer = localList!.releaseAsRecord()
      let _ = cache!.useCache(context: context, size: recordingSize)
    } else {
      let boundsInLayer = context.toLayerSpaceBounds(size: recordingSize)
      context.list.endPaintOfUnpaired(rect: boundsInLayer)
    }
  }

}
