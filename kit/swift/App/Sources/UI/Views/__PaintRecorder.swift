// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor
import Web

// A modified version of paint recorder with a provided DisplayItemList 
// that you cant Start/End

public class PaintRecorder {

  public let canvas: Canvas
  private let context: PaintContext
  private var recordCanvas: PaintCanvas
  private var recordingSize: IntSize

  public init(
    context: PaintContext, 
    recordingSize: IntSize,
    scaleX: Float,
    scaleY: Float) {
    self.recordingSize = recordingSize
    self.recordCanvas = RecordPaintCanvas(list: context.list, bounds: FloatRect(size: FloatSize(recordingSize)))
    self.context = context
    // NOTE: this is a test
    //self.recordCanvas = WebPaintCanvas()
    canvas = Canvas(canvas: self.recordCanvas, imageScale: context.deviceScaleFactor)
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
              scaleY: context.deviceScaleFactor)
  }

  deinit {
    if context.isPixelCanvas {
      canvas.restore()
    }
    let boundsInLayer = context.toLayerSpaceBounds(size: recordingSize)
  }

}
