// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public class InkDropMask : LayerDelegate {
  
  public var layer: Layer
  
  internal init(layerSize: IntSize) {
    layer = try! Layer(type: .PictureLayer)//.Textured)
    layer.delegate = self
    layer.bounds = IntRect(size: layerSize)
    layer.fillsBoundsOpaquely = false
    layer.name = "InkDropMaskLayer"
  }

  deinit {
    layer.delegate = nil
  }

  public func updateLayerSize(size: IntSize) {
    layer.bounds = IntRect(size: size)
  }

  public func onDeviceScaleFactorChanged(deviceScaleFactor: Float) {}
  public func onPaintLayer(context: PaintContext) {}

}


public class RoundRectInkDropMask : InkDropMask {
  
  public var maskInsets: IntInsets
  public var cornerRadius: Float

  public init(layerSize: IntSize,
              maskInsets: IntInsets,
              cornerRadius: Float) {
      self.maskInsets = maskInsets
      self.cornerRadius = cornerRadius
      super.init(layerSize: layerSize)
  }

  public override func onPaintLayer(context: PaintContext) {
    let flags = PaintFlags()
    flags.alpha = 255
    flags.style = Paint.Style.Fill
    flags.antiAlias = true

    let recorder = PaintRecorder(context: context, recordingSize: layer.size)
    let dsf = recorder.canvas.undoDeviceScaleFactor()

    var maskingBound = layer.bounds
    maskingBound.inset(insets: maskInsets)

    recorder.canvas.drawRoundRect(rect: Rect<Float>.scale(rect: maskingBound, factor: dsf),
                                  radius: cornerRadius * dsf, flags: flags)
  }
}

public class CircleInkDropMask : InkDropMask {
  
  public var maskCenter: IntPoint
  public var maskRadius: Int

  public init(layerSize: IntSize,
              maskCenter: IntPoint,
              maskRadius: Int) {
      
      self.maskCenter = maskCenter
      self.maskRadius = maskRadius

      super.init(layerSize: layerSize)
  }

  public override func onPaintLayer(context: PaintContext) {
    let flags = PaintFlags()
    flags.alpha = 255
    flags.style = Paint.Style.Fill
    flags.antiAlias = true

    let recorder = PaintRecorder(context: context, recordingSize: layer.size)
    recorder.canvas.drawCircle(center:  maskCenter, radius: maskRadius, flags: flags)
  }

}

extension HighlightState {
  public var inkDrop: InkDropImpl? { 
    return stateFactory.inkDrop 
  }
  public func enter() {}
  public func exit() {}
}
