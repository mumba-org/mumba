// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public protocol PaintedLayerDelegate : LayerDelegate {
  var color: Color { get set }
  var paintedBounds: FloatRect { get }
  var centeringOffset: FloatVec2 { get }
}

public class BasePaintedLayerDelegate : PaintedLayerDelegate {
  
  public var color: Color

  public var paintedBounds: FloatRect {
    return FloatRect()
  }
  
  public var centeringOffset: FloatVec2 {
    return paintedBounds.centerPoint.offsetFromOrigin
  }

  init() {
    color = Color()
  }
  
  public func onDeviceScaleFactorChanged(oldDeviceScaleFactor: Float,
                                         newDeviceScaleFactor: Float) {} 
}

public class CircleLayerDelegate : BasePaintedLayerDelegate {
  
  public override var paintedBounds: FloatRect {
    let diameter = Float(radius) * 2
    return FloatRect(x: 0, y: 0, width: diameter, height: diameter)
  }

  public private(set) var radius: Int

  public init(color: Color, radius: Int) {
    self.radius = radius    
    super.init()
    self.color = color    
  }

  public func onPaintLayer(context: PaintContext) {
    let flags = PaintFlags()
    flags.color = color
    flags.antiAlias = true
    flags.style = Paint.Style.Fill

    let recorder = PaintRecorder(context: context, recordingSize: Rect<Int>.toEnclosingRect(rect: paintedBounds).size)
    recorder.canvas.drawCircle(center: paintedBounds.centerPoint, radius: Float(radius), flags: flags)
  }
  
}


public class RectangleLayerDelegate : BasePaintedLayerDelegate {
 
  public override var paintedBounds: FloatRect {
    return FloatRect(size: size)
  }
 
  public private(set) var size: FloatSize
  
  public init(color: Color, size: FloatSize) {
    self.size = size
    super.init()    
    self.color = color
  }

  public func onPaintLayer(context: PaintContext) {
    let flags = PaintFlags()
    flags.color = color
    flags.antiAlias = true
    flags.style = Paint.Style.Fill

    let recorder = PaintRecorder(context: context, recordingSize: IntSize(size))
    recorder.canvas.drawRect(rect: paintedBounds, flags: flags)
  }

}

public class RoundedRectangleLayerDelegate : BasePaintedLayerDelegate  {
  
  public override var paintedBounds: FloatRect {
    return FloatRect(size: size)
  }

  public private(set) var size: FloatSize
  public private(set) var cornerRadius: Int
  
  public init(color: Color, size: FloatSize, cornerRadius: Int) {
    self.size = size
    self.cornerRadius = cornerRadius    
    super.init()    
    self.color = color
  }

  public func onPaintLayer(context: PaintContext) {
    let flags = PaintFlags()
    flags.color = color
    flags.antiAlias = true
    flags.style = Paint.Style.Fill

    let recorder = PaintRecorder(context: context, recordingSize: IntSize(size))
    let dsf = recorder.canvas.undoDeviceScaleFactor()
    var rect = paintedBounds
    rect.scale(by: dsf)
    recorder.canvas.drawRoundRect(rect: Rect<Int>.toEnclosingRect(rect: rect),
                                  radius: Int(dsf) * cornerRadius, 
                                  flags: flags)

  }

}


public class BorderShadowLayerDelegate : BasePaintedLayerDelegate {
  
  public override var paintedBounds: FloatRect {
    var totalRect = bounds
    totalRect.inset(insets: ShadowValue.getMargin(shadows: shadows))
    return totalRect
  }

  public override var centeringOffset: FloatVec2 {
    return bounds.centerPoint.offsetFromOrigin
  }

  public private(set) var shadows: [ShadowValue]

  public private(set) var bounds: FloatRect

  public private(set) var fillColor: Color

  public private(set) var cornerRadius: Int

  public init(shadows: [ShadowValue],
              shadowedAreaBounds: FloatRect,
              fillColor: Color,
              cornerRadius: Int) {

    self.shadows = shadows
    self.bounds = shadowedAreaBounds
    self.fillColor = fillColor
    self.cornerRadius = cornerRadius
    super.init()
    self.color = Colors.placeholderColor
  }

  public func onPaintLayer(context: PaintContext) {
    let flags = PaintFlags()
    flags.style = Paint.Style.Fill
    flags.antiAlias = true
    flags.color = fillColor
    
    let rrectBounds: FloatRect = bounds - paintedBounds.offsetFromOrigin
    let rrect = FloatRRect(rect: rrectBounds, x: Float(cornerRadius), y: Float(cornerRadius))

    // First the fill color.
    let recorder = PaintRecorder(context: context, recordingSize: IntSize(paintedBounds.size))
    recorder.canvas.paintCanvas.drawRRect(rrect, flags: flags)

    // Now the shadow.
    flags.looper = DefaultDrawLooperFactory.makeShadow(shadows: shadows)// Graphics.createShadowDrawLooper(shadows)
    recorder.canvas.paintCanvas.clipRRect(rrect, clip: ClipOp.difference, antiAlias: true)
    recorder.canvas.paintCanvas.drawRRect(rrect, flags: flags)
  }

}
