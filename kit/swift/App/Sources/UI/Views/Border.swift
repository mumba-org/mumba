// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol Border {

  var insets: IntInsets { get }
  var minimumSize: IntSize { get }

  func paint(view: View, canvas: Canvas)
}

public class EmptyBorder : Border {
  
  public private(set) var insets: IntInsets
  
  public var minimumSize: IntSize {
    return IntSize()
  }

  public init(insets: IntInsets) {
    self.insets = insets
  }

  public func paint(view: View, canvas: Canvas) {

  }

}

public class SolidSidedBorder : Border {
  
  public var minimumSize: IntSize {
    return IntSize(width: insets.width, height: insets.height)
  }
  
  public private(set) var insets: IntInsets
  public private(set) var color: Color
  
  public init(insets: IntInsets, color: Color) {
    self.insets = insets
    self.color = color
  }

  public func paint(view: View, canvas: Canvas) {
    canvas.save()
    defer { canvas.restore() }
   
    let dsf = canvas.undoDeviceScaleFactor()

    var scaledBounds = FloatRect()
    if let layer = view.layer {
      scaledBounds = FloatRect(UI.convertRectToPixel(layer: layer, view.localBounds))
    } else {
      scaledBounds = FloatRect(view.localBounds)
      scaledBounds.scale(by: dsf)
    }

    // This scaling operation floors the inset values.
    scaledBounds.inset(insets: FloatInsets(insets.scale(dsf)))
    canvas.clipRect(rect: scaledBounds, op: ClipOp.difference)
    canvas.drawColor(color: color)
  }

}

public class RoundedRectBorder : Border {
  
  public var minimumSize: IntSize {
    return IntSize(width: thickness * 2, height: thickness * 2)
  }
  
  public var insets: IntInsets {
    return IntInsets(all: thickness)
  }
  
  public private(set) var thickness: Int
  public private(set) var cornerRadius: Int
  public private(set) var color: Color

  public init(thickness: Int,
              cornerRadius: Int,
              color: Color) {
    self.thickness = thickness
    self.cornerRadius = cornerRadius
    self.color = color
  }

  public func paint(view: View, canvas: Canvas) {
    let flags = PaintFlags()
    flags.strokeWidth = Float(thickness)
    flags.color = color
    flags.style = Paint.Style.Stroke
    flags.antiAlias = true

    let halfThickness = Float(thickness / 2)
    var bounds = FloatRect(view.localBounds)
    bounds.inset(horizontal: halfThickness, vertical: halfThickness)
    canvas.drawRoundRect(rect: bounds, radius: Float(cornerRadius), flags: flags)
  }

}

public class ExtraInsetsBorder : Border {
  
  public var minimumSize: IntSize {
    var size = border.minimumSize
    size.enlarge(width: extraInsets.width, height: extraInsets.height)
    return size
  }
  
  public var insets: IntInsets {
    return border.insets + extraInsets
  }

  public private(set) var extraInsets: IntInsets
  public private(set) var border: Border
  
  public init(border: Border, insets: IntInsets) {
    self.border = border
    self.extraInsets = insets
  }

  public func paint(view: View, canvas: Canvas) {
    border.paint(view: view, canvas: canvas)
  }
}

public class BorderPainter : Border {
  
  public var minimumSize: IntSize {
    return painter.minimumSize
  }
  
  public private(set) var insets: IntInsets
  public let painter: Painter

  public init(painter: Painter, insets: IntInsets) {
    self.painter = painter
    self.insets = insets
  }

  public func paint(view: View, canvas: Canvas) {
    PainterHelper.paintPainterAt(canvas: canvas, painter: painter, rect: view.localBounds)
  }
}

public func createSolidBorder(thickness: Int, color: Color) -> Border {
  return SolidSidedBorder(insets: IntInsets(all: thickness), color: color)
}

public func createEmptyBorder(insets: IntInsets) -> Border {
  return EmptyBorder(insets: insets)
}

public func createEmptyBorder(top: Int, left: Int, bottom: Int, right: Int) -> Border {
  return createEmptyBorder(insets: IntInsets(top: top, left: left, bottom: bottom, right: right))
}

public func createRoundedRectBorder(thickness: Int,
                                          cornerRadius: Int,
                                          color: Color) -> Border {
  return RoundedRectBorder(thickness: thickness, cornerRadius: cornerRadius, color: color)
}

public func createSolidSidedBorder(top: Int, left: Int, bottom: Int, right: Int, color: Color) -> Border {
  return SolidSidedBorder(insets: IntInsets(top: top, left: left, bottom: bottom, right: right), color: color)
}

public func createPaddedBorder(border: Border,
                                      insets: IntInsets) -> Border {
  return ExtraInsetsBorder(border: border, insets: insets)
}

public func createBorderPainter(painter: Painter,
                                        insets: IntInsets) -> Border {
  return BorderPainter(painter: painter, insets: insets)
}