// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol Background {
  func paint(canvas: Canvas, view: View)
}

public class EmptyBackground : Background {
  public init() {}
  public func paint(canvas: Canvas, view: View) {}  
}

public class SolidBackground : Background {

  var color: Color

  public init(color: Color) {
    self.color = color
  }

  public func paint(canvas: Canvas, view: View) {
    canvas.drawColor(color: self.color)
  }

}

public class BackgroundPainter : Background {

  var painter: Painter

  public init(painter: Painter) {
    self.painter = painter
  }

  public func paint(canvas: Canvas, view: View) {
    PainterHelper.paintPainterAt(canvas: canvas, painter: self.painter, rect: view.localBounds)
  }

}

public class BackgroundFactory {

  public static func makeSolidBackground(color: Color) -> Background {
    return SolidBackground(color: color)
  }

  public static func makeSolidBackground(r: UInt8, g: UInt8, b: UInt8) -> Background {
    return BackgroundFactory.makeSolidBackground(color: Color(r: r, g: g, b: b))
  }

  public static func makeSolidBackground(r: UInt8, g: UInt8, b: UInt8, a: UInt8) -> Background {
    return BackgroundFactory.makeSolidBackground(color: Color(a: a, r: r, g: g, b: b))
  }

  public static func makeVerticalGradientBackground(c1: Color,
                                                    c2: Color) -> Background {
    return EmptyBackground()
  }

  public static func makeVerticalMultiColorGradientBackground(colors: [Color],
                                                              pos: [Double],
                                                              count: UInt) -> Background {
   return EmptyBackground()
  }

  public static func makeStandardPanelBackground() -> Background {
    return EmptyBackground()
  }

  public static func makeBackgroundPainter(painter: Painter) -> Background {
    return BackgroundPainter(painter: painter)
  }

}