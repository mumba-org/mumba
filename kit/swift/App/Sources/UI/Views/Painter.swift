// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol Painter {
  var minimumSize: IntSize { get }  
  func paint(canvas: Canvas, size: IntSize)
}

public class PainterFactory {

  static public func makeHorizontalGradient(c1: Color, c2: Color) -> Painter {
    var colors = [Color](repeating: Color(), count: 2)
    colors[0] = c1
    colors[1] = c2
    let pos: [Float] = [0, 1]
    return GradientPainter(horizontal: true, colors: colors, pos: pos, count: 2)
  }

  static public func makeVerticalGradient(c1: Color, c2: Color) -> Painter {
    var colors = [Color](repeating: Color(), count: 2)
    colors[0] = c1
    colors[1] = c2
    let pos: [Float] = [0, 1]
    return GradientPainter(horizontal: false, colors: colors, pos: pos, count: 2)
  }

  static public func makeVerticalMultiColorGradient(colors: [Color],
    pos: [Float],
    count: Int) -> Painter {
      return GradientPainter(horizontal: false, colors: colors, pos: pos, count: count)
  }

  static public func makeImagePainter(image: Image, insets: IntInsets) -> Painter {
    return ImagePainter(image: image, insets: insets)
  }

  static public func makeImageGridPainter(imageIds: [Int]) -> Painter {
    return ImagePainter(imageIds: imageIds)
  }

  static public func makeDashedFocusPainter() -> Painter {
    return DashedFocusPainter(insets: IntInsets())
  }

  static public func makeDashedFocusPainterWithInsets(insets: IntInsets) -> Painter {
    return DashedFocusPainter(insets: insets)
  }

  static public func makeSolidFocusPainter(color: Color, thickness: Int, insets: IntInsets) -> Painter {
    return SolidFocusPainter(color: color, thickness: thickness, insets: FloatInsets(insets))
  }

}

public struct PainterHelper {

  static public func paintPainterAt(canvas: Canvas,
    painter: Painter,
    rect: IntRect) {
      canvas.save()
      canvas.translate(offset: rect.offsetFromOrigin)
      painter.paint(canvas: canvas, size: rect.size)
      canvas.restore()
  }

  static public func paintFocusPainter(view: View,
    canvas: Canvas,
    focusPainter: Painter) {
      if view.hasFocus {
        PainterHelper.paintPainterAt(canvas: canvas, painter: focusPainter, rect: view.localBounds)
      }
  }

}

public class DashedFocusPainter : Painter {

  public var minimumSize: IntSize {
    return IntSize()
  }

  var insets: IntInsets

  public init(insets: IntInsets) {
    self.insets = insets
  }

  public func paint(canvas: Canvas, size: IntSize) {
    var rect = IntRect(size: size)
    rect.inset(insets: insets)
    canvas.drawFocusRect(rect: rect)
  }

}

public class SolidFocusPainter : Painter {

  public var minimumSize: IntSize {
    return IntSize()
  }

  var color: Color
  var insets: FloatInsets
  var thickness: Int

  public init(color: Color, thickness: Int, insets: FloatInsets) {
    self.color = color
    self.insets = insets
    self.thickness = thickness
  }

  public func paint(canvas: Canvas, size: IntSize) {
    var rect = FloatRect(Rect(size: size))
    rect.inset(insets: insets)
    canvas.drawSolidFocusRect(rect: rect, color: color, thickness: thickness)
  }

}

public class GradientPainter : Painter {

  public var minimumSize: IntSize {
    return IntSize()
  }

  var horizontal: Bool
  var colors: [Color]
  var pos: [Float]
  var count: Int

  public init(horizontal: Bool,
              colors: [Color],
              pos: [Float],
              count: Int) {
    self.horizontal = horizontal
    self.colors = colors
    self.pos = pos
    self.count = count
  }

  public func paint(canvas: Canvas, size: IntSize) {
    let paint = PaintFlags()
    var p = [FloatPoint](repeating: FloatPoint(), count: 2)
    
    p[0].set(x: 0.0, y: 0.0)

    if (horizontal) {
      p[1].set(x: Float(size.width), y: 0.0)
    } else {
      p[1].set(x: 0.0, y: Float(size.height))
    }

    let shader = PaintShaderFactory.makeLinearGradient(//DefaultShaderFactory.makeGradientLinear(
        points: p, 
        colors: colors, 
        pos: pos, 
        count: count,
        mode: TileMode.Clamp)

    paint.style = .Fill
    paint.shader = shader

    canvas.drawRect(rect: IntRect(left: 0, top: 0, right: size.width, bottom: size.height), flags: paint)
  }

}

public class ImagePainter : Painter {

  public var minimumSize: IntSize {
    return IntSize(ninePainter.minimumSize)
  }

  var ninePainter: NineImagePainter

  public init(image: Image, insets: IntInsets) {
    ninePainter = NineImagePainter(image: image, insets: FloatInsets(insets))
  }

  public init(imageIds: [Int]) {
    ninePainter = NineImagePainter(images: imageIdsToImages(imageIds: imageIds))
  }

  public func paint(canvas: Canvas, size: IntSize) {
    ninePainter.paint(canvas: canvas, bounds: FloatRect(size: FloatSize(size)))
  }

}

public class HorizontalPainter : Painter {
  
  // The image chunks.
  let left   = 0
  let center = 1
  let right  = 2

  var images: [Image]

  // Constructs a new HorizontalPainter loading the specified image names.
  // The images must be in the order left, right and center.
  public init(imageResourceNames: [Int]) {
    images = [Image](repeating: ImageSkia(), count: 3)
    for i in 0..<3 {
      if let image = ResourceBundle.getImage(imageResourceNames[i]) {
        images[i] = image
      } 
    }
  }

  // Painter:
  public var minimumSize: IntSize {
    return IntSize(width: Int(images[left].width + images[center].width + images[right].width), 
                   height: Int(images[left].height))
  }

  public func paint(canvas: Canvas, size: IntSize) {
    
    guard minimumSize.width < size.width else {
      return  // No room to paint.
    }

    canvas.drawImageInt(image: images[left] as! ImageSkia, x: 0, y: 0)
    
    canvas.drawImageInt(
      image: images[right] as! ImageSkia, 
      x: size.width - Int(images[right].width), 
      y: 0)
    
    canvas.tileImageInt(
      image: images[center] as! ImageSkia, 
      x: Int(images[left].width), 
      y: 0,
      w: size.width - Int(images[left].width) - Int(images[right].width),
      h: Int(images[left].height))
  }

}

public class RoundRectPainter : Painter {
  
  public static let borderWidth: Int = 1

  public var minimumSize: IntSize {
    return IntSize(width: 1, height: 1)
  }

  public let borderColor: Color
  public let cornerRadius: Int
  
  public init(borderColor: Color, cornerRadius: Int) {
    self.borderColor = borderColor
    self.cornerRadius = cornerRadius
  }

  public func paint(canvas: Canvas, size: IntSize) {
    let flags = PaintFlags()
    flags.color = borderColor
    flags.style = Paint.Style.Stroke
    flags.strokeWidth = Float(RoundRectPainter.borderWidth)
    flags.antiAlias = true
    var rect = IntRect(size: size)
    rect.inset(left: 0, top: 0, right: RoundRectPainter.borderWidth, bottom: RoundRectPainter.borderWidth)
    rect.offset(horizontal: RoundRectPainter.borderWidth / 2, vertical: RoundRectPainter.borderWidth / 2)
    canvas.drawRoundRect(rect: rect, radius: cornerRadius, flags: flags)
  }

}

fileprivate func imageIdsToImages(imageIds: [Int]) -> [Image] {
  var images = Array<Image>()
  for i in 0..<imageIds.count {
   // //print("NineImagePainter array: inserting image at \(i)")
    images.insert(ImageSkia(), at: i)
  }
  return images
}
