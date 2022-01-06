// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
#if os(Linux) 
import Glibc
#endif

fileprivate let UTF16And: UInt16 = 38 // '&'

public struct TextOptions : OptionSet {
  public let rawValue: Int
  // Specifies the alignment for text rendered with the DrawStringRect method.
  public static let TextAlignLeft = TextOptions(rawValue: 1 << 0)
  public static let TextAlignCenter = TextOptions(rawValue: 1 << 1)
  public static let TextAlignRight = TextOptions(rawValue: 1 << 2)
  public static let TextAlignToHead = TextOptions(rawValue: 1 << 3)

  // Specifies the text consists of multiple lines.
  public static let Multiline = TextOptions(rawValue: 1 << 4)

  // By default DrawStringRect does not process the prefix ('&') character
  // specially. That is, the string "&foo" is rendered as "&foo". When
  // rendering text from a resource that uses the prefix character for
  // mnemonics, the prefix should be processed and can be rendered as an
  // underline (SHOW_PREFIX), or not rendered at all (HIDE_PREFIX).
  public static let ShowPrefix = TextOptions(rawValue: 1 << 5)
  public static let HidePrefix = TextOptions(rawValue: 1 << 6)

  // Prevent ellipsizing
  public static let NoEllipsis = TextOptions(rawValue: 1 << 7)

  // Specifies if words can be split by new lines.
  // This only works with MULTI_LINE.
  public static let CharacterBreak = TextOptions(rawValue: 1 << 8)

  // Instructs DrawStringRect() to not use subpixel rendering.  This is useful
  // when rendering text onto a fully- or partially-transparent background
  // that will later be blended with another image.
  public static let NoSubpixelRendering = TextOptions(rawValue: 1 << 9)

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }
}

public class Canvas {

  public static var defaultCanvasTextAlignment: TextOptions {
    return i18n.isRTL() ? TextOptions.TextAlignRight : TextOptions.TextAlignLeft
  }
 
  public var isClipEmpty: Bool {
    return paintCanvas.isClipEmpty
  }

  public var clipBounds: IntRect? {
    if let r = paintCanvas.localClipBounds {
      return IntRect.toEnclosingRect(rect: r)
    }
    return nil
  }
  
  // FIXME: Its not always SkiaCanvas now
  public var nativeCanvas: SkiaCanvas {
    return paintCanvas.nativeCanvas
  }

  public var fillStyle: String {
    get {
      return paintCanvas.fillStyle
    }
    set {
      paintCanvas.fillStyle = newValue
    }
  }

  public internal(set) var paintCanvas: PaintCanvas

  public internal(set) var bitmap: Bitmap?

  public private(set) var imageScale: Float

  public init() {
    imageScale = 1.0

    let width: Float = 1.0
    let height: Float = 1.0
    
    bitmap = Bitmap()
    bitmap!.allocatePixels(width: width, height: height, alpha: AlphaType.Opaque)
    paintCanvas = SkiaPaintCanvas(bitmap: bitmap!) 
    paintCanvas.scale(x: imageScale, y: imageScale)
  }

  public init(size: IntSize, imageScale: Float, isOpaque: Bool) {
    self.imageScale = imageScale
   
    let pixelSize = IntSize.scaleToCeiled(size, scale: imageScale)

    let alpha: AlphaType = isOpaque ? AlphaType.Opaque : AlphaType.Premul

    let width = max(pixelSize.width, 1)
    let height = max(pixelSize.height, 1)
    
    bitmap = Bitmap()
    bitmap!.allocatePixels(width: Float(width), height: Float(height), alpha: alpha)
    paintCanvas = SkiaPaintCanvas(bitmap: bitmap!) 
    paintCanvas.scale(x: imageScale, y: imageScale)
  }

  public init(canvas: PaintCanvas, imageScale: Float) {
    self.imageScale = imageScale
    self.paintCanvas = canvas
  }

  public func drawDashedRect(rect inrect: FloatRect, color: Color) {
    if inrect.isEmpty {
      return
    }

    var rect = inrect

    let flags = PaintFlags()
    flags.color = color
    let intervals: [Float] = [1.0, 1.0]
    flags.strokeWidth = 1.0
    flags.style = .Stroke
    rect.inset(insets: FloatInsets(all: 0.5))

    flags.pathEffect = PathEffect.makeDash(intervals: intervals, count: 2, phase: 0)

    // Top-left to top-right.
    paintCanvas.drawLine(x0: rect.x - 0.5, y0: rect.y, x1: rect.right + 0.5, y1: rect.y, flags: flags)
    // Top-left to bottom-left.
    paintCanvas.drawLine(x0: rect.right + 0.5, y0: rect.bottom, x1: rect.x - 0.5, y1: rect.bottom, flags: flags)
    // Bottom-right to bottom-left.
    paintCanvas.drawLine(x0: rect.x, y0: rect.y - 0.5, x1: rect.x, y1: rect.bottom + 0.5, flags: flags)
    // Bottom-right to top-right.
    paintCanvas.drawLine(x0: rect.right, y0: rect.bottom + 0.5, x1: rect.right, y1: rect.y - 0.5, flags: flags)
  }

  public func undoDeviceScaleFactor() -> Float {
    let scaleFactor = 1.0 / imageScale
    paintCanvas.scale(x: scaleFactor, y: scaleFactor)
    return imageScale
  }

  public func save() {
    let _ = paintCanvas.save()
  }

  public func saveLayerAlpha(alpha: UInt8) {
    let _ = paintCanvas.saveLayerAlpha(bounds: nil, alpha: alpha, preserveLcdTextRequests: false)
  }

  public func saveLayerAlpha(alpha: UInt8, bounds layerBounds: IntRect) {
    let bounds = FloatRect(layerBounds)
    let _ = paintCanvas.saveLayerAlpha(bounds: bounds, alpha: alpha, preserveLcdTextRequests: false)
  }

  public func saveLayerWithFlags(flags: PaintFlags) {
    let _ = paintCanvas.saveLayer(bounds: nil, flags: flags)
  }

  public func restore() {
    paintCanvas.restore()
  }

  public func clipRect(rect: IntRect, op: ClipOp = ClipOp.intersect) {
    paintCanvas.clipRect(FloatRect(rect), clip: op)
  }

  public func clipRect(rect: FloatRect, op: ClipOp = ClipOp.intersect) {
    paintCanvas.clipRect(rect, clip: op)
  }

  public func clipRRect(_ rrect: FloatRRect, antiAlias: Bool) {
    paintCanvas.clipRRect(rrect, clip: ClipOp.intersect, antiAlias: antiAlias)
  }
  
  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp) {
    paintCanvas.clipRRect(rrect, clip: clip, antiAlias: false)
  }

  public func clipRRect(_ rrect: FloatRRect, clip: ClipOp, antiAlias: Bool) {
    paintCanvas.clipRRect(rrect, clip: clip, antiAlias: antiAlias)
  }
  
  public func clipRRect(_ rrect: FloatRRect) {
    paintCanvas.clipRRect(rrect)
  }

  public func clipPath(path: Path, antiAlias: Bool) {
    paintCanvas.clipPath(path, clip: ClipOp.intersect, antiAlias: antiAlias)
  }

  public func translate(offset: IntVec2) {
    paintCanvas.translate(x: Float(offset.x), y: Float(offset.y))
  }

  public func scale(x: Float, y: Float ) {
    paintCanvas.scale(x: x, y: y)
  }

  public func rotate(degrees: Float) {
    paintCanvas.rotate(degrees: degrees) 
  }
  
  public func concat(matrix: Mat) {
    paintCanvas.concat(matrix: matrix)
  }

  public func setMatrix(_ m: Mat) {
    paintCanvas.setMatrix(m)
  }

  public func drawColor(color: Color) {
    drawColor(color: color, mode: .SrcOver)
  }

  public func drawColor(color: Color, mode: BlendMode) {
    paintCanvas.drawColor(color, mode: mode)
  }

  public func fillRect(_ r: IntRect) {
    paintCanvas.fillRect(r)
  }

  public func fillRect(rect: IntRect, color: Color) {
    fillRect(rect: rect, color: color, mode: .SrcOver)
  }

  public func fillRect(rect: IntRect, color: Color, mode: BlendMode) {
    let flags = PaintFlags()
    flags.color = color
    flags.style = .Fill
    flags.blendMode = mode
    drawRect(rect: rect, flags: flags)
  }

  public func fillRect(rect: FloatRect, color: Color) {
    fillRect(rect: rect, color: color, mode: .SrcOver)
  }

  public func fillRect(rect: FloatRect, color: Color, mode: BlendMode) {
    let flags = PaintFlags()
    flags.color = color
    flags.style = .Fill
    flags.blendMode = mode
    drawRect(rect: rect, flags: flags)
  }

  public func clear(color: Color) {
    paintCanvas.clear(color: color) 
  }

  public func clearRect(_ rect: IntRect) {
    paintCanvas.clearRect(rect)
  }

  public func clearRect(_ rect: FloatRect) {
    paintCanvas.clearRect(rect)
  }

  public func drawRect(rect: FloatRect, color: Color) {
    drawRect(rect: rect, color: color, mode: .SrcOver)
  }

  public func drawRect(rect: FloatRect, color: Color, mode: BlendMode) {
    let flags = PaintFlags()
    flags.color = color
    flags.style = .Stroke
    // Set a stroke width of 0, which will put us down the stroke rect path.  If
    // we set a stroke width of 1, for example, this will internally create a
    // path and fill it, which causes problems near the edge of the paintCanvas.
    flags.strokeWidth = 0
    flags.blendMode = mode

    drawRect(rect: rect, flags: flags)
  }

  public func drawRect(rect: IntRect, flags: PaintFlags) {
    drawRect(rect: FloatRect(rect), flags: flags)
  }

  public func drawRect(rect: FloatRect, flags: PaintFlags) {
    paintCanvas.drawRect(rect, flags: flags)
  }

  public func drawLine(p1: IntPoint, p2: IntPoint, color: Color) {
    drawLine(p1: FloatPoint(p1), p2: FloatPoint(p2), color: color)
  }

  public func drawLine(p1: FloatPoint, p2: FloatPoint, color: Color) {
    let flags = PaintFlags()
    flags.color = color
    flags.strokeWidth = 1
    drawLine(p1: p1, p2: p2, flags: flags)
  }

  public func drawLine(p1: IntPoint,
                       p2: IntPoint,
                       flags: PaintFlags) {
    drawLine(p1: FloatPoint(p1), p2: FloatPoint(p2), flags: flags)
  }

  public func drawLine(p1: FloatPoint, p2: FloatPoint, flags: PaintFlags) {
    paintCanvas.drawLine(start: p1, end: p2, flags: flags)
  }

  public func drawSharpLine(p1: FloatPoint, p2: FloatPoint, color: Color) {
    let _ = ScopedCanvas(canvas: self)
    let dsf = undoDeviceScaleFactor()
    var mp1 = p1
    var mp2 = p2
    mp1.scale(by: dsf)
    mp2.scale(by: dsf)

    let flags = PaintFlags()
    flags.color = color
    flags.strokeWidth = floor(dsf)

    drawLine(p1: mp1, p2: mp2, flags: flags)
  }

  public func draw1pxLine(p1: FloatPoint, p2: FloatPoint, color: Color) {
    let _ = ScopedCanvas(canvas: self)
    let dsf = undoDeviceScaleFactor()
    var mp1 = p1
    var mp2 = p2
    mp1.scale(by: dsf)
    mp2.scale(by: dsf)

    drawLine(p1: mp1, p2: mp2, color: color)
  }

  public func drawCircle(center: IntPoint,
                         radius: Int,
                         flags: PaintFlags) {
    paintCanvas.drawOval(
        FloatRect(left: Float(center.x - radius), top: Float(center.y - radius),
                  right: Float(center.x + radius), bottom: Float(center.y + radius)),
        flags: flags)
  }

  public func drawCircle(center: FloatPoint,
                         radius: Float,
                         flags: PaintFlags) {
    paintCanvas.drawOval(
        FloatRect(left: center.x - radius, top: center.y - radius,
                        right: center.x + radius, bottom: center.y + radius),
        flags: flags)
  }

  public func drawRoundRect(rect: IntRect,
                            radius: Int,
                            flags: PaintFlags) {
    drawRoundRect(rect: FloatRect(rect), radius: Float(radius), flags: flags)
  }

  public func drawRoundRect(rect: FloatRect,
                            radius: Float,
                            flags: PaintFlags) {
    paintCanvas.drawRoundRect(rect, x: radius,
                         y: radius, flags: flags)
  }

  public func drawPath(path: Path, flags: PaintFlags) {
    paintCanvas.drawPath(path, flags: flags)
  }

  public func commit(_ cb: @escaping () -> Void) {
    paintCanvas.commit(cb)
  }

  public func drawFocusRect(rect: IntRect) {
    drawFocusRect(rect: FloatRect(rect))
  }

  public func drawFocusRect(rect: FloatRect) {
    drawDashedRect(rect: rect, color: Color.Gray)
  }

  public func drawSolidFocusRect(rect: FloatRect, color: Color, thickness: Int) {
    let flags = PaintFlags()
    flags.color = color
    let adjustedThickness = floor(Float(thickness) * imageScale) / imageScale
    flags.strokeWidth = adjustedThickness
    flags.style = .Stroke
    var mrect = rect
    mrect.inset(insets: FloatInsets(all: adjustedThickness / 2.0))
    drawRect(rect: mrect, flags: flags)
  }

  public func drawBitmap(bitmap: Bitmap, x: Int, y: Int) {
    print("Canvas.drawBitmap")
    guard !bitmap.isNull else {
      print("drawBitmap: bitmap is null. cancelling")
      return
    }
    let flags = PaintFlags()
    //let bitmapScale = image.scale
    //let _ = ScopedCanvas(canvas: self)

    // paintCanvas.scale(x: 1.0 / bitmapScale,
    //                   y: 1.0 / bitmapScale)
    
    paintCanvas.drawBitmap(bitmap,
                           left: Float(x),// * bitmapScale,
                           top:  Float(y),// * bitmapScale,
                           flags: flags)
  }

  public func drawImageInt(image: ImageSkia, x: Int, y: Int) {
    let flags = PaintFlags()
    drawImageInt(image: image, x: x, y: y, flags: flags)
  }

  public func drawImageInt(image: ImageSkia, x: Int, y: Int, a: UInt8) {
    let flags = PaintFlags()
    flags.alpha = a
    drawImageInt(image: image, x: x, y: y, flags: flags)
  }

  public func drawImageInt(image: ImageSkia, x: Int, y: Int, flags: PaintFlags) {

    let bitmap = image.bitmap
    
    guard !bitmap.isNull else {
      return
    }
  
    let bitmapScale = image.scale
    let _ = ScopedCanvas(canvas: self)


    paintCanvas.scale(x: 1.0 / bitmapScale,
                 y: 1.0 / bitmapScale)
    
    paintCanvas.drawBitmap(bitmap,
                      left: Float(x) * bitmapScale,
                      top:  Float(y) * bitmapScale,
                      flags: flags)
  }

  public func drawImageInt(image: ImageSkia,
                           sx: Int,
                           sy: Int,
                           sw: Int,
                           sh: Int,
                           dx: Int,
                           dy: Int,
                           dw: Int,
                           dh: Int,
                           filter: Bool) {
    let flags = PaintFlags()
    drawImageInt(
              image: image, 
              sx: sx, 
              sy: sy, 
              sw: sw, 
              sh: sh, 
              dx: dx, 
              dy: dy,
              dw: dw, 
              dh: dh, 
              filter: filter, 
              flags: flags)
  }

  public func drawImageInt(image: ImageSkia,
                           sx: Int,
                           sy: Int,
                           sw: Int,
                           sh: Int,
                           dx: Int,
                           dy: Int,
                           dw: Int,
                           dh: Int,
                           filter: Bool,
                           flags: PaintFlags) {

    guard let bitmap = image.getBitmapFor(scale: imageScale) else {
      return 
    }

    drawImageIntHelper(
      bitmap: bitmap,
      sx: sx,
      sy: sy,
      sw: sw,
      sh: sh,
      dx: dx,
      dy: dy,
      dw: dw,
      dh: dh,
      filter: filter,
      flags: flags,
      removeImageScale: true)
  }

  public func drawImageIntInPixel(bitmap: Bitmap,
                                  dx: Int,
                                  dy: Int,
                                  dw: Int,
                                  dh: Int,
                                  filter: Bool,
                                  flags: PaintFlags) {
    let sx = 0
    let sy = 0
    let sw = Int(bitmap.width)
    let sh = Int(bitmap.height)
    // Don't remove image scale here, this function is used to draw the
    // (already scaled) |image_rep| at a 1:1 scale with the paintCanvas.
  
    drawImageIntHelper(
      bitmap: bitmap,
      sx: sx,
      sy: sy,
      sw: sw,
      sh: sh,
      dx: dx,
      dy: dy,
      dw: dw,
      dh: dh,
      filter: filter,
      flags: flags, 
      removeImageScale: false)
  }

  public func drawImageInPath(image: ImageSkia,
                              x: Int,
                              y: Int,
                              path: Path,
                              flags inputFlags: PaintFlags) {
    guard let bitmap = image.getBitmapFor(scale: imageScale) else {
      return
    }
  
    let matrix = Mat()
    matrix.translate(x: Double(x), y: Double(y))
    let flags = inputFlags
    flags.shader = PaintShaderFactory.makeImageForScale(bitmap: bitmap, tileMode: .Repeat, matrix: matrix, scale: imageScale)
    paintCanvas.drawPath(path, flags: flags)
  }

  public func drawStringRect(text: String,
                             font: FontList,
                             color: Color,
                             rect displayRect: FloatRect) {
    drawStringRect(
      text: text, 
      font: font,
      color: color,
      rect: displayRect, 
      flags: i18n.isRTL() ? TextOptions.TextAlignRight : TextOptions.TextAlignLeft)
  }

  public func drawStringRect(text: String,
                             font fontList: FontList,
                             color: Color,
                             rect displayRect: FloatRect,
                             flags: TextOptions) {
    var mflags = flags

    guard intersectsClipRect(rect: displayRect) else {
      return
    }

    let _ = save()
    
    clipRect(rect: displayRect)

    var rect = displayRect

    let renderText = RenderText()

    if flags.contains(.Multiline) {
      var wrapBehavior: WordWrapBehavior = .IgnoreLongWords
      if flags.contains(.CharacterBreak) {
        wrapBehavior = .WrapLongWords
      } else if !flags.contains(.NoEllipsis) {
        wrapBehavior = .ElideLongWords
      }

      var strings: [String] = []
     
      let _ = elideRectangleText(text: text, 
                         list: fontList,
                         width: displayRect.width,
                         height: Int(displayRect.height), 
                         behavior: wrapBehavior, 
                         lines: &strings)

      for i in 0..<strings.count {
        let range: TextRange = Canvas.stripAcceleratorChars(options: flags, text: &strings[i])
        Canvas.updateRenderText(rect: rect, text: strings[i], list: fontList, options: &mflags, color: color, renderText: renderText)
        let linePadding: Float = 0.0
        let lineHeight = Float(renderText.stringSize.height)

        // TODO(msw|asvitkine): Center Windows multi-line text: crbug.com/107357
#if !os(Windows)
        if i == 0 {
          // TODO(msw|asvitkine): Support multi-line text with varied heights.
          let textHeight = Float(strings.count) * lineHeight - linePadding
          rect = rect + FloatVec2(x: 0, y: (displayRect.height - textHeight) / 2.0)
        }
#endif

        rect.height = lineHeight - linePadding

        if range.isValid {
          renderText.applyStyle(style: .Underline, value: true, range: range)
        }
        renderText.displayRect = rect
        renderText.draw(canvas: self)
        rect = rect + FloatVec2(x: 0, y: lineHeight)
      }
    } else {
      var adjustedText = text
      var range: TextRange = Canvas.stripAcceleratorChars(options: flags, text: &adjustedText)
      var elideText: Bool = !flags.contains(.NoEllipsis)

#if os(Linux)
      // On Linux, eliding really means fading the end of the string. But only
      // for LTR text. RTL text is still elided (on the left) with "...".
      if elideText {
        renderText.text = adjustedText
        if renderText.displayTextDirection == .LeftToRight {
          renderText.elideBehavior = .FadeTail
          elideText = false
        }
      }
#endif

      if elideText {
        Canvas.elideTextAndAdjustRange(
                                fontList: fontList,
                                width: displayRect.width,
                                text: &adjustedText, 
                                range: &range)
      }

      Canvas.updateRenderText(
        rect: rect, 
        text: adjustedText, 
        list: fontList, 
        options: &mflags, 
        color: color,
        renderText: renderText)

      if range.isValid {
        renderText.applyStyle(style: .Underline, value: true, range: range)
      }
      renderText.draw(canvas: self)
    }

    restore()
  }

  public func tileImageInt(image: ImageSkia,
                           x: Int,
                           y: Int,
                           w: Int,
                           h: Int) {
    tileImageInt(image: image, sx: 0, sy: 0, dx: x, dy: y, w: w, h: h)
  }

  public func tileImageInt(image: ImageSkia,
                        sx: Int,
                        sy: Int,
                        dx: Int,
                        dy: Int,
                        w: Int,
                        h: Int) {
  
    tileImageInt(image: image, sx: sx, sy: sy, dx: dx, dy: dy, w: w, h: h, tileScale: 1.0, flags: nil)
  }

  public func tileImageInt(image: ImageSkia,
                           sx: Int,
                           sy: Int,
                           dx: Int,
                           dy: Int,
                           w: Int,
                           h: Int,
                           tileScale: Float,
                           flags: PaintFlags?) {
    
    let destRect = FloatRect(x: Float(dx),
                         y: Float(dy),
                         width: Float(dx + w),
                         height: Float(dy + h))

    if !intersectsClipRect(rect: destRect) {
      return
    }

    var paintFlags: PaintFlags?

    if let inputFlags = flags {
      paintFlags = inputFlags
    } else {
      paintFlags = PaintFlags()
    }

    if initPaintFlagsForTiling(image: image, sx: sx, sy: sy, tileScaleX: tileScale, tileScaleY: tileScale, dx: dx, dy: dy, flags: &paintFlags!) {
      paintCanvas.drawRect(destRect, flags: paintFlags!)
    }
  }

  public func initPaintFlagsForTiling(image: ImageSkia,
                                      sx: Int,
                                      sy: Int,
                                      tileScaleX: Float,
                                      tileScaleY: Float,
                                      dx: Int,
                                      dy: Int,
                                      flags: inout PaintFlags) -> Bool {
    
    guard let bitmap = image.getBitmapFor(scale: imageScale) else {
      return false
    }
    
    let shaderScale = Mat()

    shaderScale.scale(x: Double(tileScaleX), y: Double(tileScaleY))
    shaderScale.preTranslate(x: Double(-sx), y: Double(-sy))
    shaderScale.postTranslate(x: Double(dx), y: Double(dy))

    flags.shader = PaintShaderFactory.makeImageForScale(bitmap: bitmap, tileMode: .Repeat, matrix: shaderScale, scale: imageScale)
    return true
  }

  public func transform(transform: Transform) {
    paintCanvas.concat(matrix: transform.matrix.toMat3())
  }

  public func intersectsClipRect(rect: FloatRect) -> Bool {
    if let clip = paintCanvas.localClipBounds {
      return clip.intersects(rect: rect)
    }
    return false
  }

  public func drawImageIntHelper(bitmap: Bitmap,
                                 sx: Int,
                                 sy: Int,
                                 sw: Int,
                                 sh: Int,
                                 dx: Int,
                                 dy: Int,
                                 dw: Int,
                                 dh: Int,
                                 filter: Bool,
                                 flags originalFlags: PaintFlags,
                                 removeImageScale: Bool) {

  
    if sw <= 0 || sh <= 0 {
      ////print("Attempting to draw bitmap from an empty rect!")
      return
    }

   
    let destRect = FloatRect(x: Float(dx),
                             y: Float(dy),
                             width: Float(dx + dw),
                             height: Float(dy + dh))

    if !intersectsClipRect(rect: destRect) {
      return
    }

    let userScaleX = Float(dw / sw)
    let userScaleY = Float(dh / sh)

    // Make a bitmap shader that contains the bitmap we want to draw. This is
    // basically what SkCanvas.drawBitmap does internally, but it gives us
    // more control over quality and will use the mipmap in the source image if
    // it has one, whereas drawBitmap won't.

    let shaderScale = Mat()

    shaderScale.scale(x: Double(userScaleX), y: Double(userScaleY))
    shaderScale.preTranslate(x: Double(-sx), y: Double(-sy))
    shaderScale.postTranslate(x: Double(dx), y: Double(dy))

    let flags = originalFlags
    flags.filterQuality = filter ? .Low : .None
    flags.shader = PaintShaderFactory.makeImageForScale(bitmap: bitmap, tileMode: .Repeat, matrix: shaderScale, scale: removeImageScale ? imageScale : 1.0)

    // The rect will be filled by the bitmap.
    paintCanvas.drawRect(destRect, flags: flags)
  }

  public func drawPicture(record: PaintRecord) {
    paintCanvas.drawPicture(record: record) 
  }

  public func drawTextBlob(_ blob: PaintTextBlob, x: Float, y: Float, flags: PaintFlags) {
    paintCanvas.drawTextBlob(blob, x: x, y: y, flags: flags) 
  }

  public static func getStringWidth(text: String, list: FontList) -> Float {
    var width: Float = 0
    var height: Float = 0

    Canvas.sizeString(text: text, list: list, width: &width, height: &height, lineHeight: 0, options: TextOptions.NoEllipsis)
    
    return width
  }

  public static func sizeString(text: String,
                                 list: FontList,
                                 width: inout Float, 
                                 height: inout Float,
                                 lineHeight: Int,
                                 options: TextOptions) {

    var moptions = options

    if options.contains(.Multiline) && width != 0 {
      var wrapBehavior: WordWrapBehavior = .TruncateLongWords
      if options.contains(.CharacterBreak) {
        wrapBehavior = .WrapLongWords
      } else if !options.contains(.NoEllipsis) {
        wrapBehavior = .ElideLongWords
      }

      var strings = [String]()
      let _ = elideRectangleText(text: text, list: list, width: width, height: Int.max, behavior: wrapBehavior, lines: &strings)
      let rect = FloatRect(width: width, height: Float.greatestFiniteMagnitude)
      let renderText = RenderText()
      Canvas.updateRenderText(rect: rect, text: "", list: list, options: &moptions, color: Color(), renderText: renderText)

      var h: Float = 0
      var w: Float = 0
      var i = 0
      for var string in strings {
        let _ = Canvas.stripAcceleratorChars(options: moptions, text: &string)
        renderText.text = string
        let stringSize = renderText.stringSizef
        w = max(w, stringSize.width)
        h += (i > 0 && lineHeight > 0) ? max(Float(lineHeight), stringSize.height) : stringSize.height
        i += i
      }
      width = w
      height = h
    } else {
      let renderText = RenderText()
      let rect = FloatRect(width: width, height: height)
      var adjustedText = text
      let _ = Canvas.stripAcceleratorChars(options: moptions, text: &adjustedText)
      Canvas.updateRenderText(rect: rect, text: adjustedText, list: list, options: &moptions, color: Color(), renderText: renderText)
      let stringSize = renderText.stringSizef
      width = stringSize.width
      height = stringSize.height
    }
  }

  internal static func updateRenderText(rect: FloatRect, 
    text: String,
    list: FontList,
    options: inout TextOptions,
    color: Color,
    renderText: RenderText) {
    
    renderText.fontList = list
    renderText.text = text
    renderText.cursorEnabled = false
    renderText.displayRect = rect

    // Set the text alignment explicitly based on the directionality of the UI,
    // if not specified.
    if !(options.contains(.TextAlignCenter) ||
         options.contains(.TextAlignRight) ||
         options.contains(.TextAlignLeft) ||
         options.contains(.TextAlignToHead)) {
      options.insert(Canvas.defaultCanvasTextAlignment)
    }

    if options.contains(.TextAlignToHead) {
      renderText.horizontalAlignment = .AlignToHead
    } else if options.contains(.TextAlignRight) {
      renderText.horizontalAlignment = .AlignRight
    } else if options.contains(.TextAlignCenter) {
      renderText.horizontalAlignment = .AlignCenter
    } else {
      renderText.horizontalAlignment = .AlignLeft
    }

    renderText.subpixelRenderingSuppressed = options.contains(.NoSubpixelRendering)

    renderText.setColor(color: color)
    let fontStyle = list.fontStyle
    renderText.setStyle(style: .Bold, value: fontStyle.contains(.Bold))
    renderText.setStyle(style: .Italic, value: fontStyle.contains(.Italic))
    renderText.setStyle(style: .Underline, value: fontStyle.contains(.Underline))
    renderText.setWeight(list.fontWeight)
  }

  // Strips accelerator character prefixes in |text| if needed, based on |flags|.
  // Returns a range in |text| to underline or Range::InvalidRange() if
  // underlining is not needed.
  internal static func stripAcceleratorChars(options: TextOptions, text: inout String) -> TextRange {
    if options.contains(.ShowPrefix) || options.contains(.HidePrefix) {
      var charPos = -1
      var charSpan = 0
      text = removeAcceleratorChar(s: text, char: UTF16And, pos: &charPos, span: &charSpan)
      if options.contains(.ShowPrefix) && charPos != -1 {
        return TextRange(start: charPos, end: charPos + charSpan)
      }
    }

    return TextRange.InvalidRange
  }

  internal static func elideTextAndAdjustRange(
    fontList: FontList,
    width: Float,
    text: inout String,
    range: inout TextRange) {
  
    var index = text.index(text.startIndex, offsetBy: range.start)
    let startChar: Character = (range.isValid ? text[index] : Character(""))
    let _ = elideText(text: &text, list: fontList, width: width, behavior: .ElideTail)
    
    if !range.isValid {
      return
    }
    
    index = text.index(text.startIndex, offsetBy: range.start)
    if range.start >= text.count || text[index] != startChar {
      range = TextRange.InvalidRange
    }

  }
  
}