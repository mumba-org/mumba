// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

//fileprivate let UTF16And: UInt16 = 38 // '&'

// public struct TextOptions : OptionSet {
//   public let rawValue: Int
//   // Specifies the alignment for text rendered with the DrawStringRect method.
//   public static let TextAlignLeft = TextOptions(rawValue: 1 << 0)
//   public static let TextAlignCenter = TextOptions(rawValue: 1 << 1)
//   public static let TextAlignRight = TextOptions(rawValue: 1 << 2)
//   public static let TextAlignToHead = TextOptions(rawValue: 1 << 3)

//   // Specifies the text consists of multiple lines.
//   public static let Multiline = TextOptions(rawValue: 1 << 4)

//   // By default DrawStringRect does not process the prefix ('&') character
//   // specially. That is, the string "&foo" is rendered as "&foo". When
//   // rendering text from a resource that uses the prefix character for
//   // mnemonics, the prefix should be processed and can be rendered as an
//   // underline (SHOW_PREFIX), or not rendered at all (HIDE_PREFIX).
//   public static let ShowPrefix = TextOptions(rawValue: 1 << 5)
//   public static let HidePrefix = TextOptions(rawValue: 1 << 6)

//   // Prevent ellipsizing
//   public static let NoEllipsis = TextOptions(rawValue: 1 << 7)

//   // Specifies if words can be split by new lines.
//   // This only works with MULTI_LINE.
//   public static let CharacterBreak = TextOptions(rawValue: 1 << 8)

//   // Instructs DrawStringRect() to not use subpixel rendering.  This is useful
//   // when rendering text onto a fully- or partially-transparent background
//   // that will later be blended with another image.
//   public static let NoSubpixelRendering = TextOptions(rawValue: 1 << 9)

//   public init(rawValue: Int) {
//     self.rawValue = rawValue
//   }
// }

public struct DrawAtlasTransform {
  public var scale: Float = 0.0
  public var radians: Float = 0.0 
  public var tx: Float = 0.0 
  public var ty: Float = 0.0
  public var ax: Float = 0.0
  public var ay: Float = 0.0
}

public class SkiaCanvas {

  // public static var defaultCanvasTextAlignment: TextOptions {
  //   return i18n.isRTL() ? TextOptions.TextAlignRight : TextOptions.TextAlignLeft
  // }

  public var deviceSize: FloatSize {
    var w: Float = 0.0, h: Float = 0.0
    _CanvasGetDeviceSize(reference, &w, &h)
    return FloatSize(width: w, height: h)
  }

   public var localClipBounds: FloatRect? {
    var x: Float = 0.0, y: Float = 0.0, width: Float = 0.0, height: Float = 0.0
    let result = _CanvasGetLocalClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return FloatRect(x: x, y: y, width: width, height: height)
    }
    return nil
  }

  public var deviceClipBounds: IntRect? {
    var x: Int32 = 0, y: Int32 = 0, width: Int32 = 0, height: Int32 = 0
    let result = _CanvasGetDeviceClipBounds(reference, &x, &y, &width, &height)
    if result == 1 {
      return IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height))
    }
    return nil
  }

  public var isClipEmpty: Bool {
    return _CanvasIsClipEmpty(reference) == 0 ? false : true
  }

  public var isClipRect: Bool {
    return _CanvasIsClipRect(reference) == 0 ? false : true
  }

  public var totalMatrix: Mat {
    let ref = _CanvasTotalMatrix(reference)
    return Mat(reference: ref!, owned: false)
  }


  public var saveCount: Int {
    return Int(_CanvasGetSaveCount(reference))
  }

  public private(set) var imageScale: Float

  var _drawFilter: DrawFilter?
  
  public var reference: CanvasRef

  public init() {
    imageScale = 1.0
    reference = _CanvasCreate()
  }

  public init(bitmap: Bitmap) {
    imageScale = 1.0
    reference = _CanvasCreateWithBitmap(bitmap.reference)
  }

  // public init(recorder: PictureRecorder, bounds: IntRect) {
  //   imageScale = 1.0
    
  //   let canvas = recorder.beginRecording(bounds: bounds)
  //   reference = canvas.reference
  // }

  // TODO: this needs to be private
  // maybe provide some constructors
  public init(reference: CanvasRef) {
    imageScale = 1.0
    self.reference = reference
  }

  deinit {
    _CanvasDestroy(reference)
  }

  static public func getStringWidth(text: String, font: FontList) -> Int {
    assert(false)
    return 0
  }

  public func save() -> Int {
    return Int(_CanvasSave(reference))
  }

  public func saveLayer(paint: Paint?) -> Int {
    if let p = paint {
      return Int(_CanvasSaveLayer(reference, p.reference))
    } else {
      return Int(_CanvasSaveLayer(reference, nil))
    }
  }

  public func saveLayer(paint: Paint?, bounds: FloatRect?) -> Int {
    if let rect = bounds {
      if let p = paint {
        return Int(_CanvasSaveLayerRect(reference, rect.x, rect.y, rect.width, rect.height, p.reference))
      } else {
        return Int(_CanvasSaveLayerRect(reference, rect.x, rect.y, rect.width, rect.height, nil))
      }
    } else {
      if let p = paint {
        return Int(_CanvasSaveLayer(reference, p.reference))
      } else {
        return Int(_CanvasSaveLayer(reference, nil))
      }
    }
  }

  public func saveLayerAlpha(alpha: UInt8) -> Int {
    return Int(_CanvasSaveLayerAlpha(reference, alpha))
  }

  public func saveLayerAlpha(alpha: UInt8, bounds: FloatRect?) -> Int {
    if let rect = bounds {
      return Int(_CanvasSaveLayerAlphaRect(reference, alpha, rect.x, rect.y, rect.width, rect.height))
    } else {
      return Int(_CanvasSaveLayerAlpha(reference, alpha))
    }
  }

  public func saveLayerPreserveLCDTextRequests(paint: Paint, bounds: FloatRect?) -> Int {
    if let b = bounds {
      return Int(_CanvasSaveLayerPreserveLCDTextRequestsRect(reference, b.x, b.y, b.width, b.height, paint.reference))
    } else {
      return Int(_CanvasSaveLayerPreserveLCDTextRequests(reference, paint.reference))
    }
  }

  public func restore() {
    _CanvasRestore(reference)
  }

  public func restoreTo(count: Int) {
    _CanvasRestoreToCount(reference, Int32(count))
  }

  public func flush() {
    _CanvasFlush(reference)
  }

  public func translate(offset: IntVec2) {
    translate(x: Float(offset.x), y: Float(offset.y))
  }

  public func translate(offset: FloatVec2) {
    translate(x: offset.x, y: offset.y)
  }

  public func translate(x: Float, y: Float) {
    _CanvasTranslate(reference, x, y)
  }

  public func scale(x: Float, y: Float) {
    _CanvasScale(reference, x, y)
  }

  public func rotate(radians: Float) {
    _CanvasRotate(reference, radians)
  }

  public func skew(x: Float, y: Float) {
    _CanvasSkew(reference, x, y)
  }

  public func concat(matrix: Mat) {
    //_CanvasConcat(reference,
    //  matrix[0],
    //  matrix[1],
    //  matrix[2],
    //  matrix[3],
    //  matrix[4],
    //  matrix[5],
    //  matrix[6],
    //  matrix[7],
    //  matrix[8])
    _CanvasConcatHandle(reference, matrix.reference)
  }

  public func concat(matrix: Mat4) {
    _CanvasConcatHandle(reference, matrix.reference) 
  }

  public func setMatrix(matrix: Mat) {
    //_CanvasSetMatrix(reference,
    //  matrix[0],
    //  matrix[1],
    //  matrix[2],
    //  matrix[3],
    //  matrix[4],
    //  matrix[5],
    //  matrix[6],
    //  matrix[7],
    //  matrix[8])
    _CanvasSetMatrixHandle(reference, matrix.reference)
  }

  public func transform(_ trans: Transform) {
    concat(matrix: trans.matrix)
  }

  public func clipRect(rect: IntRect) {
    clipRect(rect: FloatRect(rect))
  }

  public func clipRect(rect: FloatRect) {
    clipRect(rect: rect, clip: ClipOp.intersect, antiAlias: true)
  }

  public func clipRect(rect: FloatRect, antiAlias: Bool) {
    clipRect(rect: rect, clip: ClipOp.intersect, antiAlias: antiAlias)
  }

  public func clipRect(rect: FloatRect, clip: ClipOp, antiAlias: Bool) {
    _CanvasClipRect(reference, rect.x, rect.y, rect.width, rect.height, Int32(clip.rawValue), antiAlias.intValue)
  }

  public func clipRRect(rrect: FloatRRect) {
    clipRRect(rrect: rrect, clip: ClipOp.intersect, antiAlias: true)
  }

  public func clipRRect(rrect: FloatRRect, antiAlias: Bool) {
    clipRRect(rrect: rrect, clip: ClipOp.intersect, antiAlias: antiAlias)
  }

  public func clipRRect(rrect: FloatRRect, clip: ClipOp, antiAlias: Bool) {
    _CanvasClipRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, Int32(clip.rawValue), antiAlias.intValue)
  }

  public func clipPath(path: Path) {
    clipPath(path: path, clip: ClipOp.intersect, antiAlias: true)
  }

  public func clipPath(path: Path, antiAlias: Bool) {
    clipPath(path: path, clip: ClipOp.intersect, antiAlias: antiAlias)
  }

  public func clipPath(path: Path, clip: ClipOp, antiAlias: Bool) {
    _CanvasClipPath(reference, path.reference, Int32(clip.rawValue), antiAlias.intValue)
  }

  public func readImage() -> Image? {
    let size = deviceSize
    var result = Bitmap(size: size)
    if readPixels(bitmap: &result, x: 0, y: 0) {
      return ImageSkia(bitmap: result, scale: imageScale) 
    }
    return nil
  }

  public func fillRect(rect: FloatRect, color: Color, mode: BlendMode = .SrcOver) {
    let paint = Paint()
    paint.color = color
    paint.style = .Fill
    paint.mode = mode
    drawRect(rect: rect, paint: paint)
  }

  public func readPixels(bitmap: inout Bitmap, x: Int, y: Int) -> Bool {
    return _CanvasReadPixelsXY(reference, bitmap.reference, Int32(x), Int32(y)) == 0 ? false : true
  }

  // public func readPixels(bitmap: inout Bitmap, rect r: IntRect) -> Bool {
  //   return _CanvasReadPixelsRect(reference, bitmap.reference, Int32(r.x), Int32(r.y), Int32(r.width), Int32(r.height)) == 0 ? false : true
  // }

  public func writePixels(bitmap: Bitmap, x: Int, y: Int) -> Bool {
    return _CanvasWritePixels(reference, bitmap.reference, Int32(x), Int32(y)) == 0 ? false : true
  }

  public func clear(color: Color) {
    _CanvasDrawColor(reference, color.a, color.r, color.g, color.b, BlendMode.Src.rawValue)
  }

  public func clearRect(_ rect: IntRect) {
    let paint = Paint()
    paint.color = Color.Black
    drawRect(rect: FloatRect(rect), paint: paint)
  }

  public func clearRect(_ rect: FloatRect) {
    let paint = Paint()
    paint.color = Color.Black
    drawRect(rect: rect, paint: paint)
  }

  public func drawColor(color: Color, transferMode: BlendMode = .SrcOver) {
    _CanvasDrawColor(reference, color.a, color.r, color.g, color.b, transferMode.rawValue)
  }

  public func drawLine(p1: FloatPoint, p2: FloatPoint, paint: Paint) {
    _CanvasDrawLine(reference, p1.x, p1.y, p2.x, p2.y, paint.reference)
  }

  public func drawPaint(paint: Paint) {
    _CanvasDrawPaint(reference, paint.reference)
  }

  public func drawRegion(region: Region, paint: Paint) {
    _CanvasDrawRegion(reference, region.reference, paint.reference)
  }

  public func drawRect(rect: FloatRect, paint: Paint) {
    _CanvasDrawRect(reference, rect.x, rect.y, rect.width, rect.height, paint.reference)
  }

  public func drawIRect(rect: IntRect, paint: Paint) {
    _CanvasDrawIRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height), paint.reference)
  }

  public func drawRoundRect(rect: FloatRect, x: Float, y: Float, paint: Paint) {
    _CanvasDrawRoundRect(reference, rect.x, rect.y, rect.width, rect.height, x, y, paint.reference)
  }

  public func drawRRect(rrect: FloatRRect, paint: Paint) {
    _CanvasDrawRRect(reference, rrect.x, rrect.y, rrect.width, rrect.height, paint.reference)
  }

  public func drawDRRect(outer: FloatRRect, inner: FloatRRect, paint: Paint) {
    _CanvasDrawDRRect(reference, outer.x, outer.y, outer.width, outer.height, inner.x, inner.y, inner.width, inner.height, paint.reference)
  }

  public func drawOval(rect: FloatRect, paint: Paint) {
    _CanvasDrawOval(reference, rect.x, rect.y, rect.width, rect.height, paint.reference)
  }

  public func drawCircle(p: FloatPoint, radius: Float, paint: Paint) {
    _CanvasDrawCircle(reference, p.x, p.y, radius, paint.reference)
  }
  
  // public func drawFocusRect(rect: FloatRect) {
  //   drawDashedRect(rect: rect, color: Color.Gray)
  // }

  // public func drawSolidFocusRect(rect: FloatRect, color: Color) {
  //   let paint = Paint()
  //   paint.color = color
  //   paint.strokeWidth = 1
  //   // Note: We cannot use DrawRect since it would create a path and fill it which
  //   // would cause problems near the edge of the canvas.
  //   let x1 = min(rect.x, rect.right)
  //   let x2 = max(rect.x, rect.right)
  //   let y1 = min(rect.y, rect.bottom)
  //   let y2 = max(rect.y, rect.bottom)
  //   drawLine(p1: FloatPoint(x: x1, y: y1), p2: FloatPoint(x: x2, y: y1), paint: paint)
  //   drawLine(p1: FloatPoint(x: x1, y: y2), p2: FloatPoint(x: x2, y: y2), paint: paint)
  //   drawLine(p1: FloatPoint(x: x1, y: y1), p2: FloatPoint(x: x1, y: y2), paint: paint)
  //   drawLine(p1: FloatPoint(x: x2, y: y1), p2: FloatPoint(x: x2, y: y2 + 1), paint: paint)
  // }

  // // DEPRECATED: moved to Canvas.drawDashedRect
  // public func drawDashedRect(rect: FloatRect, color: Color) {
    
  //   guard !rect.isEmpty else {
  //     return
  //   }
  //   // Create a 2D bitmap containing alternating on/off pixels - we do this
  //   // so that you never get two pixels of the same color around the edges
  //   // of the focus rect (this may mean that opposing edges of the rect may
  //   // have a dot pattern out of phase to each other).
    
  //   // TODO: eram 'static' no C++ e portanto
  //   // podiam cachear os resultados anteriores
  //   // por isso o check == nil depois
  //   //
  //   var lastColor: Color? = nil
  //   var dots: Bitmap? = nil
  //   if dots == nil || lastColor != color {
  //     let colPixels = 32
  //     let rowPixels = 32

  //     lastColor = color
  //     dots = Bitmap()
  //     dots!.allocatePixels(width: Float(colPixels), height: Float(rowPixels))
  //     dots!.erase(a: 0, r: 0, g: 0, b: 0)
  //     // TODO: criar um closure pra processar os pixels
  //     dots!.withUnsafeMutablePixelBuffer { dot in
  //       for i in 0...rowPixels {
  //         for u in 0...colPixels {
  //           if (u % 2 + i % 2) % 2 != 0 {
  //             dot[i * rowPixels + u] = color.value
  //           }
  //         }
  //       }
  //     }
  //   }

  //   // Make a shader for the bitmap with an origin of the box we'll draw. This
  //   // shader is refcounted and will have an initial refcount of 1.
  //   let shader = DefaultShaderFactory.makeBitmap(bitmap: dots!, x: .Repeat, y: .Repeat, matrix: nil)
  //   // Assign the shader to the paint & release our reference. The paint will
  //   // now own the shader and the shader will be destroyed when the paint goes
  //   // out of scope.
  //   let paint = Paint()
  //   paint.shader = shader

  //   drawRect(rect: FloatRect(x: rect.x, y: rect.y, width: rect.width, height: 1), paint: paint)
  //   drawRect(rect: FloatRect(x: rect.x, y: rect.y + rect.height - 1, width: rect.width, height: 1), paint: paint)
  //   drawRect(rect: FloatRect(x: rect.x, y: rect.y, width: 1, height: rect.height), paint: paint)
  //   drawRect(rect: FloatRect(x: rect.x + rect.width - 1, y: rect.y, width: 1, height: rect.height), paint: paint)
  // }

//   // DEPRECATED: moved to Canvas
//   public func drawStringRect(text: String,
//                              font: FontList,
//                              color: Color,
//                              rect displayRect: FloatRect) {
//     drawStringRect(
//       text: text, 
//       font: font,
//       color: color,
//       rect: displayRect, 
//       flags: i18n.isRTL() ? TextOptions.TextAlignRight : TextOptions.TextAlignLeft)
//   }

//   // DEPRECATED: moved to Canvas
//   public func drawStringRect(text: String,
//                              font fontList: FontList,
//                              color: Color,
//                              rect displayRect: FloatRect,
//                              flags: TextOptions) {
//     var mflags = flags

//     guard intersectsClipRect(rect: displayRect) else {
//       return
//     }

//     let _ = save()
    
//     clipRect(rect: displayRect)

//     var rect = displayRect

//     let renderText = RenderText()

//     if flags.contains(.Multiline) {
//       var wrapBehavior: WordWrapBehavior = .IgnoreLongWords
//       if flags.contains(.CharacterBreak) {
//         wrapBehavior = .WrapLongWords
//       } else if !flags.contains(.NoEllipsis) {
//         wrapBehavior = .ElideLongWords
//       }

//       var strings: [String] = []
     
//       elideRectangleText(text: text, 
//                          list: fontList,
//                          width: displayRect.width,
//                          height: Int(displayRect.height), 
//                          behavior: wrapBehavior, 
//                          lines: &strings)

//       for i in 0..<strings.count {
//         let range: TextRange = Canvas.stripAcceleratorChars(options: flags, text: &strings[i])
//         Canvas.updateRenderText(rect: rect, text: strings[i], list: fontList, options: &mflags, color: color, renderText: renderText)
//         let linePadding: Float = 0.0
//         let lineHeight = Float(renderText.stringSize.height)

//         // TODO(msw|asvitkine): Center Windows multi-line text: crbug.com/107357
// #if !os(Windows)
//         if i == 0 {
//           // TODO(msw|asvitkine): Support multi-line text with varied heights.
//           let textHeight = Float(strings.count) * lineHeight - linePadding
//           rect += FloatVec2(x: 0, y: (displayRect.height - textHeight) / 2.0)
//         }
// #endif

//         rect.height = lineHeight - linePadding

//         if range.isValid {
//           renderText.applyStyle(style: .Underline, value: true, range: range)
//         }
//         renderText.displayRect = rect
//         renderText.draw(canvas: self)
//         rect += FloatVec2(x: 0, y: lineHeight)
//       }
//     } else {
//       var adjustedText = text
//       var range: TextRange = Canvas.stripAcceleratorChars(options: flags, text: &adjustedText)
//       var elideText: Bool = !flags.contains(.NoEllipsis)

// #if os(Linux)
//       // On Linux, eliding really means fading the end of the string. But only
//       // for LTR text. RTL text is still elided (on the left) with "...".
//       if elideText {
//         renderText.text = adjustedText
//         if renderText.displayTextDirection == .LeftToRight {
//           renderText.elideBehavior = .FadeTail
//           elideText = false
//         }
//       }
// #endif

//       if elideText {
//         Canvas.elideTextAndAdjustRange(
//                                 fontList: fontList,
//                                 width: displayRect.width,
//                                 text: &adjustedText, 
//                                 range: &range)
//       }

//       Canvas.updateRenderText(
//         rect: rect, 
//         text: adjustedText, 
//         list: fontList, 
//         options: &mflags, 
//         color: color,
//         renderText: renderText)

//       if range.isValid {
//         renderText.applyStyle(style: .Underline, value: true, range: range)
//       }
//       renderText.draw(canvas: self)
//     }

//     restore()
//   }

  public func drawText(text: String, x: Float, y: Float, paint: Paint) {
    text.withCString { ptr in 
      _CanvasDrawText(reference, ptr, text.utf16.count, x, y, paint.reference)
    }
  }

  public func drawText(text: String, pos: [FloatPoint], paint: Paint) {
    var x: [Float] = []
    var y: [Float] = []

    for point in pos {
      x.append(point.x)
      y.append(point.y)
    }

    text.withCString { ptr in
      x.withUnsafeBufferPointer { xbuf in
        y.withUnsafeBufferPointer { ybuf in 
          _CanvasDrawPosText(reference, ptr, text.utf16.count, xbuf.baseAddress, ybuf.baseAddress, Int32(pos.count), paint.reference)
        }
      }
    }
  }

  public func drawText(glyphs: [UInt16], len: Int, pos: [FloatPoint], paint: Paint) {
    var x: [Float] = []
    var y: [Float] = []

    paint.color = Color.Black
   
    for point in pos {
      x.append(point.x)
      y.append(point.y)
    }

    x.withUnsafeBufferPointer { xbuf in
      y.withUnsafeBufferPointer { ybuf in
        glyphs.withUnsafeBufferPointer { glyphbuf in
          _CanvasDrawPosText(reference, glyphbuf.baseAddress, (len * 2), xbuf.baseAddress, ybuf.baseAddress, Int32(pos.count), paint.reference)
        }
      }
    }
  }

  public func drawTextBlob(text: PaintTextBlob, x: Float, y: Float, paint: Paint) {
    _CanvasDrawTextBlob(reference, text.reference, x, y, paint.reference)
  }

  public func drawPath(path: Path, paint: Paint) {
    _CanvasDrawPath(reference, path.reference, paint.reference)
  }

  public func drawImage(image: Image, p: FloatPoint, paint: Paint) {
    let imageSkia = image as! ImageSkia
    _CanvasDrawImage(reference, imageSkia.reference, p.x, p.y, paint.reference)
  }

  public func drawImageRect(image: Image, src: FloatRect, dst: FloatRect, paint: Paint) {
    let imageSkia = image as! ImageSkia
    _CanvasDrawImageRect(reference, imageSkia.reference, src.x, src.y, src.width, src.height,
      dst.x, dst.y, dst.width, dst.height, paint.reference)
  }

  public func drawImageNine(image: Image, center: FloatRect, dst: FloatRect, paint: Paint) {
    let imageSkia = image as! ImageSkia
    _CanvasDrawImageNine(reference, imageSkia.reference, center.x, center.y, center.width,
      center.height, dst.x, dst.y, dst.width, dst.height, paint.reference)
  }

  public func drawPicture(picture: Picture) {
    _CanvasDrawPicture(reference, picture.reference)
  }

  public func drawDrawable(_ drawable: Drawable) {
    let concrete = drawable as! DrawableSkia
    _CanvasDrawDrawable(reference, concrete.reference)
  }

  public func drawDrawable(_ drawable: Drawable, at p: FloatPoint) {
    let concrete = drawable as! DrawableSkia
    _CanvasDrawDrawableAt(reference, concrete.reference, p.x, p.y)
  }

  public func drawBitmap(bitmap: Bitmap, left: Float, top: Float, paint: Paint? = nil) {
    var phandle: PaintRef? = nil
    if let p = paint { phandle = p.reference }
    _CanvasDrawBitmap(reference, bitmap.reference, left, top, phandle)
  }

  public func drawBitmapRect(bitmap: Bitmap, src: FloatRect, dst: FloatRect, paint: Paint?) {
    var phandle: PaintRef? = nil
    if let p = paint { phandle = p.reference }
    _CanvasDrawBitmapRectSrcDst(reference, bitmap.reference, src.x, src.y, src.width, src.height, dst.x, dst.y, dst.width, dst.height, phandle)
  }

  public func drawBitmapRect(bitmap: Bitmap, dst: FloatRect, paint: Paint?) {
    var phandle: PaintRef? = nil
    if let p = paint { phandle = p.reference }
    _CanvasDrawBitmapRectDst(reference, bitmap.reference, dst.x, dst.y, dst.width, dst.height, phandle)
  }

  public func drawBitmapNine(bitmap: Bitmap, center: FloatRect, dst: FloatRect, paint: Paint?) {
    var phandle: PaintRef? = nil
    if let p = paint { phandle = p.reference }
    _CanvasDrawBitmapNine(reference, bitmap.reference, center.x, center.y, center.width, center.height, dst.x, dst.y, dst.width, dst.height, phandle)
  }

  // public func drawSprite(bitmap: Bitmap, left: Int, top: Int, paint: Paint? = nil) {
  //   var phandle: PaintRef? = nil
  //   if let p = paint { phandle = p.reference }
  //   _CanvasDrawSprite(reference, bitmap.reference, Int32(left), Int32(top), phandle)
  // }

  public func drawVertices(
    vertexMode: VertexMode,
    vertices: [FloatPoint],
    textureCoordinates: [FloatPoint],
    colors: [Color],
    mode: BlendMode,
    indices: [Int],
    paint: Paint) {

    var vx = ContiguousArray<Float>()
    var vy = ContiguousArray<Float>()
    
    var tx = ContiguousArray<Float>()
    var ty = ContiguousArray<Float>()

    var colorsArray = ContiguousArray<CInt>()
    var indicesArray = ContiguousArray<CInt>()
    
    for vertice in vertices {
      vx.append(vertice.x)
      vy.append(vertice.y)
    }

    for coord in textureCoordinates {
      tx.append(coord.x)
      ty.append(coord.y)
    }

    for color in colors {
      colorsArray.append(CInt(color.value))
    }

    for indice in indices {
      indicesArray.append(CInt(indice))
    }

    var vxPtr: UnsafeMutableBufferPointer<Float>?
    var vyPtr: UnsafeMutableBufferPointer<Float>?
    
    var txPtr: UnsafeMutableBufferPointer<Float>?
    var tyPtr: UnsafeMutableBufferPointer<Float>?
    
    var colorPtr: UnsafeMutableBufferPointer<CInt>?
    var indicePtr: UnsafeMutableBufferPointer<CInt>?
    
    vx.withUnsafeMutableBufferPointer { vxPtr = $0}
    vy.withUnsafeMutableBufferPointer { vyPtr = $0}
    
    tx.withUnsafeMutableBufferPointer { txPtr = $0}
    ty.withUnsafeMutableBufferPointer { tyPtr = $0}

    colorsArray.withUnsafeMutableBufferPointer { colorPtr = $0}
    indicesArray.withUnsafeMutableBufferPointer { indicePtr = $0 }
    
    _CanvasDrawVertices(
        reference,
        CInt(vertexMode.rawValue),
        vxPtr!.baseAddress,
        vyPtr!.baseAddress,
        txPtr!.baseAddress,
        tyPtr!.baseAddress,
        colorPtr!.baseAddress,
        CInt(vertices.count),
        CInt(mode.rawValue),
        indicePtr!.baseAddress,
        CInt(indices.count),
        paint.reference)
  }

  public func drawAtlas(
    atlas: ImageSkia,
    transforms: [DrawAtlasTransform],
    textures: [FloatRect],
    colors: [Color],
    mode: BlendMode,
    cullRect: FloatRect,
    paint: Paint) {
    
    var rx = ContiguousArray<Float>()
    var ry = ContiguousArray<Float>()
    var rw = ContiguousArray<Float>()
    var rh = ContiguousArray<Float>()

    var scale = ContiguousArray<Float>()
    var radians = ContiguousArray<Float>()
    var tx = ContiguousArray<Float>()
    var ty = ContiguousArray<Float>()
    var ax = ContiguousArray<Float>()
    var ay = ContiguousArray<Float>()

    var colorsArray = ContiguousArray<CInt>()
    
    for r in textures {
      rx.append(r.x)
      ry.append(r.y)
      rw.append(r.width)
      rh.append(r.height)
    }

    for t in transforms {
      scale.append(t.scale)
      radians.append(t.radians)
      tx.append(t.tx)
      ty.append(t.ty)
      ax.append(t.ax)
      ay.append(t.ay)
    }

    for color in colors {
      colorsArray.append(CInt(color.value))
    }

    var txScalePtr: UnsafeMutableBufferPointer<Float>?
    var txRadiansPtr: UnsafeMutableBufferPointer<Float>?
    var txTxPtr: UnsafeMutableBufferPointer<Float>?
    var txTyPtr: UnsafeMutableBufferPointer<Float>?
    var txAxPtr: UnsafeMutableBufferPointer<Float>?
    var txAyPtr: UnsafeMutableBufferPointer<Float>?

    var rxPtr: UnsafeMutableBufferPointer<Float>?
    var ryPtr: UnsafeMutableBufferPointer<Float>?
    var rwPtr: UnsafeMutableBufferPointer<Float>?
    var rhPtr: UnsafeMutableBufferPointer<Float>?
    
    var colorPtr: UnsafeMutableBufferPointer<CInt>?
    
    rx.withUnsafeMutableBufferPointer { rxPtr = $0 }
    ry.withUnsafeMutableBufferPointer { ryPtr = $0 }
    rw.withUnsafeMutableBufferPointer { rhPtr = $0 }
    rh.withUnsafeMutableBufferPointer { rwPtr = $0 }

    scale.withUnsafeMutableBufferPointer { txScalePtr = $0 }
    radians.withUnsafeMutableBufferPointer { txRadiansPtr = $0 }
    tx.withUnsafeMutableBufferPointer { txTxPtr = $0 }
    ty.withUnsafeMutableBufferPointer { txTyPtr = $0 }
    ax.withUnsafeMutableBufferPointer { txAxPtr = $0 }
    ay.withUnsafeMutableBufferPointer { txAyPtr = $0 }

    colorsArray.withUnsafeMutableBufferPointer { colorPtr = $0 }

    _CanvasDrawAtlas(
      reference,
      atlas.reference,
      txScalePtr!.baseAddress,
      txRadiansPtr!.baseAddress, 
      txTxPtr!.baseAddress,
      txTyPtr!.baseAddress,
      txAxPtr!.baseAddress,
      txAyPtr!.baseAddress,
      rxPtr!.baseAddress,
      ryPtr!.baseAddress,
      rwPtr!.baseAddress,
      rhPtr!.baseAddress,
      colorPtr!.baseAddress,
      CInt(textures.count),
      CInt(mode.rawValue),
      cullRect.x,
      cullRect.y,
      cullRect.width,
      cullRect.height,
      paint.reference)
  }

  // // deprecated: Now on Canvas
  // public func drawImage(image: Image, x: Float, y: Float) {
  //   let paint = Paint()
  //   drawImage(image: image, x: x, y: y, paint: paint)
  // }

  // // deprecated: Now on Canvas
  // public func drawImage(image: Image, x: Float, y: Float, a: UInt8) {
  //   let paint = Paint()
  //   paint.alpha = a
  //   drawImage(image: image, x: x, y: y, paint: paint)
  // }

  // // deprecated: Now on Canvas
  // public func drawImage(image: Image,
  //                       x: Float,
  //                       y: Float,
  //                       paint: Paint) {
    
  //   let bitmap = image.bitmap
    
  //   guard !bitmap.isNull else {
  //     return
  //   }
  
  //   let bitmapScale = image.scale

  //   scale(x: 1.0 / bitmapScale,
  //         y: 1.0 / bitmapScale)
    
  //   drawBitmap(bitmap: bitmap,
  //              left: x * bitmapScale,
  //              top:  y * bitmapScale,
  //              paint: paint)
  // }

  // public func drawImage(image: Image,
  //                       sx: Float,
  //                       sy: Float,
  //                       sw: Float,
  //                       sh: Float,
  //                       dx: Float,
  //                       dy: Float,
  //                       dw: Float,
  //                       dh: Float,
  //                       filter: Bool) {
  //   let paint = Paint()
  //   drawImage(image: image, 
  //             sx: sx, 
  //             sy: sy, 
  //             sw: sw, 
  //             sh: sh, 
  //             dx: dx, 
  //             dy: dy,
  //             dw: dw, 
  //             dh: dh, 
  //             filter: filter, 
  //             paint: paint)
  // }

  // public func drawImage(image: Image,
  //                       sx: Float,
  //                       sy: Float,
  //                       sw: Float,
  //                       sh: Float,
  //                       dx: Float,
  //                       dy: Float,
  //                       dw: Float,
  //                       dh: Float,
  //                       filter: Bool,   
  //                       paint: Paint) {
    
  //   guard !image.isNull else {
  //     return
  //   }
  
  //   drawImageHelper(image: image, 
  //                   sx: sx, 
  //                   sy: sy, 
  //                   sw: sw, 
  //                   sh: sh, 
  //                   dx: dx, 
  //                   dy: dy,
  //                   dw: dw, 
  //                   dh: dh, 
  //                   filter: filter, 
  //                   paint: paint, 
  //                   pixel: false)
  // }

  // public func drawImageInPixel(image: Image,
  //                              dx: Float,
  //                              dy: Float,
  //                              dw: Float,
  //                              dh: Float,
  //                              filter: Bool,   
  //                              paint: Paint) {
   
  //   drawImageHelper(image: image, 
  //                   sx: 0, 
  //                   sy: 0,
  //                   sw: image.pixelWidth,
  //                   sh: image.pixelHeight,
  //                   dx: dx, 
  //                   dy: dy,
  //                   dw: dw, 
  //                   dh: dh, 
  //                   filter: filter, 
  //                   paint: paint, 
  //                   pixel: true)
  // }

  // public func drawImageInPath(image: Image,
  //                             x: Float,
  //                             y: Float,
  //                             path: Path,
  //                             paint: Paint) {
  //   guard !image.isNull else {
  //     return
  //   }

  //   let matrix = Mat()
  //   matrix.translate(x: Double(x), y: Double(y))

  //   let shader = DefaultShaderFactory.makeImage(image: image, mode: .Repeat, matrix: matrix, scale: image.scale)

  //   let p = Paint(paint: paint)
  //   p.shader = shader
  //   drawPath(path: path, paint: p)
  // }

  // public func tileImage(image: Image,
  //                       x: Float,
  //                       y: Float,
  //                       w: Float,
  //                       h: Float) {
  //   tileImage(image: image, sx: 0, sy: 0, dx: x, dy: y, w: w, h: h)
  // }

  // public func tileImage(image: Image,
  //                       sx: Float,
  //                       sy: Float,
  //                       dx: Float,
  //                       dy: Float,
  //                       w: Float,
  //                       h: Float) {
  
  //   tileImage(image: image, sx: sx, sy: sy, tx: 1.0, ty: 1.0, dx: dx, dy: dy, w: w, h: h)
  // }

  // public func tileImage(image: Image,
  //                       sx: Float,
  //                       sy: Float,
  //                       tx tileScaleX: Float,
  //                       ty tileScaleY: Float,
  //                       dx: Float,
  //                       dy: Float,
  //                       w: Float,
  //                       h: Float) {

  //   guard intersectsClipRect(x: dx, y: dy, w: w, h: h) else {
  //     return
  //   }

  //   guard !image.isNull else{
  //     return
  //   }

  //   let shaderScale = Mat()
    
  //   shaderScale.scale(x: Double(tileScaleX), y: Double(tileScaleY))
  //   shaderScale.preTranslate(x: Double(-sx), y: Double(-sy))
  //   shaderScale.postTranslate(x: Double(dx), y: Double(dy))

  //   let shader = DefaultShaderFactory.makeImage(image: image, mode: .Repeat, matrix: shaderScale, scale: image.scale)

  //   let paint = Paint()
  //   paint.shader = shader
  //   paint.mode = .SrcOver

  //   let destRect = FloatRect(x: dx,
  //                       y: dy,
  //                       width: dx + w,
  //                       height: dy + h)
    
  //   drawRect(rect: destRect, paint: paint)
  // }

  // public func undoDeviceScaleFactor() -> Float {
  //   let scaleFactor = 1.0 / imageScale
  //   scale(x: scaleFactor, y: scaleFactor)
  //   return imageScale
  // }

  // func intersectsClipRect(x: Float, y: Float, w: Float, h: Float) -> Bool {
  //   if let clip = localClipBounds {
  //     return clip.intersects(x: x, y: y, w: x + w, h: y + h)
  //   }
  //   return false
  // }

  // func intersectsClipRect(rect: FloatRect) -> Bool {
  //   return intersectsClipRect(x: rect.x, y: rect.y, w: rect.width, h: rect.height)
  // }

  // func drawImageHelper(image: Image,
  //                      sx: Float,
  //                      sy: Float,
  //                      sw: Float,
  //                      sh: Float,
  //                      dx: Float,
  //                      dy: Float,
  //                      dw: Float,
  //                      dh: Float,
  //                      filter: Bool,
  //                      paint: Paint,
  //                      pixel: Bool) {

  //   //assert(src_x + src_w < std::numeric_limits<int16_t>::max() &&
  //   //            src_y + src_h < std::numeric_limits<int16_t>::max());
  
  //   if sw <= 0 || sh <= 0 {
  //     ////print("Attempting to draw bitmap from an empty rect!")
  //     return
  //   }

  //   if !intersectsClipRect(x: dx, y: dy, w: dw, h: dh) {
  //     return
  //   }

  //   let userScaleX = Double(dw / sw)
  //   let userScaleY = Double(dh / sh)

  //   let destRect = FloatRect(x: dx,
  //                            y: dy,
  //                            width: dx + dw,
  //                            height: dy + dh)

  //   if sw == dw && sh == dh && userScaleX == 1.0 && userScaleY == 1.0 && image.scale == 1.0 && !pixel {
  //     // Workaround for apparent bug in Skia that causes image to occasionally
  //     // shift.
  //     let srcRect = FloatRect(x: sx, y: sy, width: sx + sw, height: sy + sh)
  //     let bitmap = image.bitmap
  //     drawBitmapRect(bitmap: bitmap, src: srcRect, dst: destRect, paint: paint)
  //     return
  //   }

  //   // Make a bitmap shader that contains the bitmap we want to draw. This is
  //   // basically what SkCanvas.drawBitmap does internally, but it gives us
  //   // more control over quality and will use the mipmap in the source image if
  //   // it has one, whereas drawBitmap won't.
  //   let shaderScale = Mat()

  //   shaderScale.scale(x: userScaleX, y: userScaleY)
  //   shaderScale.preTranslate(x: Double(-sx), y: Double(-sy))
  //   shaderScale.postTranslate(x: Double(dx), y: Double(dy))

  //   let shader = DefaultShaderFactory.makeImage(
  //       image: image,
  //       mode: .Repeat,
  //       matrix: shaderScale,
  //       scale: pixel ? 1.0 : image.scale)

  //   // Set up our paint to use the shader & release our reference (now just owned
  //   // by the paint).
  //   let p = Paint(paint: paint)
  //   p.filterQuality = (filter ? .Low : .None)
  //   p.shader = shader

  //   // The rect will be filled by the bitmap.
  //   drawRect(rect: destRect, paint: p)
  // }

    // TODO: cleanup things here!! these methods are not in the right place and they are ugly

  // public static func getStringWidthf(text: String, list: FontList) -> Float {
  //   var width: Float = 0
  //   var height: Float = 0

  //   Canvas.sizeStringf(text: text, list: list, width: &width, height: &height, lineHeight: 0, options: TextOptions.NoEllipsis)
    
  //   return width
  // }

  // public static func sizeStringf(text: String,
  //                                list: FontList,
  //                                width: inout Float, 
  //                                height: inout Float,
  //                                lineHeight: Int,
  //                                options: TextOptions) {

  //   var moptions = options

  //   if options.contains(.Multiline) && width != 0 {
  //     var wrapBehavior: WordWrapBehavior = .TruncateLongWords
  //     if options.contains(.CharacterBreak) {
  //       wrapBehavior = .WrapLongWords
  //     } else if !options.contains(.NoEllipsis) {
  //       wrapBehavior = .ElideLongWords
  //     }

  //     var strings = [String]()
  //     let _ = elideRectangleText(text: text, list: list, width: width, height: Int.max, behavior: wrapBehavior, lines: &strings)
  //     let rect = FloatRect(width: width, height: Float.greatestFiniteMagnitude)
  //     let renderText = RenderText()
  //     Canvas.updateRenderText(rect: rect, text: "", list: list, options: &moptions, color: Color(), renderText: renderText)

  //     var h: Float = 0
  //     var w: Float = 0
  //     var i = 0
  //     for var string in strings {
  //       let _ = Canvas.stripAcceleratorChars(options: moptions, text: &string)
  //       renderText.text = string
  //       let stringSize = renderText.stringSizef
  //       w = max(w, stringSize.width)
  //       h += (i > 0 && lineHeight > 0) ? max(Float(lineHeight), stringSize.height) : stringSize.height
  //       i += i
  //     }
  //     width = w
  //     height = h
  //   } else {
  //     let renderText = RenderText()
  //     let rect = FloatRect(width: width, height: height)
  //     var adjustedText = text
  //     let _ = Canvas.stripAcceleratorChars(options: moptions, text: &adjustedText)
  //     Canvas.updateRenderText(rect: rect, text: adjustedText, list: list, options: &moptions, color: Color(), renderText: renderText)
  //     let stringSize = renderText.stringSizef
  //     width = stringSize.width
  //     height = stringSize.height
  //   }
  // }

  // internal static func updateRenderText(rect: FloatRect, 
  //   text: String,
  //   list: FontList,
  //   options: inout TextOptions,
  //   color: Color,
  //   renderText: RenderText) {
    
  //   renderText.fontList = list
  //   renderText.text = text
  //   renderText.cursorEnabled = false
  //   renderText.displayRect = rect

  //   // Set the text alignment explicitly based on the directionality of the UI,
  //   // if not specified.
  //   if !(options.contains(.TextAlignCenter) ||
  //        options.contains(.TextAlignRight) ||
  //        options.contains(.TextAlignLeft) ||
  //        options.contains(.TextAlignToHead)) {
  //     options.insert(Canvas.defaultCanvasTextAlignment)
  //   }

  //   if options.contains(.TextAlignToHead) {
  //     renderText.horizontalAlignment = .AlignToHead
  //   } else if options.contains(.TextAlignRight) {
  //     renderText.horizontalAlignment = .AlignRight
  //   } else if options.contains(.TextAlignCenter) {
  //     renderText.horizontalAlignment = .AlignCenter
  //   } else {
  //     renderText.horizontalAlignment = .AlignLeft
  //   }

  //   renderText.subpixelRenderingSuppressed = options.contains(.NoSubpixelRendering)

  //   renderText.setColor(color: color)
  //   let fontStyle = list.fontStyle
  //   renderText.setStyle(style: .Bold, value: fontStyle.contains(.Bold))
  //   renderText.setStyle(style: .Italic, value: fontStyle.contains(.Italic))
  //   renderText.setStyle(style: .Underline, value: fontStyle.contains(.Underline))
  //   renderText.setWeight(list.fontWeight)
  // }

  // // Strips accelerator character prefixes in |text| if needed, based on |flags|.
  // // Returns a range in |text| to underline or Range::InvalidRange() if
  // // underlining is not needed.
  // internal static func stripAcceleratorChars(options: TextOptions, text: inout String) -> TextRange {
  //   if options.contains(.ShowPrefix) || options.contains(.HidePrefix) {
  //     var charPos = -1
  //     var charSpan = 0
  //     text = removeAcceleratorChar(s: text, char: UTF16And, pos: &charPos, span: &charSpan)
  //     if options.contains(.ShowPrefix) && charPos != -1 {
  //       return TextRange(start: charPos, end: charPos + charSpan)
  //     }
  //   }

  //   return TextRange.InvalidRange
  // }

  // internal static func elideTextAndAdjustRange(
  //   fontList: FontList,
  //   width: Float,
  //   text: inout String,
  //   range: inout TextRange) {
  
  //   var index = text.index(text.startIndex, offsetBy: range.start)
  //   let startChar: Character = (range.isValid ? text[index] : Character(""))
  //   let _ = elideText(text: &text, list: fontList, width: width, behavior: .ElideTail)
    
  //   if !range.isValid {
  //     return
  //   }
    
  //   index = text.index(text.startIndex, offsetBy: range.start)
  //   if range.start >= text.count || text[index] != startChar {
  //     range = TextRange.InvalidRange
  //   }

  // }

}

public final class NoDrawSkiaCanvas : SkiaCanvas {

  public init(width: Int, height: Int) {
    let ref = _NoDrawCanvasCreate(Int32(width), Int32(height))
    super.init(reference: ref!)
  }

  public func resetCanvas(width: Int, height: Int) {
    _NoDrawCanvasResetCanvas(reference, Int32(width), Int32(height))
  }

}
