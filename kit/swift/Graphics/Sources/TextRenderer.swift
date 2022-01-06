// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc // for floor, ceil
#endif

// Fraction of the text size to use for a strike through or under-line.
let LineThickness = (1 / 18)
// Fraction of the text size to lower a strike through below the baseline.
let StrikeThroughOffset = (-1 * 6 / 21)
// Fraction of the text size to lower an underline below the baseline.
let UnderlineOffset = (1 / 9)

let UnderlineMetricsNotSet = -1

// Fraction of the text size to use for a top margin of a diagonal strike.
let DiagonalStrikeMarginOffset  = (1 / 4)

// Helper class to draw text through Skia.
public class TextRenderer {

  public var drawLooper: DrawLooper? {
    get {
      return flags.looper
    }
    set {
      if let looper = newValue {
        flags.looper = looper
      }
    }
  }

  public var typeface: Typeface? {
    get {
      return flags.typeface
    }
    set {
      if let tface = newValue {
        flags.typeface = tface
      }
    }
  }
  
  public var textSize: Int {
    get {
      return Int(flags.textSize)
    }
    set {
      flags.textSize = Float(newValue)
    }
  }

  public var foreground: Color {
    get {
      return flags.color
    }
    set {
      flags.color = newValue
    }
  }
  
  public var shader: PaintShader? {
    get {
      return flags.shader
    }
    set {
      if let sh = newValue {
        flags.shader = sh
      }
    }
  }

  var canvas: Canvas
  //var paintCanvas: PaintCanvas
  var flags: PaintFlags
  var underlineThickness: Int 
  var underlinePosition: Int
  var diagonal: DiagonalStrike?

  internal init(canvas: Canvas) {
    self.canvas = canvas
    //paintCanvas = canvas.paintCanvas
    flags = PaintFlags()
    underlineThickness = UnderlineMetricsNotSet
    underlinePosition = 0
    flags.textEncoding = .GlyphID
    flags.style = .Fill
    flags.antiAlias = true
    flags.subpixelText = false
    flags.LCDRenderText = false
    flags.hinting = .Normal
    // added here
    //flags.typeface = Typeface(font: "Ubuntu", style: FontStyle.Bold)
  }
  
  public func setFontRenderParams(params: FontRenderParams, subpixelRenderingSuppressed: Bool) {
    flags.antiAlias = params.antialiasing
    flags.LCDRenderText = (!subpixelRenderingSuppressed && params.subpixelRendering != .None)
    flags.subpixelText = params.subpixelPositioning
    flags.autohinted = params.autohinted
    flags.hinting = Paint.Hinting(rawValue: Int(params.hinting.rawValue))!
  }

  // public func setFontWithStyle(font: Font, fontStyle: FontStyle) {
  //   let face: Typeface = Typeface(font: font.fontName, style: fontStyle)
  //   typeface = face
  //   flags.isFakeBoldText = fontStyle.contains(.Bold) && !face.isBold
  // }
  
  public func setUnderlineMetrics(thickness: Int, position: Int) {
    underlineThickness = thickness
    underlinePosition = position
  }

  public func drawSelection(selection: [FloatRect], color: Color) {
    assert(false)
  }

  public func drawText(pos: [FloatPoint],
                       glyphs: ContiguousArray<UInt16>,
                       len: Int) {
    drawText(glyphs: glyphs, len: len, pos: pos, flags: self.flags)
  }

  public func drawText(glyphs: ContiguousArray<UInt16>, len: Int, pos: [FloatPoint], flags: PaintFlags) {
    let textBlob = PaintTextBlob(glyphs: glyphs, len: len, pos: pos, flags: flags)
    //paintCanvas.drawTextBlob(textBlob, x: 0, y: 0, flags: flags)
    canvas.drawTextBlob(textBlob, x: 0, y: 0, flags: flags)
  }
  
  public func drawDecorations(x: Int, y: Int, width: Int, underline: Bool, strike: Bool, diagonalStrike: Bool) {
    if underline {
      drawUnderline(x: x, y: y, width: width)
    }
    if strike {
      drawStrike(x: x, y: y, width: width)
    }
    if diagonalStrike {
      if diagonal == nil {
        diagonal = DiagonalStrike(canvas: canvas, start: IntPoint(x: x, y: y), flags: flags)
      }
      diagonal!.addPiece(lenght: width, color: flags.color)
    } else if diagonal != nil {
      endDiagonalStrike()
    }
  }
  
  public func endDiagonalStrike() {
    if let d = diagonal {
      d.draw()
      diagonal = nil
    }
  }
  
  public func drawUnderline(x: Int, y: Int, width: Int) {
    var r = IntRect(
      left: x, 
      top: y + underlinePosition, 
      right: x + width, 
      bottom:y + underlinePosition + underlineThickness)
    
    if underlineThickness == UnderlineMetricsNotSet {
      let textSize = Int(flags.textSize)
      r.top = textSize * UnderlineOffset +  y
      r.bottom = r.top + textSize * LineThickness
    }
    canvas.drawRect(rect: r, flags: flags)
  }

  public func drawStrike(x: Int, y: Int, width: Int) {
    let textSize = Int(flags.textSize)
    let height = textSize * LineThickness
    let offset = textSize * StrikeThroughOffset +  y
    let r = IntRect(left: x, top: offset, right: x + width, bottom: offset + height)
    canvas.drawRect(rect: r, flags: flags)
  }

  // Helper class to draw a diagonal line with multiple pieces of different
  // lengths and colors; to support text selection appearances.
  public class DiagonalStrike {
    
    struct Piece {
      var lenght: Int
      var color: Color
    }

    var canvas: Canvas 
    var start: IntPoint
    var flags: PaintFlags
    var totalLength: Int
    var pieces: [Piece]

    internal init(canvas: Canvas, start: IntPoint, flags: PaintFlags) {
      self.canvas = canvas
      self.start = start
      self.flags = flags
      totalLength = 0
      pieces = [Piece]()
    }

    internal func addPiece(lenght: Int, color: Color) {
      totalLength += lenght
      pieces.append(Piece(lenght: lenght, color: color))
    }

    internal func draw() {
      let textSize = Int(flags.textSize)
      let offset = textSize * DiagonalStrikeMarginOffset
      //SkScalarCeilToInt(SkScalarMul)
      let thickness = (textSize * LineThickness) * 2
      
      //SkScalarCeilToInt
      let height = textSize - offset
      let end: IntPoint = start + IntVec2(x: totalLength, y: -height)
      let clipHeight = height + 2 * thickness

      flags.antiAlias = true
      flags.strokeWidth = Float(thickness)

      let clipped = pieces.count > 1
      var x = start.x

      for piece in pieces {
        flags.color = piece.color

        if clipped {
          let _ = canvas.save()
          canvas.clipRect(rect: IntRect(x: x, y: end.y - thickness, width: piece.lenght, height: clipHeight))
        }

        canvas.drawLine(p1: start, p2: end, flags: flags)

        if clipped {
          canvas.restore()
        }

        x += piece.lenght
      }

    }

  }

}