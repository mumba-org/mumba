// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class Paint {

  public enum Style: Int {
    case Fill = 0
    case Stroke = 1
    case StrokeAndFill = 2
  }

  public enum Hinting: Int {
    case None          = 0
    case Slight        = 1
    case Normal        = 2   // this is the default
    case Full          = 3
  }

  public enum TextEncoding: Int {
    case UTF8     = 0 // the text parameters are UTF8
    case UTF16    = 1// the text parameters are UTF16
    case UTF32    = 2// the text parameters are UTF32
    case GlyphID  = 3 // the text parameters are glyph indices
  }

  public enum FilterQuality: Int {
    case None      // fastest but lowest quality, typically nearest-neighbor
    case Low       // typically bilerp
    case Medium    // typically bilerp + mipmaps for down-scaling
    case High      // slowest but highest quality, typically bicubic or better
  }

  public enum Cap : Int {
    case Butt
    case Round
    case Square
  }

  public enum Join : Int {
    case Miter
    case Round
    case Bevel
  }

  public struct FontMetrics {
    public var descent: Float
    public var ascent: Float

    public init() {
      descent = 0.0
      ascent = 0.0
    }
  }

  public var color: Color {
    get { 
      var a: UInt8 = 0, r: UInt8 = 0, g: UInt8 = 0, b: UInt8 = 0
      _PaintGetColor(reference, &a, &r, &g, &b)
      return Color(a: a, r: r, g: g, b: b) 
    }
    set {
      _PaintSetColor(reference, newValue.a, newValue.r, newValue.g, newValue.b)
    }
  }

  public var alpha: UInt8 {
    get { 
      return _PaintGetAlpha(reference)
    }
    set {
      _PaintSetAlpha(reference, newValue)
    }
  }

  public var style: Style {
    get { 
      let s = Int(_PaintGetStyle(reference))
      return Style(rawValue: s)! 
    }
    set {
      _PaintSetStyle(reference, UInt32(newValue.rawValue))
    }
  }

  public var mode: BlendMode {
    get { 
      let m = Int(_PaintGetBlend(reference))
      return BlendMode(rawValue: Int32(m))!
    }
    set {
      _PaintSetBlend(reference, UInt32(newValue.rawValue))
    }
  }

  public var strokeWidth: Float {
    get { 
     return Float(_PaintGetStrokeWidth(reference))
    }
    set {
      _PaintSetStrokeWidth(reference, Int32(newValue))
    }
  }

  public var antiAlias: Bool {
    get {
      return _PaintIsAntiAlias(reference) == 1 ? true : false
    }
    set {
      _PaintSetAntiAlias(reference, Int32(newValue.intValue))
    }
  }

  public var isAutoHinted: Bool {
    get {
      return _PaintIsAutoHinted(reference) == 1 ? true : false
    }
    set {
      _PaintSetIsAutoHinted(reference, Int32(newValue.intValue))
    }
  }

  public var drawLooper: DrawLooper? {
    get {
      if _drawLooper == nil {
        if let ptr = _PaintGetDrawLooper(reference) {
          _drawLooper = DrawLooperSkia(reference: ptr)
        }
      }
      return _drawLooper
    }
    set {
      if let value = newValue as? DrawLooperSkia {
        // invalidate cached
        _drawLooper = nil
        _PaintSetDrawLooper(reference, value.reference)
      }
    }
  }

  public var typeface: Typeface? {
    get {
      if _typeface == nil {
        if let ptr = _PaintGetTypeface(reference) {
          _typeface = Typeface(reference: ptr)
        }
      }
      return _typeface
    }
    set { // TODO: this will never permit us to "clear" from the outside
      if let value = newValue {
        _typeface = nil
        _PaintSetTypeface(reference, value.reference)
      }
    }
  }

  public var textSize: Int {
    get {
      return Int(_PaintGetTextSize(reference))
    }
    set {
      _PaintSetTextSize(reference, Int32(newValue))
    }
  }

  public var shader: Shader? {
    get {
      if _shader == nil {
        if let ptr = _PaintGetShader(reference) {
          _shader = SkiaShader(reference: ptr)
        }
      }
      return _shader
    }
    set {
      if let value = newValue as? SkiaShader {
        _shader = nil
        _PaintSetShader(reference, value.reference)
      }
    }
  }

  public var isFakeBoldText: Bool {
    get {
      return _PaintIsFakeBoldText(reference) == 0 ? false : true
    }
    set {
     _PaintSetIsFakeBoldText(reference, newValue.intValue)
    }
  }

  public var textEncoding : TextEncoding {
    get {
      let value = Int(_PaintGetTextEncoding(reference))
      return TextEncoding(rawValue: value)!
    }
    set {
      _PaintSetTextEncoding(reference, UInt32(newValue.rawValue))
    }
  }
  
  public var isSubpixelText : Bool {
    get {
      return _PaintIsSubpixelText(reference) == 0 ? false : true
    }
    set {
      _PaintSetIsSubpixelText(reference, newValue.intValue)
    }
  }
  
  public var isLCDRenderText : Bool {
    get {
      return _PaintIsLCDRenderText(reference) == 0 ? false : true
    }
    set {
      _PaintSetIsLCDRenderText(reference, newValue.intValue)
    }
  }
  
  public var hinting: Hinting {
    get {
      let value = Int(_PaintGetHinting(reference))
      return Hinting(rawValue: value)!
    }
    set {
      _PaintSetHinting(reference, UInt32(newValue.rawValue))
    }
  }

  public var maskFilter: MaskFilter? {
    get {
      if _maskFilter == nil {
        if let ptr = _PaintGetMaskFilter(reference) {
          _maskFilter = MaskFilterSkia(reference: ptr)
        }
      }
      return _maskFilter
    }
    set {
      if let value = newValue as? MaskFilterSkia {
        _maskFilter = nil
        _PaintSetMaskFilter(reference, value.reference)
      }
    }
  }

  public var colorFilter: ColorFilter? {
    get {
      if _colorFilter == nil {
        if let ptr = _PaintGetColorFilter(reference) {
          _colorFilter = ColorFilterSkia(reference: ptr)
        }
      }
      return _colorFilter
    }
    set {
      if let value = newValue as? ColorFilterSkia {
        _colorFilter = nil
        _PaintSetColorFilter(reference, value.reference)
      }
    }
  }

  public var filterQuality: FilterQuality {
    get {
      let value = Int(_PaintGetFilterQuality(reference))
      return FilterQuality(rawValue: value)!
    }
    set {
      _PaintSetFilterQuality(reference, UInt32(newValue.rawValue))
    }
  }

  public var reference: PaintRef

  // cached values
  var _drawLooper: DrawLooper?
  var _shader: Shader?
  var _typeface: Typeface?
  var _maskFilter: MaskFilter?
  var _colorFilter: ColorFilter?

  public init() {
    reference = _PaintCreate()
  }

  public init(paint: Paint) {
    reference = _PaintCreateFromOther(paint.reference)
  }

  public init(reference: PaintRef) {
    self.reference = reference
  }

  deinit {
    _PaintDestroy(reference)
  }

  // TODO: really implement this
  public func getFontMetrics(metrics: inout FontMetrics) {
    metrics.ascent = -1
    metrics.descent = 1
  }
}
