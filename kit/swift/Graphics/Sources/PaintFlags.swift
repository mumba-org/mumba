// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class PaintFlags {

  public var color: Color {
    get {
      var a: UInt8 = 0, r: UInt8 = 0, g: UInt8 = 0, b: UInt8 = 0
      _PaintFlagsGetColorFlag(reference, &r, &g, &b, &a)
      return Color( a: a, r: r, g: g, b: b)
    }
    set {
      _PaintFlagsSetColorFlag(reference, newValue.r, newValue.g, newValue.b, newValue.a)
    }
  }

  public var alpha: UInt8 {
    get {
      return _PaintFlagsGetAlphaFlag(reference)
    }
    set {
      _PaintFlagsSetAlphaFlag(reference, newValue)
    }
  }

  public var style: Paint.Style {
    get {
      return Paint.Style(rawValue: Int(_PaintFlagsGetStyleFlag(reference)))!
    }
    set {
      _PaintFlagsSetStyleFlag(reference, Int32(newValue.rawValue))
    }
  }

  public var blendMode: BlendMode {
    get { 
      return BlendMode(rawValue: Int32(_PaintFlagsGetBlendModeFlag(reference)))!
    }
    set {
      _PaintFlagsSetBlendModeFlag(reference, Int32(newValue.rawValue))
    }
  }

  public var antiAlias: Bool {
    get { 
      return _PaintFlagsGetAntiAliasFlag(reference) == 1
    }
    set {
      _PaintFlagsSetAntiAliasFlag(reference, Int32(newValue.intValue))
    }
  }

  public var verticalText: Bool {
    get {
      return _PaintFlagsGetVerticalTextFlag(reference) == 1
    }
    set {
      _PaintFlagsSetVerticalTextFlag(reference, Int32(newValue.intValue))
    }
  }

  public var subpixelText: Bool {
    get {
      return _PaintFlagsGetSubpixelTextFlag(reference) == 1
    }
    set {
      _PaintFlagsSetSubpixelTextFlag(reference, Int32(newValue.intValue))
    }
  }

  public var LCDRenderText: Bool {
    get {
      return _PaintFlagsGetLCDRenderTextFlag(reference) == 1
    }
    set {
      _PaintFlagsSetLCDRenderTextFlag(reference, Int32(newValue.intValue))
    }
  }

  public var hinting: Paint.Hinting {
    get {
      return Paint.Hinting(rawValue: Int(_PaintFlagsGetHintingFlag(reference)))!
    }
    set {
      _PaintFlagsSetHintingFlag(reference, Int32(newValue.rawValue))
    }
  }

  public var autohinted: Bool {
    get {
      return _PaintFlagsGetAutohintedFlag(reference) == 1
    }
    set {
      _PaintFlagsSetAutohintedFlag(reference, Int32(newValue.intValue))
    }
  }

  public var dither: Bool {
    get {
      return _PaintFlagsGetDitherFlag(reference) == 1
    }
    set {
      _PaintFlagsSetDitherFlag(reference, Int32(newValue.intValue))
    }
  }

  public var textEncoding : Paint.TextEncoding {
    get {
      return Paint.TextEncoding(rawValue: Int(_PaintFlagsGetTextEncodingFlag(reference)))!
    }
    set {
      _PaintFlagsSetTextEncodingFlag(reference, Int32(newValue.rawValue))
    }
  }

  public var textSize: Float {
    get {
      return _PaintFlagsGetTextSizeFlag(reference)
    }
    set {
      _PaintFlagsSetTextSizeFlag(reference, newValue)
    }
  }

  public var filterQuality: Paint.FilterQuality {
    get {
      return Paint.FilterQuality(rawValue: Int(_PaintFlagsGetFilterQualityFlag(reference)))!
    }
    set {
      _PaintFlagsSetFilterQualityFlag(reference, Int32(newValue.rawValue))
    }
  }

  public var strokeWidth: Float {
    get {
      return _PaintFlagsGetStrokeWidthFlag(reference)
    }
    set {
      _PaintFlagsSetStrokeWidthFlag(reference, newValue)
    }
  }

  public var strokeMiter: Float {
    get {
      return _PaintFlagsGetStrokeMiterFlag(reference)
    }
    set {
      _PaintFlagsSetStrokeMiterFlag(reference, newValue)
    }
  }

  public var strokeCap: Paint.Cap {
    get {
      return Paint.Cap(rawValue: Int(_PaintFlagsGetStrokeCapFlag(reference)))!
    }
    set {
      _PaintFlagsSetStrokeCapFlag(reference, Int32(newValue.rawValue))
    }
  }

  public var strokeJoin: Paint.Join {
    get {
      return Paint.Join(rawValue: Int(_PaintFlagsGetStrokeJoinFlag(reference)))!
    }
    set {
      _PaintFlagsSetStrokeJoinFlag(reference, Int32(newValue.rawValue))
    }
  }

  public var typeface: Typeface {
    get {
      if _typeface == nil {
        _typeface = Typeface(reference: _PaintFlagsGetTypefaceFlag(reference))
      }
      return _typeface!
    }
    set {
      _typeface = newValue
      _PaintFlagsSetTypefaceFlag(reference, _typeface!.reference)
    }
  }

  public var colorFilter: ColorFilter {
    get {
      if _colorFilter == nil {
        _colorFilter = ColorFilterSkia(reference: _PaintFlagsGetColorFilterFlag(reference))
      }
      return _colorFilter!
    }
    set {
      _colorFilter = newValue as? ColorFilterSkia
      _PaintFlagsSetColorFilterFlag(reference, _colorFilter!.reference)
    }
  }

  public var maskFilter: MaskFilter {
    get {
      if _maskFilter == nil {
        _maskFilter = MaskFilterSkia(reference: _PaintFlagsGetMaskFilterFlag(reference))
      }
      return _maskFilter!
    }
    
    set {
      _maskFilter = newValue as? MaskFilterSkia
      _PaintFlagsSetMaskFilterFlag(reference, _maskFilter!.reference)
    }
  }

  public var shader: PaintShader? {
    get {
      if _shader == nil {
        if let ref = _PaintFlagsGetShaderFlag(reference) {
          _shader = PaintShader(reference: ref)
        }
      }
      return _shader
    }
    set {
      _shader = newValue
      if let local = newValue {
        _PaintFlagsSetShaderFlag(reference, local.reference)
      } else {
        _PaintFlagsSetShaderFlag(reference, nil)
      }
    }
  }

  public var pathEffect: PathEffect {
    get {
      if _pathEffect == nil {
        _pathEffect = PathEffect(reference: _PaintFlagsGetPathEffectFlag(reference))
      }
      return _pathEffect!
    }
    set {
      _pathEffect = newValue
      _PaintFlagsSetPathEffectFlag(reference, _pathEffect!.reference)
    }
  }

  public var imageFilter: PaintFilter {
    get {
      if _imageFilter == nil {
        _imageFilter = PaintFilter(reference: _PaintFlagsGetImageFilterFlag(reference))
      }
      return _imageFilter!
    }
    set {
      _imageFilter = newValue
      _PaintFlagsSetImageFilterFlag(reference, _imageFilter!.reference)
    }
  }

  public var looper: DrawLooper {
  get {
      if _looper == nil {
        _looper = DrawLooperSkia(reference: _PaintFlagsGetLooperFlag(reference))
      }
      return _looper!
    }
    set {
      _looper = newValue as? DrawLooperSkia
      _PaintFlagsSetLooperFlag(reference, _looper!.reference)
    }
  }

 public var isSimpleOpacity: Bool {
    return _PaintFlagsIsSimpleOpacity(reference) == 1
 }

 var _typeface: Typeface?
 var _colorFilter: ColorFilterSkia?
 var _maskFilter: MaskFilterSkia?
 var _shader: PaintShader?
 var _pathEffect: PathEffect?
 var _imageFilter: PaintFilter?
 var _looper: DrawLooperSkia?
 public var reference: PaintFlagsRef

 public init() {
   reference = _PaintFlagsCreate()
 }

 deinit {
   //_PaintFlagsDestroy(reference)
 }

 public func toPaint() -> Paint {
  let pref = _PaintFlagsToSkiaPaint(reference)
  return Paint(reference: pref!)
 }

}
