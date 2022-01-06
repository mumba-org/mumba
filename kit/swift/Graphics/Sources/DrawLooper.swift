// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol DrawLooper {}

public protocol DrawLooperFactory {
  static func makeLayer(info: LayerDrawLooperInfo) -> DrawLooper
  static func makeBlur(color: Color, sigma: Double, dx: Double, dy: Double) -> DrawLooper
  static func makeShadow(shadows: ShadowValues) -> DrawLooper
}

extension DrawLooperFactory {

  public static func makeLayer(info: LayerDrawLooperInfo) -> DrawLooper {
    let looperBuilder = LayerDrawLooperBuilder()
    looperBuilder.addLayer()
    let _ = looperBuilder.addLayer(info: info)
    return looperBuilder.detachLooper()
  }
  
  public static func makeBlur(color: Color, sigma: Double, dx: Double, dy: Double) -> DrawLooper {
    return BlurDrawLooper(color: color, sigma: sigma, dx: dx, dy: dy)
  }

  public static func makeShadow(shadows: ShadowValues) -> DrawLooper {
    if shadows.isEmpty {
      let looperBuilder = LayerDrawLooperBuilder()
      looperBuilder.addLayer()
      return looperBuilder.detachLooper()
    }

    let looperBuilder = LayerDrawLooperBuilder()

    looperBuilder.addLayer()

    var layerInfo = LayerDrawLooperInfo() 
    layerInfo.paintBits.insert(.MaskFilter)
    layerInfo.paintBits.insert(.ColorFilter)
    layerInfo.colorMode = .Src

    for shadow in shadows {
      layerInfo.offset.x = shadow.x
      layerInfo.offset.y = shadow.y

      // SkBlurMaskFilter's blur radius defines the range to extend the blur from
      // original mask, which is half of blur amount as defined in ShadowValue.
      let blurMask = BlurMaskFilter(style: .Normal,
                         radius: BlurMaskFilter.convertRadiusToSigma(shadow.blur / 2.0),
                         options: .HighQuality)

      let colorFilter = DefaultColorFilterFactory.makeModeFilter(c: shadow.color, mode: .SrcIn)

      let paint = looperBuilder.addLayer(info: layerInfo)
      // TODO: check if this works as expected
      paint.maskFilter = blurMask
      paint.colorFilter = colorFilter
    }

    return looperBuilder.detachLooper() 
  }

}

public struct DefaultDrawLooperFactory : DrawLooperFactory {}

public class DrawLooperSkia : DrawLooper {
 
 var reference: DrawLooperRef

 internal init(reference: DrawLooperRef) {
   self.reference = reference
 }

 deinit {
    _DrawLooperDestroy(reference)
 }

}

public class BlurDrawLooper : DrawLooperSkia {
  
  public init(color: Color, sigma: Double, dx: Double, dy: Double) {
    let ptr = _DrawLooperCreateBlur(color.a, color.r, color.g, color.b, sigma, dx, dy)
    super.init(reference: ptr!)
  }

}

public struct LayerDrawLooperOptions : OptionSet  {
  static let Style       = LayerDrawLooperOptions(rawValue: 1 << 0)   //!< use this layer's Style/stroke settings
  static let TextSkewX   = LayerDrawLooperOptions(rawValue: 1 << 1)   //!< use this layer's textskewx
  static let PathEffect  = LayerDrawLooperOptions(rawValue: 1 << 2)   //!< use this layer's patheffect
  static let MaskFilter  = LayerDrawLooperOptions(rawValue: 1 << 3)   //!< use this layer's maskfilter
  static let Shader      = LayerDrawLooperOptions(rawValue: 1 << 4)   //!< use this layer's shader
  static let ColorFilter = LayerDrawLooperOptions(rawValue: 1 << 5)  //!< use this layer's colorfilter
  static let Xfermode    = LayerDrawLooperOptions(rawValue: 1 << 6)   //!< use this layer's xfermode
  static let EntirePaint = LayerDrawLooperOptions(rawValue: -1)

  public var rawValue: Int

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }
}

public struct LayerDrawLooperInfo {
  public var paintBits: LayerDrawLooperOptions
  public var colorMode: BlendMode
  public var offset: FloatVec2
  public var postTranslate: Bool

  public init() {
    paintBits = LayerDrawLooperOptions(rawValue: 0)
    colorMode = .Dst
    offset = FloatVec2(x: 0.0, y: 0.0)
    postTranslate = false
  }

}

public class LayerDrawLooper : DrawLooperSkia {

  public init() {
    let ptr = _DrawLooperCreateLayer()
    super.init(reference: ptr!)
  }

  internal override init(reference: DrawLooperRef) {
    super.init(reference: reference)
  }

}

public class LayerDrawLooperBuilder {
  
  var reference: DrawLooperBuilderRef

  public init() {
    reference = _DrawLooperLayerBuilderCreate()
  }

  deinit {
    _DrawLooperLayerBuilderDestroy(reference)
  }

  public func addLayer(info: LayerDrawLooperInfo) -> Paint {
    let phandle = _DrawLooperLayerBuilderAddLayer(reference, 
      Int32(info.paintBits.rawValue), 
      info.colorMode.rawValue, 
      Int32(info.offset.x), Int32(info.offset.y),
      info.postTranslate ? 1 : 0)

    return Paint(reference: phandle!)
  }

  public func addLayer(x: Int, y: Int) {
    _DrawLooperLayerBuilderAddLayerXY(reference, Int32(x), Int32(y))
  }

  public func addLayer() { 
    addLayer(x: 0, y: 0) 
  }

  public func addLayerOnTop(info: LayerDrawLooperInfo) -> Paint {
    let phandle = _DrawLooperLayerBuilderAddLayerOnTop(reference,  
      Int32(info.paintBits.rawValue), 
      info.colorMode.rawValue, 
      Int32(info.offset.x), Int32(info.offset.y),
      info.postTranslate ? 1 : 0)
    return Paint(reference: phandle!)  
  }

  public func detachLooper() -> LayerDrawLooper {
    let lhandle = _DrawLooperLayerBuilderDetachLooper(reference)
    return LayerDrawLooper(reference: lhandle!)
  }

}