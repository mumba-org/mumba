// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol MaskFilter {

}

public class MaskFilterSkia : MaskFilter {
  
  var reference: MaskFilterRef

  internal init(reference: MaskFilterRef) {
    self.reference = reference
  }

  deinit {
    _MaskFilterDestroy(reference)
  }

}

public enum BlurStyle : UInt {
  case Normal = 0
  case Solid  = 1
  case Outer  = 2
  case Inner  = 3
}

public enum BlurOptions : UInt {
  case None              = 0x00
  case IgnoreTransform   = 0x01
  case HighQuality       = 0x02
  case All               = 0x03
}

public class BlurMaskFilter : MaskFilterSkia {
  
  static let BlurSigmaScale = 0.57735
  
  public static func convertRadiusToSigma(_ radius: Double) -> Double {
    return radius > 0 ? BlurSigmaScale * radius + 0.5 : 0.0
  }
  
  public init(style: BlurStyle, radius: Double, options: BlurOptions = .None) {
    let ptr = _MaskFilterCreateBlur(radius, Int32(style.rawValue), Int32(options.rawValue))
    super.init(reference: ptr!)
  }

}

//public class EmbossMaskFilter : MaskFilterSkia {
  
//  public init(sigma: Float, dir d: FloatVec3, ambient: Float, specular: Float) {
//    let ptr = _MaskFilterCreateEmboss(Double(sigma), Double(d.x), Double(d.y), Double(d.z), Double(ambient), Double(specular))
//    super.init(reference: ptr!)
//  }

//}