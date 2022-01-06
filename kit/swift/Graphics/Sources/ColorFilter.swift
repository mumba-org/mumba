// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol ColorFilter {}

public protocol ColorFilterFactory {
  static func makeModeFilter(c: Color, mode: BlendMode) -> ColorFilter
  static func makeLightingFilter(mul: Color, add: Color) -> ColorFilter
  static func makeComposeFilter(outer: ColorFilter, inner: ColorFilter) -> ColorFilter
}

extension ColorFilterFactory {
  
  public static func makeModeFilter(c: Color, mode: BlendMode) -> ColorFilter {
    return ColorFilterSkia(reference: nil)
  }

  public static func makeLightingFilter(mul: Color, add: Color) -> ColorFilter {
    return ColorFilterSkia(reference: nil)
  }

  public static func makeComposeFilter(outer: ColorFilter, inner: ColorFilter) -> ColorFilter {
    return ColorFilterSkia(reference: nil)
  }

}

public struct DefaultColorFilterFactory : ColorFilterFactory {}

public class ColorFilterSkia : ColorFilter {

  // access needed by module Compositor -> Fixit. use a withUnsafe.. closure?
  public var reference: ColorFilterRef?

  init(reference: ColorFilterRef?) {
    self.reference = reference
  }

}
