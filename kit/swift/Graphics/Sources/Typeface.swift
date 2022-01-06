// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class Typeface {
  
  public var isBold: Bool {
    return _TypefaceIsBold(reference) == 0 ? false : true
  }

  public var isItalic: Bool {
    return _TypefaceIsItalic(reference) == 0 ? false : true
  }

  static let defaultFontName = "sans"

  var reference: TypefaceRef

  public init(font: String, style: FontStyle) {
    reference = font.withCString { fontcstr -> TypefaceRef in 
      return _TypefaceCreate(fontcstr, style.contains(.Bold) ? 1 : 0, style.contains(.Italic) ? 1 : 0)
    }
  }

  public init(size: Int, style: FontStyle) {
    reference = Typeface.defaultFontName.withCString { fontcstr -> TypefaceRef in 
      return _TypefaceCreate(fontcstr, style.contains(.Bold) ? 1 : 0, style.contains(.Italic) ? 1 : 0)
    }
  }

  internal init(reference: TypefaceRef) {
    self.reference = reference
  }

  deinit {
    _TypefaceDestroy(reference)
  }

}
