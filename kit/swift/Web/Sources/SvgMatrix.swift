// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class SvgMatrix {
 
  var owned: SVGMatrixOwnedRef?
  let reference: SVGMatrixRef

  public init(a: Double, b: Double, c: Double, d: Double, e: Double, f: Double) {
    owned = SVGMatrixCreate(a, b, c, d, e, f)
    reference = SVGMatrixFromOwned(owned!)
  }

  init(reference: SVGMatrixRef) {
    self.reference = reference
  }

  deinit {
    if owned != nil {
      SVGMatrixDestroy(owned!)
    }
  }

}